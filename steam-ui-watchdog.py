#!/usr/bin/env python3
"""Recover native ARM64 Steam from its post-login library-ready stall.

The ARM64 client can authenticate successfully but remain in login state 4
(`WaitingForLibraryReady`).  SteamUI consequently never starts its post-login
services.  This helper uses Steam's localhost-only CEF debugger to perform the
missed UI handoff.  It never reads or prints account credentials.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


LOGGED_IN_STATE = 5
WAITING_FOR_LIBRARY_STATE = 4
APPINFO_MAGIC = 0x07564429
APPINFO_RECORD_HEADER_SIZE = 68


class CDPError(RuntimeError):
    """A Chrome DevTools Protocol operation failed."""


def log(message: str) -> None:
    print(f"steam-ui-watchdog: {message}", file=sys.stderr, flush=True)


def process_alive(pid: int | None) -> bool:
    return pid is None or os.path.exists(f"/proc/{pid}")


def read_exact(connection: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise CDPError("websocket closed")
        chunks.extend(chunk)
    return bytes(chunks)


def send_websocket_text(connection: socket.socket, payload: bytes) -> None:
    mask = os.urandom(4)
    length = len(payload)
    header = bytearray([0x81])
    if length < 126:
        header.append(0x80 | length)
    elif length < 65536:
        header.append(0x80 | 126)
        header.extend(struct.pack("!H", length))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack("!Q", length))
    masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    connection.sendall(header + mask + masked)


def receive_websocket_json(connection: socket.socket) -> dict:
    while True:
        first, second = read_exact(connection, 2)
        opcode = first & 0x0F
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", read_exact(connection, 2))[0]
        elif length == 127:
            length = struct.unpack("!Q", read_exact(connection, 8))[0]
        if second & 0x80:
            mask = read_exact(connection, 4)
        else:
            mask = None
        payload = read_exact(connection, length)
        if mask is not None:
            payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        if opcode == 0x8:
            raise CDPError("websocket closed")
        if opcode == 0x9:
            connection.sendall(bytes([0x8A, len(payload)]) + payload)
            continue
        if opcode != 0x1:
            continue
        return json.loads(payload)


def find_shared_context(port: int) -> dict:
    endpoint = f"http://127.0.0.1:{port}/json/list"
    with urllib.request.urlopen(endpoint, timeout=2) as response:
        targets = json.load(response)
    for target in targets:
        if target.get("title") == "SharedJSContext":
            return target
    raise CDPError("SharedJSContext target is not available")


def evaluate(port: int, expression: str, *, await_promise: bool = False) -> object:
    target = find_shared_context(port)
    websocket_url = urllib.parse.urlparse(target["webSocketDebuggerUrl"])
    if websocket_url.hostname not in {"127.0.0.1", "localhost"}:
        raise CDPError("refusing a non-local debugger target")

    connection = socket.create_connection((websocket_url.hostname, websocket_url.port), 3)
    try:
        connection.settimeout(8)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {websocket_url.path} HTTP/1.1\r\n"
            f"Host: {websocket_url.netloc}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        connection.sendall(request.encode("ascii"))
        response = bytearray()
        while b"\r\n\r\n" not in response:
            response.extend(connection.recv(4096))
            if len(response) > 65536:
                raise CDPError("oversized websocket handshake")
        status_line = bytes(response).split(b"\r\n", 1)[0]
        if b" 101 " not in status_line:
            raise CDPError("websocket upgrade was rejected")

        request_id = 1
        command = {
            "id": request_id,
            "method": "Runtime.evaluate",
            "params": {
                "expression": expression,
                "returnByValue": True,
                "awaitPromise": await_promise,
            },
        }
        send_websocket_text(connection, json.dumps(command, separators=(",", ":")).encode())
        while True:
            message = receive_websocket_json(connection)
            if message.get("id") != request_id:
                continue
            result = message.get("result", {})
            if "exceptionDetails" in result:
                description = result["exceptionDetails"].get("text", "evaluation failed")
                raise CDPError(description)
            remote_value = result.get("result", {})
            return remote_value.get("value")
    finally:
        connection.close()


STATE_EXPRESSION = """(()=>{
  const app = globalThis.App;
  return app ? {
    loginState: app.LoginState,
    started: !!app.m_bStartedInitAfterLogin,
    services: !!app.m_bServicesInitialized
  } : null;
})()"""


WORKAROUND_STATE_EXPRESSION = """(()=>({
  libraryRepair: typeof globalThis.__arm64RepairLibrary === "function",
  installFallback: typeof globalThis.__arm64OriginalInstallApp === "function",
  detailsFallback: typeof globalThis.__arm64EnsureAppDetails === "function",
  compatFallback: typeof globalThis.__arm64OriginalSpecifyCompatTool === "function",
  launchFallback: typeof globalThis.__arm64OriginalRunGame === "function",
  terminateFallback: typeof globalThis.__arm64OriginalTerminateApp === "function",
  overviewListener: globalThis.__arm64LibraryChangeRegistered === true,
  navigationListener: globalThis.__arm64NavigationListenerInstalled === true
}))()"""


START_UI_EXPRESSION = """(()=>{
  const app = globalThis.App;
  if (!app || app.LoginState !== 4 || app.m_bStartedInitAfterLogin)
    return false;
  globalThis.__arm64SteamUIRecovery = "pending";
  app.InitAfterLogin().then(
    () => globalThis.__arm64SteamUIRecovery = "resolved",
    () => globalThis.__arm64SteamUIRecovery = "rejected"
  );
  return true;
})()"""


RELEASE_FRIENDS_GATE_EXPRESSION = """(()=>{
  try {
    if (!globalThis.__arm64WebpackRequire) {
      globalThis.webpackChunksteamui.push([
        [987654321], {}, require => globalThis.__arm64WebpackRequire = require
      ]);
    }
    const store = globalThis.__arm64WebpackRequire(87913).LN;
    if (!store || store.m_bStartupFinished || typeof store.m_fnStartupCompleted !== "function")
      return false;
    store.m_fnStartupCompleted();
    return true;
  } catch (_) {
    return false;
  }
})()"""


COMPLETE_LOGIN_EXPRESSION = """(async()=>{
  const app = globalThis.App;
  if (!app || app.LoginState !== 4 || !app.m_bServicesInitialized)
    return false;
  const accountName = globalThis.loginStore?.accountName || "";
  await app.OnLoginStateChange(accountName, 5, 1, 0, 0, "");
  return app.LoginState === 5 && app.BHasCurrentUser();
})()"""


RESTORE_LIBRARY_ROUTE_EXPRESSION = """(()=>{
  try {
    if (!globalThis.__arm64WebpackRequire) {
      globalThis.webpackChunksteamui.push([
        [987654323], {}, require => globalThis.__arm64WebpackRequire = require
      ]);
    }
    const routing = globalThis.__arm64WebpackRequire(49171).z;
    const route = localStorage.getItem("__arm64LastDesktopRoute") || "";
    if (!route.startsWith("/library"))
      return {restored:false, route};
    if (!routing?.m_history)
      return {restored:false, route, reason:"history unavailable"};
    if (routing.m_locationPathname !== route) {
      routing.m_history.replace(route);
      return {restored:true, route};
    }
    return {restored:false, route};
  } catch (error) {
    return {restored:false, reason:String(error)};
  }
})()"""


TAKE_GAME_REQUEST_EXPRESSION = """(()=>{
  const raw = localStorage.getItem("__arm64GameRequest");
  if (raw !== null)
    localStorage.removeItem("__arm64GameRequest");
  return raw;
})()"""


def _read_c_string(data: bytes, position: int, limit: int) -> tuple[str, int]:
    end = data.find(b"\0", position, limit)
    if end < 0:
        raise ValueError("unterminated appinfo string")
    return data[position:end].decode("utf-8", "replace"), end + 1


def _read_appinfo_object(
    data: bytes, position: int, limit: int, strings: list[str]
) -> tuple[dict[str, object], int]:
    result: dict[str, object] = {}
    while position < limit:
        value_type = data[position]
        position += 1
        if value_type == 8:
            return result, position

        key_index = struct.unpack_from("<I", data, position)[0]
        position += 4
        if key_index >= len(strings):
            raise ValueError("invalid appinfo string-table index")
        key = strings[key_index]

        if value_type == 0:
            value, position = _read_appinfo_object(data, position, limit, strings)
        elif value_type == 1:
            value, position = _read_c_string(data, position, limit)
        elif value_type == 2:
            value = struct.unpack_from("<I", data, position)[0]
            position += 4
        elif value_type == 3:
            value = struct.unpack_from("<f", data, position)[0]
            position += 4
        elif value_type == 4:
            value = struct.unpack_from("<I", data, position)[0]
            position += 4
        elif value_type == 5:
            length = struct.unpack_from("<H", data, position)[0]
            position += 2
            byte_length = length * 2
            value = data[position : position + byte_length].decode("utf-16le", "replace")
            value = value.rstrip("\0")
            position += byte_length
        elif value_type == 6:
            value = data[position : position + 4]
            position += 4
        elif value_type == 7:
            value = struct.unpack_from("<Q", data, position)[0]
            position += 8
        elif value_type == 10:
            value = struct.unpack_from("<q", data, position)[0]
            position += 8
        elif value_type == 11:
            value = struct.unpack_from("<Q", data, position)[0]
            position += 8
        else:
            raise ValueError(f"unsupported appinfo value type {value_type}")
        result[key] = value
    raise ValueError("unterminated appinfo object")


def _localized_asset(value: object) -> str:
    """Return the English (or first available) filename from an appinfo asset."""
    if isinstance(value, str):
        return value
    if not isinstance(value, dict):
        return ""
    english = value.get("english")
    if isinstance(english, str):
        return english
    for candidate in value.values():
        if isinstance(candidate, str):
            return candidate
    return ""


def read_cached_games(appinfo_path: Path) -> list[dict[str, object]]:
    data = appinfo_path.read_bytes()
    if len(data) < 20 or struct.unpack_from("<I", data)[0] != APPINFO_MAGIC:
        raise ValueError("unsupported appinfo cache format")

    string_table_offset = struct.unpack_from("<Q", data, 8)[0]
    if string_table_offset < 20 or string_table_offset >= len(data):
        raise ValueError("invalid appinfo string-table offset")
    string_count = struct.unpack_from("<I", data, string_table_offset)[0]
    position = string_table_offset + 4
    strings: list[str] = []
    for _ in range(string_count):
        value, position = _read_c_string(data, position, len(data))
        strings.append(value)

    games: list[dict[str, object]] = []
    position = 16
    while position + 8 <= string_table_offset:
        app_id, record_size = struct.unpack_from("<II", data, position)
        if app_id == 0:
            break
        next_record = position + 8 + record_size
        value_position = position + APPINFO_RECORD_HEADER_SIZE
        if value_position >= next_record or next_record > string_table_offset:
            raise ValueError("invalid appinfo record size")
        root, _ = _read_appinfo_object(data, value_position, next_record, strings)
        appinfo = root.get("appinfo", root)
        common = appinfo.get("common", {}) if isinstance(appinfo, dict) else {}
        if isinstance(common, dict):
            name = common.get("name")
            app_type = common.get("type")
            oslist = common.get("oslist", "")
            if (
                isinstance(name, str)
                and name
                and isinstance(app_type, str)
                and app_type.casefold() == "game"
            ):
                advertised_platforms = {
                    platform.strip().casefold()
                    for platform in str(oslist).split(",")
                    if platform.strip()
                }
                config = appinfo.get("config", {})
                if not isinstance(config, dict):
                    config = {}
                install_dir = config.get("installdir", "")
                if not isinstance(install_dir, str):
                    install_dir = ""
                windows_executable = ""
                launch_options = config.get("launch", {})
                if isinstance(launch_options, dict):
                    for launch_option in launch_options.values():
                        if not isinstance(launch_option, dict):
                            continue
                        launch_config = launch_option.get("config", {})
                        launch_oslist = ""
                        if isinstance(launch_config, dict):
                            launch_oslist = str(launch_config.get("oslist", ""))
                        executable = launch_option.get("executable", "")
                        if (
                            isinstance(executable, str)
                            and executable
                            and "windows"
                            in {
                                platform.strip()
                                for platform in launch_oslist.casefold().split(",")
                            }
                        ):
                            windows_executable = executable
                            break
                header = common.get("header_image", {})
                full_assets = common.get("library_assets_full", {})
                if not isinstance(full_assets, dict):
                    full_assets = {}

                def full_asset_filename(asset_name: str, image_name: str) -> str:
                    asset = full_assets.get(asset_name, {})
                    if not isinstance(asset, dict):
                        return ""
                    return _localized_asset(asset.get(image_name, {}))

                logo_asset = full_assets.get("library_logo", {})
                logo_position: dict[str, object] = {}
                if isinstance(logo_asset, dict):
                    raw_position = logo_asset.get("logo_position", {})
                    if isinstance(raw_position, dict):
                        pinned_position = raw_position.get("pinned_position")
                        if isinstance(pinned_position, str):
                            logo_position["pinnedPosition"] = pinned_position
                        for source_key, target_key in (
                            ("width_pct", "nWidthPct"),
                            ("height_pct", "nHeightPct"),
                        ):
                            try:
                                logo_position[target_key] = float(
                                    raw_position[source_key]
                                )
                            except (KeyError, TypeError, ValueError):
                                pass

                games.append(
                    {
                        "appid": app_id,
                        "name": name,
                        "icon_hash": str(common.get("icon", "")),
                        "header_image": _localized_asset(header),
                        "library_capsule": full_asset_filename(
                            "library_capsule", "image"
                        ),
                        "library_hero": full_asset_filename("library_hero", "image"),
                        "library_hero_2x": full_asset_filename(
                            "library_hero", "image2x"
                        ),
                        "library_logo": full_asset_filename("library_logo", "image"),
                        "library_logo_2x": full_asset_filename(
                            "library_logo", "image2x"
                        ),
                        "logo_position": logo_position,
                        "store_asset_mtime": (
                            int(common.get("store_asset_mtime", 0))
                            if str(common.get("store_asset_mtime", 0)).isdigit()
                            else 0
                        ),
                        "install_dir": install_dir,
                        "windows_executable": windows_executable,
                        "use_direct_proton": (
                            "windows" in advertised_platforms
                            and "linux" not in advertised_platforms
                        ),
                    }
                )
        position = next_record

    games.sort(key=lambda game: str(game["name"]).casefold())
    return games


def find_appinfo_path(pid: int | None) -> Path | None:
    candidates: list[Path] = []
    if pid is not None:
        try:
            executable = Path(os.readlink(f"/proc/{pid}/exe"))
            candidates.append(executable.parent.parent / "appcache" / "appinfo.vdf")
        except OSError:
            pass
    script_root = Path(__file__).resolve().parent
    candidates.extend(
        (
            script_root / "Steam" / "appcache" / "appinfo.vdf",
            Path.cwd() / "Steam" / "appcache" / "appinfo.vdf",
        )
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def read_installed_app_ids(appinfo_path: Path) -> set[int]:
    """Return AppIDs whose local Steam manifests have the fully-installed bit."""
    steamapps = appinfo_path.parent.parent / "steamapps"
    installed: set[int] = set()
    for manifest in steamapps.glob("appmanifest_*.acf"):
        try:
            app_id = int(manifest.stem.removeprefix("appmanifest_"))
            text = manifest.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            continue
        marker = '"StateFlags"'
        position = text.find(marker)
        if position < 0:
            continue
        remainder = text[position + len(marker) :]
        fields = remainder.split('"', 2)
        if len(fields) < 2:
            continue
        try:
            state_flags = int(fields[1])
        except ValueError:
            continue
        if state_flags & 4:
            installed.add(app_id)
    return installed


class GameProcessManager:
    """Launch the Windows depot through direct ARM64 Proton for repaired SteamUI."""

    def __init__(self, appinfo_path: Path | None):
        self.appinfo_path = appinfo_path
        self.processes: dict[int, dict[str, object]] = {}
        self.installed_app_ids = (
            read_installed_app_ids(appinfo_path) if appinfo_path else set()
        )

    @property
    def steam_root(self) -> Path | None:
        if self.appinfo_path is None:
            return None
        return self.appinfo_path.parent.parent

    def installed_apps_changed(self) -> bool:
        if self.appinfo_path is None:
            return False
        current = read_installed_app_ids(self.appinfo_path)
        if current == self.installed_app_ids:
            return False
        self.installed_app_ids = current
        return True

    def _game(self, app_id: int) -> dict[str, object] | None:
        if self.appinfo_path is None:
            return None
        try:
            games = read_cached_games(self.appinfo_path)
        except (OSError, ValueError, struct.error):
            return None
        return next((game for game in games if game["appid"] == app_id), None)

    def launch(self, app_id: int) -> bool:
        active = self.processes.get(app_id)
        if active and active["process"].poll() is None:
            return True
        if app_id not in self.installed_app_ids:
            log(f"refusing launch for AppID {app_id}: it is not fully installed")
            return False

        game = self._game(app_id)
        steam_root = self.steam_root
        if game is None or steam_root is None:
            log(f"refusing launch for AppID {app_id}: app metadata is unavailable")
            return False
        install_dir = game.get("install_dir")
        executable = game.get("windows_executable")
        if not isinstance(install_dir, str) or not install_dir:
            log(f"refusing launch for AppID {app_id}: install directory is unavailable")
            return False
        if not isinstance(executable, str) or not executable:
            log(f"refusing launch for AppID {app_id}: Windows launch option is unavailable")
            return False

        common_root = (steam_root / "steamapps" / "common").resolve()
        game_dir = (common_root / install_dir).resolve()
        relative_executable = Path(executable.replace("\\", "/"))
        if relative_executable.is_absolute() or ".." in relative_executable.parts:
            log(f"refusing launch for AppID {app_id}: unsafe executable path")
            return False
        executable_path = (game_dir / relative_executable).resolve()
        if common_root not in game_dir.parents or game_dir not in executable_path.parents:
            log(f"refusing launch for AppID {app_id}: launch path escaped Steam library")
            return False
        if not executable_path.is_file():
            log(f"refusing launch for AppID {app_id}: Windows executable is missing")
            return False

        proton = (
            Path(__file__).resolve().parent
            / "compatibilitytools"
            / "GE-Proton11-6-aarch64-direct"
            / "proton"
        )
        if not proton.is_file() or not os.access(proton, os.X_OK):
            log(f"refusing launch for AppID {app_id}: direct Proton tool is unavailable")
            return False

        compat_data = steam_root / "steamapps" / "compatdata" / str(app_id)
        compat_data.mkdir(parents=True, exist_ok=True)
        environment = os.environ.copy()
        environment.update(
            {
                "STEAM_COMPAT_CLIENT_INSTALL_PATH": str(steam_root),
                "STEAM_COMPAT_DATA_PATH": str(compat_data),
                "STEAM_COMPAT_INSTALL_PATH": str(game_dir),
                "STEAM_COMPAT_APP_ID": str(app_id),
                "SteamAppId": str(app_id),
                "SteamGameId": str(app_id),
                "PROTON_LOG": "1",
                "PROTON_LOG_DIR": str(steam_root / "logs"),
            }
        )
        supervisor_log = open(
            steam_root / "logs" / "arm64-game-launcher.log", "ab", buffering=0
        )
        try:
            process = subprocess.Popen(
                [str(proton), "run", f"./{relative_executable.as_posix()}"],
                cwd=game_dir,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=supervisor_log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except OSError as error:
            supervisor_log.close()
            log(f"could not launch AppID {app_id}: {error}")
            return False
        self.processes[app_id] = {
            "process": process,
            "log": supervisor_log,
            "compat_data": compat_data.resolve(),
            "terminate_deadline": None,
        }
        log(f"launched AppID {app_id} through direct ARM64 Proton")
        return True

    @staticmethod
    def _prefix_process_ids(compat_data: Path) -> set[int]:
        """Return processes carrying this exact Proton data path."""
        marker = b"STEAM_COMPAT_DATA_PATH=" + os.fsencode(str(compat_data))
        process_ids: set[int] = set()
        for proc_entry in Path("/proc").iterdir():
            if not proc_entry.name.isdigit():
                continue
            process_id = int(proc_entry.name)
            try:
                environment = (proc_entry / "environ").read_bytes().split(b"\0")
            except OSError:
                continue
            if marker in environment:
                process_ids.add(process_id)
        return process_ids

    @staticmethod
    def _signal_processes(process_ids: set[int], requested_signal: int) -> None:
        for process_id in process_ids:
            try:
                os.kill(process_id, requested_signal)
            except (PermissionError, ProcessLookupError):
                pass

    def terminate(self, app_id: int) -> bool:
        active = self.processes.get(app_id)
        if not active:
            return False
        process = active["process"]
        prefix_processes = self._prefix_process_ids(active["compat_data"])
        if process.poll() is not None and not prefix_processes:
            return False
        if process.poll() is None:
            prefix_processes.add(process.pid)
        self._signal_processes(prefix_processes, signal.SIGTERM)
        active["terminate_deadline"] = time.monotonic() + 5
        log(f"requested termination of AppID {app_id}")
        return True

    def poll(self) -> set[int]:
        stopped: set[int] = set()
        for app_id, active in list(self.processes.items()):
            process = active["process"]
            deadline = active["terminate_deadline"]
            supervisor_running = process.poll() is None
            prefix_processes = self._prefix_process_ids(active["compat_data"])
            if not supervisor_running and prefix_processes and deadline is None:
                log(
                    f"AppID {app_id} launcher exited with Wine processes still active; "
                    "cleaning up the game prefix"
                )
                active["terminate_deadline"] = time.monotonic() + 5
                deadline = active["terminate_deadline"]
                self._signal_processes(prefix_processes, signal.SIGTERM)
            if deadline is not None:
                requested_signal = (
                    signal.SIGKILL
                    if time.monotonic() >= deadline
                    else signal.SIGTERM
                )
                if supervisor_running:
                    prefix_processes.add(process.pid)
                self._signal_processes(prefix_processes, requested_signal)
                if supervisor_running or prefix_processes:
                    continue
            elif supervisor_running:
                continue
            active["log"].close()
            del self.processes[app_id]
            stopped.add(app_id)
            log(f"AppID {app_id} exited")
        return stopped

    def running_app_ids(self) -> set[int]:
        self.poll()
        return set(self.processes)


def synchronize_running_games(port: int, manager: GameProcessManager) -> None:
    app_ids = sorted(manager.running_app_ids())
    expression = f"""(()=>{{
      const next = new Set({json.dumps(app_ids)});
      const current = globalThis.__arm64ExternalRunningIDs || new Set();
      const changed = current.size !== next.size || [...current].some(id => !next.has(id));
      const managed = globalThis.__arm64ManagedAppIDs || new Set();
      next.forEach(id => managed.add(id));
      globalThis.__arm64ManagedAppIDs = managed;
      const appStore = globalThis.__arm64WebpackRequire?.(1776)?.tw;
      const stale = [...managed].some(id => {{
        const status = appStore?.m_mapApps?.get(id)?.per_client_data?.[0]
          ?.display_status;
        return status !== (next.has(id) ? 4 : 28);
      }});
      if (!changed && !stale)
        return false;
      globalThis.__arm64ExternalRunningIDs = next;
      globalThis.__arm64RepairLibrary?.();
      clearTimeout(globalThis.__arm64RunningStateRepairTimer);
      globalThis.__arm64RunningStateRepairTimer = setTimeout(
        () => globalThis.__arm64RepairLibrary?.(), 500
      );
      return true;
    }})()"""
    evaluate(port, expression)


def handle_game_request(port: int, manager: GameProcessManager) -> None:
    raw = evaluate(port, TAKE_GAME_REQUEST_EXPRESSION)
    if not isinstance(raw, str) or not raw:
        synchronize_running_games(port, manager)
        return
    try:
        request = json.loads(raw)
        app_id = int(request.get("appid", 0))
        action = request.get("action")
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
        log("ignored malformed SteamUI game request")
        synchronize_running_games(port, manager)
        return
    if app_id <= 0:
        log("ignored SteamUI game request with invalid AppID")
    elif action == "launch":
        manager.launch(app_id)
    elif action == "terminate":
        manager.terminate(app_id)
    else:
        log("ignored SteamUI game request with unknown action")
    synchronize_running_games(port, manager)


def build_library_repair_expression(games: list[dict[str, object]]) -> str:
    candidates = json.dumps(games, ensure_ascii=True, separators=(",", ":"))
    return rf"""(async()=>{{
  try {{
    if (!globalThis.__arm64WebpackRequire) {{
      globalThis.webpackChunksteamui.push([
        [987654322], {{}}, require => globalThis.__arm64WebpackRequire = require
      ]);
    }}
    const require = globalThis.__arm64WebpackRequire;
    const store = require(1776).tw;
    const Change = require(59865).bs;
    if (!store || !Change || !globalThis.SteamClient?.Apps)
      return {{accepted:false, reason:"Steam app store unavailable"}};
    const candidates = {candidates};
    const checks = await Promise.all(candidates.map(async app => {{
      try {{
        return await SteamClient.Apps.GetIsSubscribedApp(app.appid) ? app : null;
      }} catch (_) {{
        return null;
      }}
    }}));
    const owned = checks.filter(app => app);
    globalThis.__arm64OwnedLibraryFallback = owned;
    globalThis.__arm64OwnedLibraryIDs = new Set(owned.map(app => app.appid));

    globalThis.__arm64RepairLibrary = () => {{
      const fallback = globalThis.__arm64OwnedLibraryFallback;
      if (!fallback.length) {{
        store.m_bIsInitialized = true;
        return {{accepted:true, injected:0, total:store.m_mapApps?.size || 0}};
      }}
      const change = Change.fromObject({{
        app_overview: fallback.map(app => ({{
          appid: app.appid,
          display_name: app.name,
          display_name_elanguage: 0,
          visible_in_game_list: true,
          subscribed_to: true,
          sort_as: app.name,
          app_type: 1,
          gameid: String(app.appid),
          per_client_data: [{{
            clientid: "0",
            client_name: "Local Computer",
            display_status: globalThis.__arm64ExternalRunningIDs?.has(app.appid)
              ? 4
              : 28,
            status_percentage: 0,
            installed: !!app.installed,
            is_available_on_current_platform: true,
            is_invalid_os_type: false
          }}],
          most_available_clientid: "0",
          selected_clientid: "0",
          number_of_copies: 1,
          icon_hash: app.icon_hash || "",
          library_capsule_filename: app.library_capsule || "library_600x900.jpg",
          header_filename: app.header_image || "header.jpg",
          rt_store_asset_mtime: app.store_asset_mtime || 0,
          local_cache_version: 0
        }})),
        full_update: false,
        update_complete: true
      }});
      const accepted = !!store.UpdateAppOverview(change.serializeBinary());
      if (accepted)
        store.m_bIsInitialized = true;
      return {{accepted, injected:fallback.length, total:store.m_mapApps?.size || 0}};
    }};

    if (!globalThis.__arm64LibraryChangeRegistered) {{
      SteamClient.Apps.RegisterForAppOverviewChanges(() => {{
        clearTimeout(globalThis.__arm64LibraryRepairTimer);
        globalThis.__arm64LibraryRepairTimer = setTimeout(
          () => globalThis.__arm64RepairLibrary?.(), 50
        );
      }});
      globalThis.__arm64LibraryChangeRegistered = true;
    }}

    const routing = require(49171).z;
    if (!globalThis.__arm64NavigationListenerInstalled && routing?.m_history?.listen) {{
      globalThis.__arm64NavigationUnlisten = routing.m_history.listen(location => {{
        const route = location?.pathname || "";
        if (route.startsWith("/library") || route === "/browser/")
          localStorage.setItem("__arm64LastDesktopRoute", route);
      }});
      globalThis.__arm64NavigationListenerInstalled = true;
    }}

    const detailsStore = require(78057).H;
    globalThis.__arm64EnsureAppDetails = appID => {{
      const numericAppID = Number(appID);
      const app = globalThis.__arm64OwnedLibraryFallback.find(
        candidate => candidate.appid === numericAppID
      );
      if (!app || !detailsStore)
        return false;
      const existing = detailsStore.GetAppDetails(numericAppID);
      let compatMappings = {{}};
      try {{
        compatMappings = JSON.parse(
          localStorage.getItem("__arm64CompatToolMappings") || "{{}}"
        );
      }} catch (_) {{}}
      const fallbackAssets = {{
        strHeroImage: app.library_hero || "library_hero.jpg",
        strHeroImage_2x: app.library_hero_2x || "",
        strHeroBlurImage: "",
        strLogoImage: app.library_logo || "logo.png",
        strLogoImage_2x: app.library_logo_2x || "",
        strHeaderImage: app.header_image || "header.jpg",
        strHeaderImage_2x: "",
        logoPosition: Object.keys(app.logo_position || {{}}).length
          ? app.logo_position
          : {{pinnedPosition:"UpperLeft", nWidthPct:50, nHeightPct:50}}
      }};
      const details = Object.assign({{
        unAppID: numericAppID,
        strDisplayName: app.name,
        strDeveloperName: "",
        strPublisherName: "",
        strHomepageURL: "",
        strSupportURL: "",
        strSelectedBeta: "",
        strSteamDeckBlogURL: "",
        bIsSubscribedTo: true,
        bHasAnyLocalContent: false,
        bCloudEnabledForAccount: false,
        bCloudEnabledForApp: false,
        bCloudAvailable: false,
        bCloudSyncOnSuspendAvailable: false,
        bCloudSyncOnSuspendEnabled: false,
        bCanMoveInstallFolder: false,
        bHasDifferentCopies: false,
        bIsExcludedFromSharing: false,
        bIsThirdPartyUpdater: false,
        bWorkshopVisible: false,
        bCommunityMarketPresence: false,
        bOverlayEnabled: true,
        bIsAvailableOnPlatform: true,
        bStorePagePublished: true,
        bFDMEnable: false,
        bForceIdentAsSteamDeck: false,
        bOverrideInternalResolution: false,
        bRPOEnable: false,
        unEntitledContentApp: 0,
        unTimedTrialSecondsAllowed: 0,
        unTimedTrialSecondsPlayed: 0,
        eAppOwnershipFlags: 0,
        eAppUpdateError: 0,
        eAutoUpdateValue: 0,
        eBackgroundDownloads: 0,
        eCloudStatus: 0,
        eControllerStyle: 0,
        eControllerType: 0,
        eDisplayStatus: 28,
        eEnableThirdPartyControllerConfiguration: 0,
        eSteamInputControllerMask: 0,
        eTSOEnable: 0,
        iInstallFolder: 0,
        lDiskSpaceRequiredBytes: 0,
        lDiskUsageBytes: "0",
        nBuildID: 0,
        nCloudProgressPercent: 0,
        nCompatToolPriority: 0,
        nPlaytimeForever: 0,
        rtLastTimePlayed: 0,
        rtLastUpdated: 0,
        selectedLanguage: "english",
        strCloudBytesAvailable: "0",
        strCloudBytesUsed: "0",
        strCompatExperiment: "",
        strCompatToolName: "",
        strInstallFolder: "",
        strLaunchOptions: "",
        strResolutionOverride: "",
        achievements: {{vecHighlight:[], vecUnachieved:[], vecAchievedHidden:[]}},
        vecChildConfigApps: [],
        vecDLC: [],
        vecBetas: [],
        vecLanguages: [],
        vecPlatforms: [],
        vecDeckCompatTestResults: [],
        vecSteamFrameCompatTestResults: [],
        vecSteamMachineCompatTestResults: [],
        vecSteamOSCompatTestResults: [],
        deckDerivedProperties: {{
          requires_non_controller_launcher_nav: false,
          requires_manual_keyboard_invoke: false,
          small_text: false,
          hdr_support: 0
        }}
      }}, existing || {{}});
      details.libraryAssets = Object.assign(
        {{}}, fallbackAssets, existing?.libraryAssets || {{}}
      );
      for (const field of [
        "vecChildConfigApps", "vecDLC", "vecBetas", "vecLanguages",
        "vecPlatforms",
        "vecDeckCompatTestResults", "vecSteamFrameCompatTestResults",
        "vecSteamMachineCompatTestResults", "vecSteamOSCompatTestResults"
      ]) {{
        if (!Array.isArray(details[field]))
          details[field] = [];
      }}
      if (!details.strOwnerSteamID)
        delete details.strOwnerSteamID;
      if (Object.hasOwn(compatMappings, String(numericAppID))) {{
        details.strCompatToolName = compatMappings[numericAppID] || "";
        details.nCompatToolPriority = details.strCompatToolName ? 250 : 0;
      }}
      detailsStore.AppDetailsChanged(details);
      return true;
    }};

    if (detailsStore && !globalThis.__arm64OriginalRegisterForAppData) {{
      globalThis.__arm64OriginalRegisterForAppData =
        detailsStore.RegisterForAppData.bind(detailsStore);
      detailsStore.RegisterForAppData = (appID, listener) => {{
        const registration =
          globalThis.__arm64OriginalRegisterForAppData(appID, listener);
        queueMicrotask(() => globalThis.__arm64EnsureAppDetails?.(appID));
        return registration;
      }};
    }}

    if (!globalThis.__arm64OriginalSpecifyCompatTool) {{
      globalThis.__arm64OriginalSpecifyCompatTool =
        SteamClient.Apps.SpecifyCompatTool.bind(SteamClient.Apps);
      SteamClient.Apps.SpecifyCompatTool = (appID, toolName) => {{
        const numericAppID = Number(appID);
        return Promise.resolve(
          globalThis.__arm64OriginalSpecifyCompatTool(appID, toolName)
        ).then(result => {{
          let compatMappings = {{}};
          try {{
            compatMappings = JSON.parse(
              localStorage.getItem("__arm64CompatToolMappings") || "{{}}"
            );
          }} catch (_) {{}}
          compatMappings[numericAppID] = String(toolName || "");
          localStorage.setItem(
            "__arm64CompatToolMappings", JSON.stringify(compatMappings)
          );
          globalThis.__arm64EnsureAppDetails?.(numericAppID);
          return result;
        }});
      }};
    }}

    for (const app of owned) {{
      if (app.installed)
        globalThis.__arm64EnsureAppDetails(app.appid);
    }}
    const routeAppID = Number(routing?.m_locationPathname?.match(
      /^\/library\/app\/(\d+)/
    )?.[1]);
    if (routeAppID)
      globalThis.__arm64EnsureAppDetails(routeAppID);

    const actions = require(2444).I;
    if (actions && !globalThis.__arm64OriginalInstallApp) {{
      globalThis.__arm64OriginalInstallApp = actions.InstallApp.bind(actions);
      actions.InstallApp = appID => {{
        const numericAppID = Number(appID);
        if (
          Number.isSafeInteger(numericAppID) &&
          numericAppID > 0 &&
          globalThis.__arm64OwnedLibraryIDs.has(numericAppID)
        ) {{
          actions.m_unAppIDExpectedInstall = numericAppID;
          const app = globalThis.__arm64OwnedLibraryFallback.find(
            candidate => candidate.appid === numericAppID
          );
          const install = () =>
            SteamClient.Console.ExecCommand(`app_install ${{numericAppID}}`);
          if (app?.use_direct_proton) {{
            return Promise.resolve(
              SteamClient.Apps.SpecifyCompatTool(
                numericAppID, "GE-Proton11-6-aarch64-direct"
              )
            ).then(install);
          }}
          return install();
        }}
        return globalThis.__arm64OriginalInstallApp(appID);
      }};
    }}

    globalThis.__arm64ExternalRunningIDs ||= new Set();
    if (!globalThis.__arm64OriginalRunGame) {{
      globalThis.__arm64OriginalRunGame = SteamClient.Apps.RunGame.bind(
        SteamClient.Apps
      );
      SteamClient.Apps.RunGame = (appID, ...args) => {{
        const numericAppID = Number(appID);
        const app = globalThis.__arm64OwnedLibraryFallback.find(
          candidate => candidate.appid === numericAppID
        );
        if (app?.installed && app.windows_executable) {{
          globalThis.__arm64ExternalRunningIDs.add(numericAppID);
          localStorage.setItem("__arm64GameRequest", JSON.stringify({{
            action: "launch",
            appid: numericAppID,
            serial: `${{Date.now()}}-${{Math.random()}}`
          }}));
          globalThis.__arm64RepairLibrary();
          return;
        }}
        return globalThis.__arm64OriginalRunGame(appID, ...args);
      }};
    }}

    if (!globalThis.__arm64OriginalTerminateApp) {{
      globalThis.__arm64OriginalTerminateApp = SteamClient.Apps.TerminateApp.bind(
        SteamClient.Apps
      );
      SteamClient.Apps.TerminateApp = (appID, ...args) => {{
        const numericAppID = Number(appID);
        if (globalThis.__arm64ExternalRunningIDs.has(numericAppID)) {{
          localStorage.setItem("__arm64GameRequest", JSON.stringify({{
            action: "terminate",
            appid: numericAppID,
            serial: `${{Date.now()}}-${{Math.random()}}`
          }}));
          return;
        }}
        return globalThis.__arm64OriginalTerminateApp(appID, ...args);
      }};
    }}

    return globalThis.__arm64RepairLibrary();
  }} catch (error) {{
    return {{accepted:false, reason:String(error)}};
  }}
}})()"""


def repair_visual_library(port: int, pid: int | None) -> None:
    appinfo_path = find_appinfo_path(pid)
    if appinfo_path is None:
        log("local appinfo cache not found; visual Library repair was skipped")
        return
    try:
        games = read_cached_games(appinfo_path)
    except (OSError, ValueError, struct.error) as error:
        log(
            "could not read local appinfo cache; "
            f"visual Library repair was skipped: {error}"
        )
        return
    if not games:
        log("local appinfo cache contains no games; visual Library repair was skipped")
        return
    installed_app_ids = read_installed_app_ids(appinfo_path)
    for game in games:
        game["installed"] = int(game["appid"]) in installed_app_ids
    result = evaluate(
        port, build_library_repair_expression(games), await_promise=True
    )
    if not isinstance(result, dict) or not result.get("accepted"):
        reason = (
            result.get("reason", "unknown error")
            if isinstance(result, dict)
            else "unknown error"
        )
        log(f"visual Library repair was not accepted: {reason}")
        return
    injected = int(result.get("injected", 0))
    total = int(result.get("total", 0))
    if injected:
        log(f"restored {injected} owned games to the visual Library ({total} total)")


def restore_library_route(port: int) -> None:
    result = evaluate(port, RESTORE_LIBRARY_ROUTE_EXPRESSION)
    if isinstance(result, dict) and result.get("restored"):
        log(f"restored the requested SteamUI route {result.get('route')}")


def get_state(port: int) -> dict | None:
    value = evaluate(port, STATE_EXPRESSION)
    return value if isinstance(value, dict) else None


def wait_for_shared_context(port: int, pid: int | None, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and process_alive(pid):
        try:
            if get_state(port) is not None:
                return True
        except (CDPError, OSError, urllib.error.URLError, json.JSONDecodeError):
            pass
        time.sleep(0.5)
    return False


def recover_context(port: int, pid: int | None, startup_timeout: float) -> int:
    if not wait_for_shared_context(port, pid, startup_timeout):
        if process_alive(pid):
            log("CEF debugger did not become ready; leaving Steam untouched")
        return 1

    waiting_since: float | None = None
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline and process_alive(pid):
        try:
            state = get_state(port)
        except (CDPError, OSError, urllib.error.URLError, json.JSONDecodeError):
            time.sleep(0.5)
            continue
        if state is None:
            time.sleep(0.5)
            continue
        if state.get("loginState") == LOGGED_IN_STATE:
            log("Steam reached the logged-in UI state")
            repair_visual_library(port, pid)
            return 0
        if state.get("loginState") != WAITING_FOR_LIBRARY_STATE:
            waiting_since = None
            time.sleep(0.5)
            continue
        if waiting_since is None:
            waiting_since = time.monotonic()
            log("detected WaitingForLibraryReady; allowing the native handoff five seconds")
        if time.monotonic() - waiting_since < 5:
            time.sleep(0.5)
            continue
        break
    else:
        return 1

    state = get_state(port)
    if state and state.get("loginState") == WAITING_FOR_LIBRARY_STATE:
        # The native ARM64 client publishes an empty app-overview update. Seed
        # the store before SteamUI constructs the post-login desktop so a
        # Library navigation can survive this forced context initialization.
        repair_visual_library(port, pid)
        restore_library_route(port)

    state = get_state(port)
    if state and not state.get("started"):
        if evaluate(port, START_UI_EXPRESSION):
            log("started the missed post-login SteamUI initialization")

    service_deadline = time.monotonic() + 12
    while time.monotonic() < service_deadline and process_alive(pid):
        state = get_state(port)
        if state and state.get("services"):
            break
        time.sleep(0.5)

    state = get_state(port)
    if state and not state.get("services"):
        if evaluate(port, RELEASE_FRIENDS_GATE_EXPRESSION):
            log("released the failed optional Friends Chat startup gate")

    service_deadline = time.monotonic() + 60
    while time.monotonic() < service_deadline and process_alive(pid):
        state = get_state(port)
        if state and state.get("services"):
            break
        time.sleep(0.5)
    else:
        log("post-login services did not initialize; leaving Steam running for diagnostics")
        return 1

    if evaluate(port, COMPLETE_LOGIN_EXPRESSION, await_promise=True):
        log("completed the missed logged-in UI handoff")
        repair_visual_library(port, pid)
        return 0
    log("could not complete the logged-in UI handoff")
    return 1


def run(
    port: int,
    pid: int | None,
    startup_timeout: float,
    game_manager: GameProcessManager,
) -> int:
    monitoring = False
    while process_alive(pid):
        result = recover_context(port, pid, startup_timeout)
        if result and not process_alive(pid):
            return result
        if result:
            time.sleep(2)
            continue
        if not monitoring:
            log("monitoring SteamUI for context replacement")
            monitoring = True

        while process_alive(pid):
            time.sleep(2)
            try:
                state = get_state(port)
                workaround_state = evaluate(port, WORKAROUND_STATE_EXPRESSION)
                handle_game_request(port, game_manager)
                if game_manager.installed_apps_changed():
                    log("installed app set changed; refreshing the visual Library")
                    repair_visual_library(port, pid)
            except (
                CDPError,
                OSError,
                urllib.error.URLError,
                json.JSONDecodeError,
            ):
                continue
            if state is None:
                continue
            if state.get("loginState") != LOGGED_IN_STATE or not (
                isinstance(workaround_state, dict)
                and workaround_state.get("libraryRepair")
                and workaround_state.get("installFallback")
                and workaround_state.get("detailsFallback")
                and workaround_state.get("compatFallback")
                and workaround_state.get("launchFallback")
                and workaround_state.get("terminateFallback")
                and workaround_state.get("overviewListener")
                and workaround_state.get("navigationListener")
            ):
                log("SteamUI context changed; reinstalling recovery hooks")
                break
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--steam-pid", type=int)
    parser.add_argument("--startup-timeout", type=float, default=90)
    args = parser.parse_args()
    try:
        game_manager = GameProcessManager(find_appinfo_path(args.steam_pid))
        return run(args.port, args.steam_pid, args.startup_timeout, game_manager)
    except (CDPError, OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        log(f"recovery stopped: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
