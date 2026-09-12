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
import socket
import struct
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
            if (
                isinstance(name, str)
                and name
                and isinstance(app_type, str)
                and app_type.casefold() == "game"
            ):
                games.append({"appid": app_id, "name": name})
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


def build_library_repair_expression(games: list[dict[str, object]]) -> str:
    candidates = json.dumps(games, ensure_ascii=True, separators=(",", ":"))
    return f"""(async()=>{{
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
    const uncached = candidates.filter(app =>
      !store.GetAppOverviewByAppID(app.appid)
    );
    if (!uncached.length)
      return {{accepted:true, injected:0, total:store.m_mapApps?.size || 0}};
    const checks = await Promise.all(uncached.map(async app => {{
      try {{
        return await SteamClient.Apps.GetIsSubscribedApp(app.appid) ? app : null;
      }} catch (_) {{
        return null;
      }}
    }}));
    const missing = checks.filter(app => app);
    if (!missing.length)
      return {{accepted:true, injected:0, total:store.m_mapApps?.size || 0}};
    const change = Change.fromObject({{
      app_overview: missing.map(app => ({{
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
          display_status: 0,
          status_percentage: 0,
          installed: false,
          is_available_on_current_platform: true,
          is_invalid_os_type: false
        }}],
        most_available_clientid: "0",
        selected_clientid: "0",
        number_of_copies: 1
      }})),
      full_update: false,
      update_complete: true
    }});
    const accepted = !!store.UpdateAppOverview(change.serializeBinary());
    if (accepted)
      store.m_bIsInitialized = true;
    return {{accepted, injected:missing.length, total:store.m_mapApps?.size || 0}};
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


def run(port: int, pid: int | None, startup_timeout: float) -> int:
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--steam-pid", type=int)
    parser.add_argument("--startup-timeout", type=float, default=90)
    args = parser.parse_args()
    try:
        return run(args.port, args.steam_pid, args.startup_timeout)
    except (CDPError, OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        log(f"recovery stopped: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
