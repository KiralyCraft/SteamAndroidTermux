#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define SHIM_MAGIC UINT64_C(0x5359535653454d31)
#define SHIM_VERSION 1U
#define SHIM_MAX_SEMS 256U
#define SHIM_FIRST_ID 0x5100
#define SHIM_SEMVMX 32767

struct shim_semset {
    uint64_t magic;
    uint32_t version;
    int32_t semid;
    int32_t removed;
    int32_t key;
    uint32_t nsems;
    uint32_t uid;
    uint32_t gid;
    uint32_t cuid;
    uint32_t cgid;
    uint32_t mode;
    int64_t ctime;
    int64_t otime;
    uint16_t values[SHIM_MAX_SEMS];
    int32_t last_pid[SHIM_MAX_SEMS];
};

union shim_semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
    struct seminfo *__buf;
};

static int debug_enabled(void) {
    const char *value = getenv("SYSVSEM_SHIM_DEBUG");
    return value != NULL && value[0] != '\0' && strcmp(value, "0") != 0;
}

static void debug_log(const char *format, ...) {
    if (!debug_enabled()) {
        return;
    }

    int saved_errno = errno;
    va_list args;
    va_start(args, format);
    fprintf(stderr, "sysvsem-shim[%ld]: ", (long)getpid());
    vfprintf(stderr, format, args);
    fputc('\n', stderr);
    va_end(args);
    errno = saved_errno;
}

static int base_path(char *buffer, size_t size) {
    int length = snprintf(buffer, size, "/dev/shm/steam-sysvsem-%lu", (unsigned long)geteuid());
    if (length < 0 || (size_t)length >= size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int checked_user_directory(char *buffer, size_t size) {
    if (base_path(buffer, size) < 0) {
        return -1;
    }

    if (mkdir(buffer, 0700) < 0 && errno != EEXIST) {
        return -1;
    }

    struct stat status;
    if (lstat(buffer, &status) < 0) {
        return -1;
    }
    if (!S_ISDIR(status.st_mode) || status.st_uid != geteuid()) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

static int path_for(char *buffer, size_t size, const char *kind, uint32_t value) {
    char base[PATH_MAX];
    if (checked_user_directory(base, sizeof(base)) < 0) {
        return -1;
    }

    int length = snprintf(buffer, size, "%s/%s-%08x", base, kind, value);
    if (length < 0 || (size_t)length >= size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static int registry_lock(void) {
    char path[PATH_MAX];
    if (path_for(path, sizeof(path), "registry", 0) < 0) {
        return -1;
    }
    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        return -1;
    }
    if (flock(fd, LOCK_EX) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

static int full_pread(int fd, void *buffer, size_t size, off_t offset) {
    unsigned char *cursor = buffer;
    while (size != 0) {
        ssize_t result = pread(fd, cursor, size, offset);
        if (result == 0) {
            errno = EIO;
            return -1;
        }
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        cursor += result;
        offset += result;
        size -= (size_t)result;
    }
    return 0;
}

static int full_pwrite(int fd, const void *buffer, size_t size, off_t offset) {
    const unsigned char *cursor = buffer;
    while (size != 0) {
        ssize_t result = pwrite(fd, cursor, size, offset);
        if (result == 0) {
            errno = EIO;
            return -1;
        }
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        cursor += result;
        offset += result;
        size -= (size_t)result;
    }
    return 0;
}

static int read_state_locked(int fd, struct shim_semset *state) {
    if (flock(fd, LOCK_EX) < 0) {
        return -1;
    }
    if (full_pread(fd, state, sizeof(*state), 0) < 0) {
        int saved_errno = errno;
        flock(fd, LOCK_UN);
        errno = saved_errno;
        return -1;
    }
    if (state->magic != SHIM_MAGIC || state->version != SHIM_VERSION ||
        state->nsems == 0 || state->nsems > SHIM_MAX_SEMS || state->removed) {
        flock(fd, LOCK_UN);
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static int write_state_unlock(int fd, const struct shim_semset *state) {
    int result = full_pwrite(fd, state, sizeof(*state), 0);
    int saved_errno = errno;
    if (flock(fd, LOCK_UN) < 0 && result == 0) {
        result = -1;
        saved_errno = errno;
    }
    errno = saved_errno;
    return result;
}

static int open_set(int semid) {
    if (semid < 0) {
        errno = EINVAL;
        return -1;
    }
    char path[PATH_MAX];
    if (path_for(path, sizeof(path), "set", (uint32_t)semid) < 0) {
        return -1;
    }
    return open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
}

static int allocate_id_locked(void) {
    char path[PATH_MAX];
    if (path_for(path, sizeof(path), "next", 0) < 0) {
        return -1;
    }

    int fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        return -1;
    }

    int32_t next = SHIM_FIRST_ID;
    ssize_t count = pread(fd, &next, sizeof(next), 0);
    if (count != (ssize_t)sizeof(next) || next < SHIM_FIRST_ID || next >= INT_MAX - 1) {
        next = SHIM_FIRST_ID;
    }

    int32_t selected = next;
    for (;;) {
        char set_path[PATH_MAX];
        if (path_for(set_path, sizeof(set_path), "set", (uint32_t)selected) < 0) {
            close(fd);
            return -1;
        }
        if (access(set_path, F_OK) != 0 && errno == ENOENT) {
            break;
        }
        if (++selected >= INT_MAX - 1) {
            selected = SHIM_FIRST_ID;
        }
        if (selected == next) {
            close(fd);
            errno = ENOSPC;
            return -1;
        }
    }

    int32_t following = selected + 1;
    if (full_pwrite(fd, &following, sizeof(following), 0) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    close(fd);
    return selected;
}

static int read_key_id_locked(key_t key, int *semid) {
    char path[PATH_MAX];
    if (path_for(path, sizeof(path), "key", (uint32_t)key) < 0) {
        return -1;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return -1;
    }
    int32_t value;
    int result = full_pread(fd, &value, sizeof(value), 0);
    int saved_errno = errno;
    close(fd);
    if (result < 0) {
        errno = saved_errno;
        return -1;
    }
    *semid = value;
    return 0;
}

static int write_key_id_locked(key_t key, int semid) {
    char path[PATH_MAX];
    if (path_for(path, sizeof(path), "key", (uint32_t)key) < 0) {
        return -1;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        return -1;
    }
    int32_t value = semid;
    int result = full_pwrite(fd, &value, sizeof(value), 0);
    int saved_errno = errno;
    close(fd);
    if (result < 0) {
        unlink(path);
        errno = saved_errno;
    }
    return result;
}

static int unlink_key_locked(key_t key) {
    char path[PATH_MAX];
    if (path_for(path, sizeof(path), "key", (uint32_t)key) < 0) {
        return -1;
    }
    if (unlink(path) < 0 && errno != ENOENT) {
        return -1;
    }
    return 0;
}

int semget(key_t key, int nsems, int semflg) {
    if (nsems < 0 || (unsigned)nsems > SHIM_MAX_SEMS) {
        errno = EINVAL;
        return -1;
    }

    int registry_fd = registry_lock();
    if (registry_fd < 0) {
        return -1;
    }

    if (key != IPC_PRIVATE) {
        int existing_id;
        if (read_key_id_locked(key, &existing_id) == 0) {
            int set_fd = open_set(existing_id);
            struct shim_semset state;
            if (set_fd >= 0 && read_state_locked(set_fd, &state) == 0) {
                flock(set_fd, LOCK_UN);
                close(set_fd);
                flock(registry_fd, LOCK_UN);
                close(registry_fd);
                if ((semflg & IPC_CREAT) && (semflg & IPC_EXCL)) {
                    errno = EEXIST;
                    return -1;
                }
                if (nsems != 0 && (uint32_t)nsems > state.nsems) {
                    errno = EINVAL;
                    return -1;
                }
                debug_log("semget key=%#x -> existing id=%d", (unsigned)key, existing_id);
                return existing_id;
            }
            if (set_fd >= 0) {
                close(set_fd);
            }
        }
        /* A key file without a live set is stale, usually after a crash. */
        if (unlink_key_locked(key) < 0) {
            int saved_errno = errno;
            flock(registry_fd, LOCK_UN);
            close(registry_fd);
            errno = saved_errno;
            return -1;
        }
        if (!(semflg & IPC_CREAT)) {
            flock(registry_fd, LOCK_UN);
            close(registry_fd);
            errno = ENOENT;
            return -1;
        }
    }

    if (nsems == 0) {
        flock(registry_fd, LOCK_UN);
        close(registry_fd);
        errno = EINVAL;
        return -1;
    }

    int semid = allocate_id_locked();
    if (semid < 0) {
        int saved_errno = errno;
        flock(registry_fd, LOCK_UN);
        close(registry_fd);
        errno = saved_errno;
        return -1;
    }

    char set_path[PATH_MAX];
    if (path_for(set_path, sizeof(set_path), "set", (uint32_t)semid) < 0) {
        int saved_errno = errno;
        flock(registry_fd, LOCK_UN);
        close(registry_fd);
        errno = saved_errno;
        return -1;
    }
    int set_fd = open(set_path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (set_fd < 0) {
        int saved_errno = errno;
        flock(registry_fd, LOCK_UN);
        close(registry_fd);
        errno = saved_errno;
        return -1;
    }

    struct shim_semset state = {
        .magic = SHIM_MAGIC,
        .version = SHIM_VERSION,
        .semid = semid,
        .key = key,
        .nsems = (uint32_t)nsems,
        .uid = (uint32_t)geteuid(),
        .gid = (uint32_t)getegid(),
        .cuid = (uint32_t)geteuid(),
        .cgid = (uint32_t)getegid(),
        .mode = (uint32_t)(semflg & 0777),
        .ctime = (int64_t)time(NULL),
    };

    if (ftruncate(set_fd, (off_t)sizeof(state)) < 0 || full_pwrite(set_fd, &state, sizeof(state), 0) < 0 ||
        (key != IPC_PRIVATE && write_key_id_locked(key, semid) < 0)) {
        int saved_errno = errno;
        close(set_fd);
        unlink(set_path);
        flock(registry_fd, LOCK_UN);
        close(registry_fd);
        errno = saved_errno;
        return -1;
    }

    close(set_fd);
    flock(registry_fd, LOCK_UN);
    close(registry_fd);
    debug_log("semget key=%#x nsems=%d -> new id=%d", (unsigned)key, nsems, semid);
    return semid;
}

static int remove_set_files(const struct shim_semset *state) {
    int registry_fd = registry_lock();
    if (registry_fd < 0) {
        return -1;
    }

    int result = 0;
    int saved_errno = 0;
    char path[PATH_MAX];
    if (state->key != IPC_PRIVATE) {
        int mapped_id;
        if (read_key_id_locked((key_t)state->key, &mapped_id) == 0 && mapped_id == state->semid) {
            if (unlink_key_locked((key_t)state->key) < 0) {
                result = -1;
                saved_errno = errno;
            }
        }
    }
    if (path_for(path, sizeof(path), "set", (uint32_t)state->semid) < 0 ||
        (unlink(path) < 0 && errno != ENOENT)) {
        if (result == 0) {
            result = -1;
            saved_errno = errno;
        }
    }
    flock(registry_fd, LOCK_UN);
    close(registry_fd);
    if (result < 0) {
        errno = saved_errno;
    }
    return result;
}

int semctl(int semid, int semnum, int cmd, ...) {
    union shim_semun argument = {0};
    bool needs_argument = cmd == SETVAL || cmd == SETALL || cmd == GETALL || cmd == IPC_STAT || cmd == IPC_SET;
    if (needs_argument) {
        va_list args;
        va_start(args, cmd);
        argument = va_arg(args, union shim_semun);
        va_end(args);
    }

    int fd = open_set(semid);
    if (fd < 0) {
        errno = EINVAL;
        return -1;
    }
    struct shim_semset state;
    if (read_state_locked(fd, &state) < 0) {
        close(fd);
        return -1;
    }

    bool needs_semnum = cmd == GETVAL || cmd == GETPID || cmd == GETNCNT || cmd == GETZCNT || cmd == SETVAL;
    if (needs_semnum && (semnum < 0 || (uint32_t)semnum >= state.nsems)) {
        flock(fd, LOCK_UN);
        close(fd);
        errno = EINVAL;
        return -1;
    }

    int result = 0;
    bool changed = false;
    switch (cmd) {
        case GETVAL:
            result = state.values[semnum];
            break;
        case GETPID:
            result = state.last_pid[semnum];
            break;
        case GETNCNT:
        case GETZCNT:
            result = 0;
            break;
        case SETVAL:
            if (argument.val < 0 || argument.val > SHIM_SEMVMX) {
                errno = ERANGE;
                result = -1;
                break;
            }
            state.values[semnum] = (uint16_t)argument.val;
            state.last_pid[semnum] = (int32_t)getpid();
            state.ctime = (int64_t)time(NULL);
            changed = true;
            break;
        case GETALL:
            if (argument.array == NULL) {
                errno = EFAULT;
                result = -1;
                break;
            }
            memcpy(argument.array, state.values, state.nsems * sizeof(state.values[0]));
            break;
        case SETALL:
            if (argument.array == NULL) {
                errno = EFAULT;
                result = -1;
                break;
            }
            for (uint32_t i = 0; i < state.nsems; ++i) {
                if (argument.array[i] > SHIM_SEMVMX) {
                    errno = ERANGE;
                    result = -1;
                    break;
                }
            }
            if (result == 0) {
                memcpy(state.values, argument.array, state.nsems * sizeof(state.values[0]));
                for (uint32_t i = 0; i < state.nsems; ++i) {
                    state.last_pid[i] = (int32_t)getpid();
                }
                state.ctime = (int64_t)time(NULL);
                changed = true;
            }
            break;
        case IPC_STAT:
            if (argument.buf == NULL) {
                errno = EFAULT;
                result = -1;
                break;
            }
            memset(argument.buf, 0, sizeof(*argument.buf));
            argument.buf->sem_perm.__key = state.key;
            argument.buf->sem_perm.uid = state.uid;
            argument.buf->sem_perm.gid = state.gid;
            argument.buf->sem_perm.cuid = state.cuid;
            argument.buf->sem_perm.cgid = state.cgid;
            argument.buf->sem_perm.mode = state.mode;
            argument.buf->sem_otime = (time_t)state.otime;
            argument.buf->sem_ctime = (time_t)state.ctime;
            argument.buf->sem_nsems = state.nsems;
            break;
        case IPC_SET:
            if (argument.buf == NULL) {
                errno = EFAULT;
                result = -1;
                break;
            }
            state.uid = argument.buf->sem_perm.uid;
            state.gid = argument.buf->sem_perm.gid;
            state.mode = argument.buf->sem_perm.mode & 0777;
            state.ctime = (int64_t)time(NULL);
            changed = true;
            break;
        case IPC_RMID:
            state.removed = 1;
            result = full_pwrite(fd, &state, sizeof(state), 0);
            break;
        default:
            errno = EINVAL;
            result = -1;
            break;
    }

    if (cmd == IPC_RMID) {
        int saved_errno = errno;
        if (flock(fd, LOCK_UN) < 0 && result == 0) {
            result = -1;
            saved_errno = errno;
        }
        close(fd);
        if (result == 0) {
            result = remove_set_files(&state);
            saved_errno = errno;
        }
        errno = saved_errno;
        debug_log("semctl id=%d sem=%d cmd=%d -> %d", semid, semnum, cmd, result);
        return result;
    } else if (changed && result == 0) {
        result = write_state_unlock(fd, &state);
    } else {
        flock(fd, LOCK_UN);
    }
    close(fd);
    debug_log("semctl id=%d sem=%d cmd=%d -> %d", semid, semnum, cmd, result);
    return result;
}

static int64_t monotonic_nanoseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
        return -1;
    }
    return (int64_t)now.tv_sec * INT64_C(1000000000) + now.tv_nsec;
}

static int perform_ops(int semid, struct sembuf *operations, size_t operation_count,
                       const struct timespec *timeout) {
    if (operations == NULL || operation_count == 0 || operation_count > SHIM_MAX_SEMS) {
        errno = EINVAL;
        return -1;
    }
    if (timeout != NULL && (timeout->tv_sec < 0 || timeout->tv_nsec < 0 || timeout->tv_nsec >= 1000000000L)) {
        errno = EINVAL;
        return -1;
    }

    int64_t deadline = -1;
    if (timeout != NULL) {
        int64_t now = monotonic_nanoseconds();
        if (now < 0) {
            return -1;
        }
        if (timeout->tv_sec > INT64_MAX / INT64_C(1000000000)) {
            deadline = INT64_MAX;
        } else {
            int64_t delta = (int64_t)timeout->tv_sec * INT64_C(1000000000) + timeout->tv_nsec;
            deadline = delta > INT64_MAX - now ? INT64_MAX : now + delta;
        }
    }

    unsigned delay_microseconds = 1000;
    for (;;) {
        int fd = open_set(semid);
        if (fd < 0) {
            errno = EINVAL;
            return -1;
        }
        struct shim_semset state;
        if (read_state_locked(fd, &state) < 0) {
            close(fd);
            return -1;
        }

        uint16_t proposed[SHIM_MAX_SEMS];
        memcpy(proposed, state.values, state.nsems * sizeof(proposed[0]));
        bool would_block = false;
        bool no_wait = false;
        for (size_t i = 0; i < operation_count; ++i) {
            struct sembuf operation = operations[i];
            if (operation.sem_num >= state.nsems) {
                flock(fd, LOCK_UN);
                close(fd);
                errno = EFBIG;
                return -1;
            }
            int current = proposed[operation.sem_num];
            if (operation.sem_op < 0) {
                int amount = -(int)operation.sem_op;
                if (current < amount) {
                    would_block = true;
                    no_wait = (operation.sem_flg & IPC_NOWAIT) != 0;
                    break;
                }
                proposed[operation.sem_num] = (uint16_t)(current - amount);
            } else if (operation.sem_op == 0) {
                if (current != 0) {
                    would_block = true;
                    no_wait = (operation.sem_flg & IPC_NOWAIT) != 0;
                    break;
                }
            } else {
                if (current + operation.sem_op > SHIM_SEMVMX) {
                    flock(fd, LOCK_UN);
                    close(fd);
                    errno = ERANGE;
                    return -1;
                }
                proposed[operation.sem_num] = (uint16_t)(current + operation.sem_op);
            }
        }

        if (!would_block) {
            memcpy(state.values, proposed, state.nsems * sizeof(state.values[0]));
            for (size_t i = 0; i < operation_count; ++i) {
                state.last_pid[operations[i].sem_num] = (int32_t)getpid();
            }
            state.otime = (int64_t)time(NULL);
            int result = write_state_unlock(fd, &state);
            close(fd);
            debug_log("semop id=%d count=%zu -> %d", semid, operation_count, result);
            return result;
        }

        flock(fd, LOCK_UN);
        close(fd);
        if (no_wait) {
            errno = EAGAIN;
            return -1;
        }
        if (deadline >= 0) {
            int64_t now = monotonic_nanoseconds();
            if (now < 0) {
                return -1;
            }
            if (now >= deadline) {
                errno = EAGAIN;
                return -1;
            }
            int64_t remaining_us = (deadline - now) / 1000;
            if (remaining_us < (int64_t)delay_microseconds) {
                delay_microseconds = remaining_us > 0 ? (unsigned)remaining_us : 1;
            }
        }

        struct timespec pause = {
            .tv_sec = delay_microseconds / 1000000,
            .tv_nsec = (long)(delay_microseconds % 1000000) * 1000,
        };
        if (nanosleep(&pause, NULL) < 0) {
            return -1;
        }
        if (delay_microseconds < 20000) {
            delay_microseconds *= 2;
        }
    }
}

int semop(int semid, struct sembuf *operations, size_t operation_count) {
    return perform_ops(semid, operations, operation_count, NULL);
}

int semtimedop(int semid, struct sembuf *operations, size_t operation_count,
               const struct timespec *timeout) {
    return perform_ops(semid, operations, operation_count, timeout);
}
