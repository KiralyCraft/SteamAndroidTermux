#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

union semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
    struct seminfo *__buf;
};

static void fail(const char *message) {
    perror(message);
    exit(1);
}

int main(void) {
    int semid = semget(IPC_PRIVATE, 2, IPC_CREAT | 0600);
    if (semid < 0) {
        fail("semget private");
    }

    unsigned short initial[2] = {0, 7};
    union semun argument = {.array = initial};
    if (semctl(semid, 0, SETALL, argument) < 0) {
        fail("semctl SETALL");
    }

    unsigned short observed[2] = {0, 0};
    argument.array = observed;
    if (semctl(semid, 0, GETALL, argument) < 0 || observed[0] != 0 || observed[1] != 7) {
        fail("semctl GETALL");
    }

    pid_t child = fork();
    if (child < 0) {
        fail("fork");
    }
    if (child == 0) {
        struct sembuf decrement = {.sem_num = 0, .sem_op = -1, .sem_flg = 0};
        if (semop(semid, &decrement, 1) < 0) {
            fail("child semop decrement");
        }
        _exit(0);
    }

    struct timespec child_wait = {.tv_sec = 0, .tv_nsec = 50000000};
    if (nanosleep(&child_wait, NULL) < 0) {
        fail("nanosleep");
    }
    struct sembuf increment = {.sem_num = 0, .sem_op = 1, .sem_flg = 0};
    if (semop(semid, &increment, 1) < 0) {
        fail("parent semop increment");
    }

    int status;
    if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fail("child status");
    }
    if (semctl(semid, 0, GETVAL) != 0) {
        fail("semctl GETVAL");
    }

    struct sembuf unavailable = {.sem_num = 0, .sem_op = -1, .sem_flg = IPC_NOWAIT};
    errno = 0;
    if (semop(semid, &unavailable, 1) != -1 || errno != EAGAIN) {
        fail("semop IPC_NOWAIT");
    }

    struct timespec timeout = {.tv_sec = 0, .tv_nsec = 10000000};
    struct sembuf timed_unavailable = {.sem_num = 0, .sem_op = -1, .sem_flg = 0};
    errno = 0;
    if (semtimedop(semid, &timed_unavailable, 1, &timeout) != -1 || errno != EAGAIN) {
        fail("semtimedop timeout");
    }

    struct semid_ds metadata;
    argument.buf = &metadata;
    if (semctl(semid, 0, IPC_STAT, argument) < 0 || metadata.sem_nsems != 2) {
        fail("semctl IPC_STAT");
    }
    if (semctl(semid, 0, IPC_RMID) < 0) {
        fail("semctl IPC_RMID");
    }

    key_t key = (key_t)(0x230000U | ((unsigned)getpid() & 0xffffU));
    int named = semget(key, 1, IPC_CREAT | IPC_EXCL | 0600);
    if (named < 0) {
        fail("semget named");
    }
    int reopened = semget(key, 0, 0);
    if (reopened != named) {
        fail("semget reopen");
    }
    errno = 0;
    if (semget(key, 1, IPC_CREAT | IPC_EXCL | 0600) != -1 || errno != EEXIST) {
        fail("semget exclusive");
    }
    if (semctl(named, 0, IPC_RMID) < 0) {
        fail("semctl named IPC_RMID");
    }
    named = semget(key, 1, IPC_CREAT | IPC_EXCL | 0600);
    if (named < 0 || semctl(named, 0, IPC_RMID) < 0) {
        fail("semget named recreate");
    }

    puts("sysvsem shim tests passed");
    return 0;
}
