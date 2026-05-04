#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#define PID_FILE ".monitor_pid"

void handle_signal(int sig) {
    if (sig == SIGUSR1) {
        printf("\n[MONITOR] Raport nou detectat.\n");
    } else if (sig == SIGINT) {
        printf("\n[MONITOR] Inchidere proces.\n");
        unlink(PID_FILE);
        exit(0);
    }
}

int main() {
    int fd = open(PID_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        perror("Eroare PID file");
        exit(1);
    }

    char pid_str[10];
    snprintf(pid_str, sizeof(pid_str), "%d", getpid());
    write(fd, pid_str, strlen(pid_str));
    close(fd);

    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGUSR1, &sa, NULL) == -1) {
        unlink(PID_FILE);
        exit(1);
    }

    if (sigaction(SIGINT, &sa, NULL) == -1) {
        unlink(PID_FILE);
        exit(1);
    }

    while (1) {
        pause();
    }

    return 0;
}