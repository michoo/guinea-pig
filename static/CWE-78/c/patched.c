/* Remediation for CWE-78: OS Command Injection
   Fix: Avoid the shell by using execvp with an argument vector so input is never parsed by a shell. */
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;

    /* Argument vector: argv[1] is a single ping target, never shell-interpreted */
    char *args[] = { "ping", "-c", "1", "--", argv[1], NULL };

    pid_t pid = fork();
    if (pid < 0)
        return 1;
    if (pid == 0) {
        execvp(args[0], args);
        _exit(127);
    }

    int status;
    waitpid(pid, &status, 0);
    return 0;
}
