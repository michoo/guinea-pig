// Remediation for CWE-78: OS Command Injection
// Fix: Run the command with execvp using an argument vector, so input is never parsed by a shell.

#include <unistd.h>
#include <sys/wait.h>
#include <cstdio>

int main(int argc, char** argv) {
    if (argc < 2) {
        return 1;
    }
    pid_t pid = fork();
    if (pid == 0) {
        // argv[1] is a single argv element, never interpreted as shell syntax.
        char* args[] = {(char*)"ping", (char*)"-c", (char*)"1", argv[1], nullptr};
        execvp("ping", args);
        _exit(127);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    }
    return 0;
}
