// CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
// Builds a shell command string from attacker-controlled argv and runs it via the shell.
// Vulnerable sink: system()

#include <cstdlib>
#include <cstring>
#include <cstdio>

int main(int argc, char** argv) {
    if (argc < 2) {
        return 1;
    }
    char cmd[256];
    // argv[1] is concatenated unescaped: "; rm -rf /" runs as a shell command.
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", argv[1]);
    system(cmd);
    return 0;
}
