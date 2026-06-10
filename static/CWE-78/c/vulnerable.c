/* CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
   A shell command string is built from untrusted argv and executed.
   Vulnerable sink: system() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    char command[256];

    if (argc < 2)
        return 1;

    /* Untrusted input concatenated into a shell command */
    snprintf(command, sizeof(command), "ping -c 1 %s", argv[1]);
    system(command);

    return 0;
}
