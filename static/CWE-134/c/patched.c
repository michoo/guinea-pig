/* Remediation for CWE-134: Use of Externally-Controlled Format String
   Fix: Pass a fixed "%s" format string so user input is treated as data, not a format. */
#include <stdio.h>

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;

    /* User input is an argument, never the format string */
    printf("%s\n", argv[1]);

    return 0;
}
