/* CWE-134: Use of Externally-Controlled Format String
   User-controlled argv is passed directly as the format string.
   Vulnerable sink: printf(argv[1]) */
#include <stdio.h>

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;

    /* Attacker controls the format string: %n, %x, etc. */
    printf(argv[1]);
    printf("\n");

    return 0;
}
