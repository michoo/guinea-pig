/* Remediation for CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
   Fix: Use snprintf with the buffer size to bound the copy and guarantee NUL-termination. */
#include <stdio.h>

int main(int argc, char **argv)
{
    char buffer[16];

    if (argc < 2)
        return 1;

    /* Bounded copy: never writes more than sizeof(buffer) bytes */
    snprintf(buffer, sizeof(buffer), "%s", argv[1]);

    printf("Copied: %s\n", buffer);
    return 0;
}
