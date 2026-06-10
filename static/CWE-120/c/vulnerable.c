/* CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')
   Copies an unbounded argv string into a fixed-size stack buffer.
   Vulnerable sink: strcpy() */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    char buffer[16];

    if (argc < 2)
        return 1;

    /* No length check: argv[1] may be longer than 16 bytes */
    strcpy(buffer, argv[1]);

    printf("Copied: %s\n", buffer);
    return 0;
}
