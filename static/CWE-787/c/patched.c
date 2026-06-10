/* Remediation for CWE-787: Out-of-bounds Write
   Fix: Bounds-check the index against the array length before writing. */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    int table[10];

    if (argc < 2)
        return 1;

    int index = atoi(argv[1]);

    /* Reject negative or too-large indices before indexing */
    if (index < 0 || index >= (int)(sizeof(table) / sizeof(table[0])))
        return 1;

    table[index] = 1337;

    printf("%d\n", table[index]);
    return 0;
}
