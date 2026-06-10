/* CWE-787: Out-of-bounds Write
   An attacker-controlled index is used to write past the end of a fixed array.
   Vulnerable sink: array[index] = value with unchecked index */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    int table[10];

    if (argc < 2)
        return 1;

    int index = atoi(argv[1]);

    /* No bounds check: index may be >= 10 or negative */
    table[index] = 1337;

    printf("%d\n", table[index]);
    return 0;
}
