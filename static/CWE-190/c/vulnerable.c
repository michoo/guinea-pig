/* CWE-190: Integer Overflow or Wraparound
   A multiplication that can wrap around is used as the allocation size.
   Vulnerable sink: malloc(count * size) with attacker-controlled count */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;

    int count = atoi(argv[1]);

    /* count * 64 can overflow, yielding a tiny allocation */
    char *buf = malloc(count * 64);
    if (!buf)
        return 1;

    for (int i = 0; i < count; i++)
        buf[i * 64] = 'A';

    free(buf);
    return 0;
}
