/* Remediation for CWE-190: Integer Overflow or Wraparound
   Fix: Validate the count and reject sizes that would overflow before calling malloc. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;

    long count = atol(argv[1]);

    /* Reject negative or oversized counts that would overflow count * 64 */
    if (count < 0 || count > (long)(SIZE_MAX / 64))
        return 1;

    char *buf = malloc((size_t)count * 64);
    if (!buf)
        return 1;

    for (long i = 0; i < count; i++)
        buf[i * 64] = 'A';

    free(buf);
    return 0;
}
