/* CWE-401: Missing Release of Memory after Effective Lifetime
   Heap memory is allocated but never freed on the return path.
   Vulnerable sink: malloc() with no corresponding free() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int process(int n)
{
    char *buffer = malloc(n);
    if (!buffer)
        return -1;

    memset(buffer, 0, n);
    buffer[0] = 'X';

    /* Memory leak: buffer is never freed before returning */
    return buffer[0];
}

int main(void)
{
    printf("%d\n", process(128));
    return 0;
}
