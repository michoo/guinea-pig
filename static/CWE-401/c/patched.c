/* Remediation for CWE-401: Missing Release of Memory after Effective Lifetime
   Fix: Free the allocation on every return path before leaving the function. */
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

    int result = buffer[0];

    /* Memory is released before returning */
    free(buffer);
    return result;
}

int main(void)
{
    printf("%d\n", process(128));
    return 0;
}
