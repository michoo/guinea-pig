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

    return buffer[0];
}

int main(void)
{
    printf("%d\n", process(128));
    return 0;
}
