#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;

    int count = atoi(argv[1]);

    char *buf = malloc(count * 64);
    if (!buf)
        return 1;

    for (int i = 0; i < count; i++)
        buf[i * 64] = 'A';

    free(buf);
    return 0;
}
