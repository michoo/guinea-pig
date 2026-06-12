#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    int table[10];

    if (argc < 2)
        return 1;

    int index = atoi(argv[1]);

    table[index] = 1337;

    printf("%d\n", table[index]);
    return 0;
}
