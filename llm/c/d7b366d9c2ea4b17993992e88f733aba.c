#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    char command[256];

    if (argc < 2)
        return 1;

    snprintf(command, sizeof(command), "ping -c 1 %s", argv[1]);
    system(command);

    return 0;
}
