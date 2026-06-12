#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    char buffer[16];

    if (argc < 2)
        return 1;

    strcpy(buffer, argv[1]);

    printf("Copied: %s\n", buffer);
    return 0;
}
