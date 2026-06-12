#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char *data = malloc(32);
    if (!data)
        return 1;

    strcpy(data, "hello");
    free(data);

    strcpy(data, "world");
    printf("%s\n", data);

    return 0;
}
