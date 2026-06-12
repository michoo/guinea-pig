#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    char *data = malloc(64);
    if (!data)
        return 1;

    data[0] = 'A';
    free(data);

    free(data);

    return 0;
}
