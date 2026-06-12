#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    int *values = malloc(100 * sizeof(int));

    values[0] = 42;
    printf("%d\n", values[0]);

    free(values);
    return 0;
}
