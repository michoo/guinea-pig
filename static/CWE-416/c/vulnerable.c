/* CWE-416: Use After Free
   A heap pointer is dereferenced after it has been freed.
   Vulnerable sink: write/read through pointer after free() */
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

    /* Use after free: data is dangling here */
    strcpy(data, "world");
    printf("%s\n", data);

    return 0;
}
