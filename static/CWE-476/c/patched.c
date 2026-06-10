/* Remediation for CWE-476: NULL Pointer Dereference
   Fix: Check the malloc result for NULL before dereferencing it. */
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    int *values = malloc(100 * sizeof(int));

    /* Bail out safely if the allocation failed */
    if (values == NULL)
        return 1;

    values[0] = 42;
    printf("%d\n", values[0]);

    free(values);
    return 0;
}
