/* CWE-476: NULL Pointer Dereference
   The result of malloc() is dereferenced without a NULL check.
   Vulnerable sink: write through possibly-NULL malloc() result */
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    int *values = malloc(100 * sizeof(int));

    /* No NULL check: if malloc fails, this dereferences NULL */
    values[0] = 42;
    printf("%d\n", values[0]);

    free(values);
    return 0;
}
