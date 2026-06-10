/* Remediation for CWE-415: Double Free
   Fix: Free the pointer exactly once and set it to NULL to prevent a second free. */
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    char *data = malloc(64);
    if (!data)
        return 1;

    data[0] = 'A';

    /* Free once, then null out so any later free is a safe no-op */
    free(data);
    data = NULL;

    return 0;
}
