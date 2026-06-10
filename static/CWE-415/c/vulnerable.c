/* CWE-415: Double Free
   The same heap pointer is passed to free() twice.
   Vulnerable sink: free() called twice on the same pointer */
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    char *data = malloc(64);
    if (!data)
        return 1;

    data[0] = 'A';
    free(data);

    /* Double free: data was already released above */
    free(data);

    return 0;
}
