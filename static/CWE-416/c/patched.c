/* Remediation for CWE-416: Use After Free
   Fix: Set the pointer to NULL after free and do not dereference it afterwards. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char *data = malloc(32);
    if (!data)
        return 1;

    strcpy(data, "hello");
    printf("%s\n", data);

    /* Use the buffer only while it is valid, then release and clear it */
    free(data);
    data = NULL;

    return 0;
}
