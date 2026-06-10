/* Remediation for CWE-242: Use of Inherently Dangerous Function
   Fix: Replace gets() with fgets(), which bounds the read to the buffer size. */
#include <stdio.h>
#include <string.h>

int main(void)
{
    char name[32];

    printf("Enter your name: ");

    /* fgets limits input to sizeof(name) - 1 and always NUL-terminates */
    if (fgets(name, sizeof(name), stdin) == NULL)
        return 1;

    name[strcspn(name, "\n")] = '\0';

    printf("Hello, %s\n", name);
    return 0;
}
