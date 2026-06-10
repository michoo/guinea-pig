/* CWE-242: Use of Inherently Dangerous Function
   gets() cannot limit input length and always risks a buffer overflow.
   Vulnerable sink: gets() */
#include <stdio.h>

int main(void)
{
    char name[32];

    printf("Enter your name: ");

    /* gets() performs no bounds checking and is inherently unsafe */
    gets(name);

    printf("Hello, %s\n", name);
    return 0;
}
