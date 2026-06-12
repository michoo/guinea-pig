#include <stdio.h>

int main(void)
{
    char name[32];

    printf("Enter your name: ");

    gets(name);

    printf("Hello, %s\n", name);
    return 0;
}
