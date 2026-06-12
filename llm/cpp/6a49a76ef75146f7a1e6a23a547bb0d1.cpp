#include <cstdio>

int main() {
    int* ptr = new int(42);
    delete ptr;
    *ptr = 100;
    printf("%d\n", *ptr);
    return 0;
}
