// CWE-416: Use After Free
// Dereferences and writes through a heap pointer after it has been freed.
// Vulnerable sink: use of pointer after delete

#include <cstdio>

int main() {
    int* ptr = new int(42);
    delete ptr;
    // ptr is dangling: dereferencing freed memory is undefined behavior.
    *ptr = 100;
    printf("%d\n", *ptr);
    return 0;
}
