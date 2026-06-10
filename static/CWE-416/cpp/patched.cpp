// Remediation for CWE-416: Use After Free
// Fix: Use all data before delete, then null the pointer so no dangling access can occur.

#include <cstdio>

int main() {
    int* ptr = new int(42);
    // Perform all reads/writes while the allocation is still valid.
    *ptr = 100;
    printf("%d\n", *ptr);
    delete ptr;
    // Null out the pointer to make any later use a safe, detectable null deref.
    ptr = nullptr;
    return 0;
}
