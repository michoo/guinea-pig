// Remediation for CWE-415: Double Free
// Fix: Manage the allocation with std::unique_ptr so it is released exactly once automatically.

#include <cstdio>
#include <memory>

int main() {
    // unique_ptr owns the buffer and frees it once when it goes out of scope.
    std::unique_ptr<char[]> buf(new char[64]);
    if (!buf) {
        return 1;
    }
    printf("done\n");
    return 0;
}
