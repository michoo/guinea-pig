// Remediation for CWE-190: Integer Overflow or Wraparound
// Fix: Reject counts whose multiplication by the element size would overflow before allocating.

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <limits>

int main(int argc, char** argv) {
    if (argc < 2) {
        return 1;
    }
    unsigned int count = (unsigned int)atoi(argv[1]);
    // Guard against wraparound: bail out if count * sizeof(long long) would overflow.
    if (count > std::numeric_limits<size_t>::max() / sizeof(long long)) {
        return 1;
    }
    size_t bytes = (size_t)count * sizeof(long long);
    long long* data = (long long*)malloc(bytes);
    if (!data) {
        return 1;
    }
    memset(data, 0, bytes);
    free(data);
    return 0;
}
