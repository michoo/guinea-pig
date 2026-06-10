// CWE-190: Integer Overflow or Wraparound
// Computes an allocation size by multiplication that can wrap, under-allocating the buffer.
// Vulnerable sink: malloc(count * size)

#include <cstdlib>
#include <cstdio>
#include <cstring>

int main(int argc, char** argv) {
    if (argc < 2) {
        return 1;
    }
    unsigned int count = (unsigned int)atoi(argv[1]);
    // count * 8 can overflow and wrap to a tiny value, under-allocating.
    int* data = (int*)malloc(count * sizeof(long long));
    memset(data, 0, count * sizeof(long long));
    free(data);
    return 0;
}
