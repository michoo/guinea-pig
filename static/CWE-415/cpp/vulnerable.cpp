// CWE-415: Double Free
// Releases the same heap allocation twice, corrupting the allocator's state.
// Vulnerable sink: free() called twice on the same pointer

#include <cstdlib>
#include <cstdio>

int main() {
    char* buf = (char*)malloc(64);
    if (!buf) {
        return 1;
    }
    free(buf);
    // Second free of the same pointer corrupts heap metadata.
    free(buf);
    printf("done\n");
    return 0;
}
