// Remediation for CWE-134: Use of Externally-Controlled Format String
// Fix: Pass the user input as a data argument to a constant "%s" format string.

#include <cstdio>

int main(int argc, char** argv) {
    if (argc < 2) {
        return 1;
    }
    char* userInput = argv[1];
    // Format string is a fixed literal; user input cannot inject %x/%n directives.
    printf("%s", userInput);
    return 0;
}
