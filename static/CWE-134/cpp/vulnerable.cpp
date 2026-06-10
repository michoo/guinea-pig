// CWE-134: Use of Externally-Controlled Format String
// Passes attacker-controlled argv directly as the printf format string.
// Vulnerable sink: printf(userInput)

#include <cstdio>

int main(int argc, char** argv) {
    if (argc < 2) {
        return 1;
    }
    char* userInput = argv[1];
    // Format string is attacker-controlled: %x/%n leak memory or write to it.
    printf(userInput);
    return 0;
}
