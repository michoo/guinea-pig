// Remediation for CWE-330: Use of Insufficiently Random Values
// Fix: Generate the token with a cryptographically strong SecureRandom source.

import java.security.SecureRandom;

class Patched_330 {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public String generateToken(String userInput) {
        long token = SECURE_RANDOM.nextLong();
        return userInput + "-" + Long.toHexString(token);
    }
}
