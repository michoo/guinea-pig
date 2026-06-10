// CWE-330: Use of Insufficiently Random Values
// A security token is generated with a non-cryptographic PRNG.
// Vulnerable sink: new java.util.Random().nextLong()

import java.util.Random;

class CWE_330 {
    public String generateToken(String userInput) {
        Random random = new Random();
        long token = random.nextLong();
        return userInput + "-" + Long.toHexString(token);
    }
}
