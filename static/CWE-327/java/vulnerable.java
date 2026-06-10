// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
// Weak/broken algorithms (DES, MD5) are used for encryption and hashing.
// Vulnerable sink: Cipher.getInstance("DES") / MessageDigest.getInstance("MD5")

import java.security.MessageDigest;
import javax.crypto.Cipher;

class CWE_327 {
    public byte[] weakCrypto(String userInput) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(userInput.getBytes());
    }
}
