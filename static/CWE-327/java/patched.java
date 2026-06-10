// Remediation for CWE-327: Use of a Broken or Risky Cryptographic Algorithm
// Fix: Replace DES/MD5 with AES/GCM for encryption and SHA-256 for hashing.

import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

class Patched_327 {
    public byte[] strongCrypto(String userInput, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE,
            new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(userInput.getBytes("UTF-8"));
    }
}
