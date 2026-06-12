import java.security.MessageDigest;
import javax.crypto.Cipher;

class CryptoHelper {
    public byte[] hash(String input) throws Exception {
        Cipher cipher = Cipher.getInstance("DES");
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(input.getBytes());
    }
}
