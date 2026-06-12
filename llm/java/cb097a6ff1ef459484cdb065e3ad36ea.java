import java.util.Random;

class TokenGenerator {
    public String generateToken(String input) {
        Random random = new Random();
        long token = random.nextLong();
        return input + "-" + Long.toHexString(token);
    }
}
