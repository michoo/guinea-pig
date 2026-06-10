// Remediation for CWE-78: OS Command Injection
// Fix: Use ProcessBuilder with a fixed argument list and validate the input as a host token.

import java.util.regex.Pattern;

class Patched_78 {
    private static final Pattern HOST = Pattern.compile("[A-Za-z0-9.-]{1,253}");

    public void runCommand(String userInput) throws Exception {
        if (userInput == null || !HOST.matcher(userInput).matches()) {
            throw new IllegalArgumentException("Invalid host");
        }
        ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", userInput);
        Process p = pb.start();
        p.waitFor();
    }
}
