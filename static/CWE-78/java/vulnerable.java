// CWE-78: OS Command Injection
// User-controlled input is passed unsanitized to an OS command execution call.
// Vulnerable sink: Runtime.getRuntime().exec(userInput)

class CWE_78 {
    public void runCommand(String userInput) throws Exception {
        Process p = Runtime.getRuntime().exec("ping -c 1 " + userInput);
        p.waitFor();
    }
}
