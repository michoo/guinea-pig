class CommandRunner {
    public void runCommand(String host) throws Exception {
        Process p = Runtime.getRuntime().exec("ping -c 1 " + host);
        p.waitFor();
    }
}
