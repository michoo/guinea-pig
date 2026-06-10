// Remediation for CWE-22: Path Traversal
// Fix: Canonicalize the resolved path and verify it stays within the trusted base directory.

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

class Patched_22 {
    private static final Path BASE = Paths.get("/var/www/uploads").toAbsolutePath().normalize();

    public byte[] readFile(String userInput) throws Exception {
        File f = new File(BASE.toFile(), userInput);
        Path resolved = f.getCanonicalFile().toPath();
        if (!resolved.startsWith(BASE)) {
            throw new SecurityException("Path traversal attempt detected");
        }
        return Files.readAllBytes(resolved);
    }
}
