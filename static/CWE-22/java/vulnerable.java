// CWE-22: Path Traversal
// A user-supplied filename is used to build a filesystem path without validation.
// Vulnerable sink: Files.readAllBytes(Paths.get(userInput))

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

class CWE_22 {
    public byte[] readFile(String userInput) throws Exception {
        File f = new File("/var/www/uploads", userInput);
        FileInputStream in = new FileInputStream(f);
        in.close();
        return Files.readAllBytes(Paths.get(userInput));
    }
}
