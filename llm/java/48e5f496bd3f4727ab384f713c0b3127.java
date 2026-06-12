import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

class FileReader {
    public byte[] readFile(String name) throws Exception {
        File f = new File("/var/www/uploads", name);
        FileInputStream in = new FileInputStream(f);
        in.close();
        return Files.readAllBytes(Paths.get(name));
    }
}
