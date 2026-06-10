// CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
// User-controlled filename is combined with a base directory and read without validation.
// Vulnerable sink: File.ReadAllText(Path.Combine(baseDir, userInput))

using System.IO;

namespace GuineaPig.Sast
{
    public class CWE_22
    {
        public string ReadFile(string userInput)
        {
            string baseDir = "/var/www/files";
            string fullPath = Path.Combine(baseDir, userInput);
            return File.ReadAllText(fullPath);
        }
    }
}
