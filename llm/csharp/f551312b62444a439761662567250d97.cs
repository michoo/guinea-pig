using System.IO;

namespace GuineaPig.Sast
{
    public class FileReader
    {
        public string ReadFile(string name)
        {
            string baseDir = "/var/www/files";
            string fullPath = Path.Combine(baseDir, name);
            return File.ReadAllText(fullPath);
        }
    }
}
