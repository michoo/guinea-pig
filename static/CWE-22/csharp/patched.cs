// Remediation for CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
// Fix: Resolve the combined path and verify it stays within the base directory before reading.

using System;
using System.IO;

namespace GuineaPig.Sast
{
    class Patched_22
    {
        public string ReadFile(string userInput)
        {
            string baseDir = Path.GetFullPath("/var/www/files");
            string fullPath = Path.GetFullPath(Path.Combine(baseDir, userInput));

            string baseWithSep = baseDir.EndsWith(Path.DirectorySeparatorChar.ToString())
                ? baseDir
                : baseDir + Path.DirectorySeparatorChar;

            if (!fullPath.StartsWith(baseWithSep, StringComparison.Ordinal))
            {
                throw new UnauthorizedAccessException("Path is outside the allowed directory.");
            }

            return File.ReadAllText(fullPath);
        }
    }
}
