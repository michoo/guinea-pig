// CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
// User input is appended to a shell command and executed by the OS.
// Vulnerable sink: Process.Start("cmd.exe", "/c " + userInput)

using System.Diagnostics;

namespace GuineaPig.Sast
{
    public class CWE_78
    {
        public void RunCommand(string userInput)
        {
            var psi = new ProcessStartInfo("cmd.exe", "/c " + userInput)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true
            };
            Process.Start(psi);
        }
    }
}
