// Remediation for CWE-78: OS Command Injection
// Fix: Invoke the target executable directly with ArgumentList and no shell, passing input as a discrete argument.

using System.Diagnostics;

namespace GuineaPig.Sast
{
    class Patched_78
    {
        public void RunCommand(string userInput)
        {
            var psi = new ProcessStartInfo("/usr/bin/myttool")
            {
                UseShellExecute = false,
                RedirectStandardOutput = true
            };
            // Passed as a separate argument; no shell interpretation occurs.
            psi.ArgumentList.Add(userInput);
            Process.Start(psi);
        }
    }
}
