using System.Diagnostics;

namespace GuineaPig.Sast
{
    public class CommandRunner
    {
        public void RunCommand(string input)
        {
            var psi = new ProcessStartInfo("cmd.exe", "/c " + input)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true
            };
            Process.Start(psi);
        }
    }
}
