// Remediation for CWE-94: Code Injection
// Fix: Remove runtime compilation entirely and dispatch only against an explicit allow-list of known operations.

using System;
using System.Collections.Generic;

namespace GuineaPig.Sast
{
    class Patched_94
    {
        private static readonly Dictionary<string, Action> Allowed = new Dictionary<string, Action>
        {
            { "ping", () => Console.WriteLine("pong") },
            { "version", () => Console.WriteLine("1.0.0") }
        };

        public void CompileAndRun(string userInput)
        {
            if (Allowed.TryGetValue(userInput, out var action))
            {
                action();
            }
            else
            {
                throw new ArgumentException("Unknown operation.");
            }
        }
    }
}
