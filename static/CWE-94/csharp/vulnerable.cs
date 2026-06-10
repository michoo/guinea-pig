// CWE-94: Improper Control of Generation of Code ('Code Injection')
// User input is embedded into C# source which is then compiled and executed at runtime.
// Vulnerable sink: CSharpCodeProvider.CompileAssemblyFromSource on source built from userInput

using System.CodeDom.Compiler;
using Microsoft.CSharp;

namespace GuineaPig.Sast
{
    public class CWE_94
    {
        public void CompileAndRun(string userInput)
        {
            string source = "public class Gen { public static void Run() { " + userInput + " } }";
            var provider = new CSharpCodeProvider();
            var parameters = new CompilerParameters { GenerateInMemory = true };
            CompilerResults results = provider.CompileAssemblyFromSource(parameters, source);
            var asm = results.CompiledAssembly;
            asm.GetType("Gen").GetMethod("Run").Invoke(null, null);
        }
    }
}
