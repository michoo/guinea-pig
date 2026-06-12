using System.CodeDom.Compiler;
using Microsoft.CSharp;

namespace GuineaPig.Sast
{
    public class ScriptRunner
    {
        public void CompileAndRun(string body)
        {
            string source = "public class Gen { public static void Run() { " + body + " } }";
            var provider = new CSharpCodeProvider();
            var parameters = new CompilerParameters { GenerateInMemory = true };
            CompilerResults results = provider.CompileAssemblyFromSource(parameters, source);
            var asm = results.CompiledAssembly;
            asm.GetType("Gen").GetMethod("Run").Invoke(null, null);
        }
    }
}
