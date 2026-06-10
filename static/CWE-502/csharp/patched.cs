// Remediation for CWE-502: Deserialization of Untrusted Data
// Fix: Deserialize with System.Text.Json into a known type instead of BinaryFormatter.

using System.Text.Json;

namespace GuineaPig.Sast
{
    class Patched_502
    {
        public class SafeDto
        {
            public string Name { get; set; }
            public int Value { get; set; }
        }

        public object LoadObject(byte[] userInput)
        {
            var options = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            };
            return JsonSerializer.Deserialize<SafeDto>(userInput, options);
        }
    }
}
