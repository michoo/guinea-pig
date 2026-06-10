// CWE-502: Deserialization of Untrusted Data
// An untrusted byte stream is deserialized with BinaryFormatter, allowing arbitrary object construction.
// Vulnerable sink: BinaryFormatter.Deserialize(stream)

using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace GuineaPig.Sast
{
    public class CWE_502
    {
        public object LoadObject(byte[] userInput)
        {
            using (var ms = new MemoryStream(userInput))
            {
                var formatter = new BinaryFormatter();
                return formatter.Deserialize(ms);
            }
        }
    }
}
