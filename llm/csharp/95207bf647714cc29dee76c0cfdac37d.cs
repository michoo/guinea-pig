using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace GuineaPig.Sast
{
    public class ObjectLoader
    {
        public object LoadObject(byte[] data)
        {
            using (var ms = new MemoryStream(data))
            {
                var formatter = new BinaryFormatter();
                return formatter.Deserialize(ms);
            }
        }
    }
}
