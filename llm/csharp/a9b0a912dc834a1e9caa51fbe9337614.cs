using System.Xml;

namespace GuineaPig.Sast
{
    public class XmlLoader
    {
        public string ParseXml(string content)
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Parse,
                XmlResolver = new XmlUrlResolver()
            };
            var doc = new XmlDocument { XmlResolver = new XmlUrlResolver() };
            using (var reader = XmlReader.Create(new System.IO.StringReader(content), settings))
            {
                doc.Load(reader);
            }
            return doc.OuterXml;
        }
    }
}
