// CWE-611: Improper Restriction of XML External Entity Reference ('XXE')
// Untrusted XML is parsed with DTD processing and an external resolver enabled.
// Vulnerable sink: XmlDocument.LoadXml with XmlResolver set and DtdProcessing = Parse

using System.Xml;

namespace GuineaPig.Sast
{
    public class CWE_611
    {
        public string ParseXml(string userInput)
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Parse,
                XmlResolver = new XmlUrlResolver()
            };
            var doc = new XmlDocument { XmlResolver = new XmlUrlResolver() };
            using (var reader = XmlReader.Create(new System.IO.StringReader(userInput), settings))
            {
                doc.Load(reader);
            }
            return doc.OuterXml;
        }
    }
}
