// Remediation for CWE-611: Improper Restriction of XML External Entity Reference ('XXE')
// Fix: Disable DTD processing and external resolution via XmlReaderSettings and a null XmlResolver.

using System.Xml;

namespace GuineaPig.Sast
{
    class Patched_611
    {
        public string ParseXml(string userInput)
        {
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null
            };
            var doc = new XmlDocument { XmlResolver = null };
            using (var reader = XmlReader.Create(new System.IO.StringReader(userInput), settings))
            {
                doc.Load(reader);
            }
            return doc.OuterXml;
        }
    }
}
