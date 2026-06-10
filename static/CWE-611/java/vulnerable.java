// CWE-611: Improper Restriction of XML External Entity Reference (XXE)
// Untrusted XML is parsed without disabling external entity resolution.
// Vulnerable sink: DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(...)

import java.io.ByteArrayInputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

class CWE_611 {
    public Document parseXml(String userInput) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(new ByteArrayInputStream(userInput.getBytes()));
    }
}
