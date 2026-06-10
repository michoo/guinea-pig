// CWE-502: Deserialization of Untrusted Data
// Untrusted bytes are deserialized into a Java object, allowing arbitrary object instantiation.
// Vulnerable sink: new ObjectInputStream(...).readObject()

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

class CWE_502 {
    public Object deserialize(byte[] userInput) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(userInput);
        ObjectInputStream ois = new ObjectInputStream(bis);
        return ois.readObject();
    }
}
