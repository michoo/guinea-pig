// Remediation for CWE-502: Deserialization of Untrusted Data
// Fix: Restrict ObjectInputStream to an explicit allowlist of expected classes.

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Set;

class Patched_502 {
    private static final Set<String> ALLOWED = Set.of("java.lang.String", "java.lang.Number");

    static class SafeObjectInputStream extends ObjectInputStream {
        SafeObjectInputStream(ByteArrayInputStream in) throws IOException { super(in); }
        protected Class<?> resolveClass(ObjectStreamClass desc)
                throws IOException, ClassNotFoundException {
            if (!ALLOWED.contains(desc.getName())) {
                throw new InvalidClassException("Disallowed class", desc.getName());
            }
            return super.resolveClass(desc);
        }
    }

    public Object deserialize(byte[] userInput) throws Exception {
        try (ObjectInputStream ois =
                 new SafeObjectInputStream(new ByteArrayInputStream(userInput))) {
            return ois.readObject();
        }
    }
}
