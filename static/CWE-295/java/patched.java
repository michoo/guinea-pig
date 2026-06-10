// Remediation for CWE-295: Improper Certificate Validation
// Fix: Use the platform default TrustManagers so the JVM validates the certificate chain.

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.security.KeyStore;

class Patched_295 {
    public void trustDefault() throws Exception {
        TrustManagerFactory tmf =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null); // load the default system trust store
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, tmf.getTrustManagers(), new java.security.SecureRandom());
    }
}
