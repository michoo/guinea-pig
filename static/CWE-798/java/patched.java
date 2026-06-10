// Remediation for CWE-798: Use of Hard-coded Credentials
// Fix: Read database credentials from environment variables instead of embedding them.

import java.sql.Connection;
import java.sql.DriverManager;

class Patched_798 {
    public Connection connect(String database) throws Exception {
        String user = System.getenv("DB_USER");
        String password = System.getenv("DB_PASSWORD");
        if (user == null || password == null) {
            throw new IllegalStateException("DB credentials not configured");
        }
        String url = "jdbc:mysql://localhost/" + database;
        return DriverManager.getConnection(url, user, password);
    }
}
