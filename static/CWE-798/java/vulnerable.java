// CWE-798: Use of Hard-coded Credentials
// A hard-coded database password is embedded in source and used to authenticate.
// Vulnerable sink: DriverManager.getConnection(url, user, "hardcodedPassword")

import java.sql.Connection;
import java.sql.DriverManager;

class CWE_798 {
    private static final String DB_PASSWORD = "S3cr3tP@ssw0rd!";

    public Connection connect(String userInput) throws Exception {
        String url = "jdbc:mysql://localhost/" + userInput;
        return DriverManager.getConnection(url, "admin", DB_PASSWORD);
    }
}
