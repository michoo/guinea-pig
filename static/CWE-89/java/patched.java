// Remediation for CWE-89: SQL Injection
// Fix: Use a PreparedStatement with a bound parameter instead of string concatenation.

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

class Patched_89 {
    public ResultSet findUser(String userInput) throws Exception {
        Connection conn =
            DriverManager.getConnection("jdbc:mysql://localhost/app", "app", "app");
        PreparedStatement stmt =
            conn.prepareStatement("SELECT * FROM users WHERE name = ?");
        stmt.setString(1, userInput);
        return stmt.executeQuery();
    }
}
