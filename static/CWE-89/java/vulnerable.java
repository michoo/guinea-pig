// CWE-89: SQL Injection
// User-controlled input is concatenated directly into a SQL query string.
// Vulnerable sink: Statement.executeQuery(concatenatedQuery)

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

class CWE_89 {
    public ResultSet findUser(String userInput) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app", "app", "app");
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE name = '" + userInput + "'";
        return stmt.executeQuery(query);
    }
}
