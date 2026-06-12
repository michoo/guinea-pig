import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

class UserRepository {
    public ResultSet findUser(String name) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app", "app", "app");
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE name = '" + name + "'";
        return stmt.executeQuery(query);
    }
}
