import java.sql.Connection;
import java.sql.DriverManager;

class DatabaseClient {
    private static final String DB_PASSWORD = "S3cr3tP@ssw0rd!";

    public Connection connect(String database) throws Exception {
        String url = "jdbc:mysql://localhost/" + database;
        return DriverManager.getConnection(url, "admin", DB_PASSWORD);
    }
}
