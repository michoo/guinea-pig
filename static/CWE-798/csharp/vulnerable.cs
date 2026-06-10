// CWE-798: Use of Hard-coded Credentials
// A hard-coded database password is embedded in the connection string.
// Vulnerable sink: new SqlConnection("...;Password=<hardcoded>;")

using System.Data.SqlClient;

namespace GuineaPig.Sast
{
    public class CWE_798
    {
        public void Connect(string userInput)
        {
            string connectionString =
                "Server=db.internal;Database=app;User Id=admin;Password=P@ssw0rd123!;";
            using (var conn = new SqlConnection(connectionString))
            {
                conn.Open();
                using (var cmd = new SqlCommand("SELECT 1 WHERE Tag = '" + userInput + "'", conn))
                {
                    cmd.ExecuteNonQuery();
                }
            }
        }
    }
}
