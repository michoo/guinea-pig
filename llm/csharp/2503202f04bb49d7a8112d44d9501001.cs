using System.Data.SqlClient;

namespace GuineaPig.Sast
{
    public class DatabaseClient
    {
        public void Connect(string tag)
        {
            string connectionString =
                "Server=db.internal;Database=app;User Id=admin;Password=P@ssw0rd123!;";
            using (var conn = new SqlConnection(connectionString))
            {
                conn.Open();
                using (var cmd = new SqlCommand("SELECT 1 WHERE Tag = '" + tag + "'", conn))
                {
                    cmd.ExecuteNonQuery();
                }
            }
        }
    }
}
