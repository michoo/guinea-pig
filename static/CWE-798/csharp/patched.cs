// Remediation for CWE-798: Use of Hard-coded Credentials
// Fix: Read the connection string from configuration and pass user input via a SQL parameter.

using System;
using System.Data.SqlClient;

namespace GuineaPig.Sast
{
    class Patched_798
    {
        public void Connect(string userInput)
        {
            string connectionString = Environment.GetEnvironmentVariable("APP_DB_CONNECTION");
            using (var conn = new SqlConnection(connectionString))
            {
                conn.Open();
                using (var cmd = new SqlCommand("SELECT 1 WHERE Tag = @tag", conn))
                {
                    cmd.Parameters.AddWithValue("@tag", userInput);
                    cmd.ExecuteNonQuery();
                }
            }
        }
    }
}
