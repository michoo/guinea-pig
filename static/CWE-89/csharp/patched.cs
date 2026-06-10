// Remediation for CWE-89: SQL Injection
// Fix: Use a parameterized SqlCommand with Parameters.AddWithValue instead of string concatenation.

using System.Data.SqlClient;

namespace GuineaPig.Sast
{
    class Patched_89
    {
        public void LookupUser(string userInput)
        {
            using (var conn = new SqlConnection("Server=db;Database=app;Integrated Security=true;"))
            {
                conn.Open();
                string query = "SELECT * FROM Users WHERE Name = @name";
                using (var cmd = new SqlCommand(query, conn))
                {
                    cmd.Parameters.AddWithValue("@name", userInput);
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            System.Console.WriteLine(reader[0]);
                        }
                    }
                }
            }
        }
    }
}
