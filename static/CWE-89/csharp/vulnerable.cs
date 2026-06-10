// CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
// User input is concatenated directly into a SQL query string and executed.
// Vulnerable sink: new SqlCommand(query, conn) where query = "... " + userInput

using System.Data.SqlClient;

namespace GuineaPig.Sast
{
    public class CWE_89
    {
        public void LookupUser(string userInput)
        {
            using (var conn = new SqlConnection("Server=db;Database=app;Integrated Security=true;"))
            {
                conn.Open();
                string query = "SELECT * FROM Users WHERE Name = '" + userInput + "'";
                using (var cmd = new SqlCommand(query, conn))
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
