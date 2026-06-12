using System.Data.SqlClient;

namespace GuineaPig.Sast
{
    public class UserRepository
    {
        public void LookupUser(string name)
        {
            using (var conn = new SqlConnection("Server=db;Database=app;Integrated Security=true;"))
            {
                conn.Open();
                string query = "SELECT * FROM Users WHERE Name = '" + name + "'";
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
