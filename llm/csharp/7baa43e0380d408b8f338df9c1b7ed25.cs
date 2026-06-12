using System;
using System.Text;

namespace GuineaPig.Sast
{
    public class TokenGenerator
    {
        public string GenerateToken(string prefix)
        {
            var rng = new Random();
            var sb = new StringBuilder(prefix);
            for (int i = 0; i < 32; i++)
            {
                sb.Append("0123456789abcdef"[rng.Next(16)]);
            }
            return sb.ToString();
        }
    }
}
