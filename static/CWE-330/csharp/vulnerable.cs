// CWE-330: Use of Insufficiently Random Values
// A security token is generated using the non-cryptographic System.Random PRNG.
// Vulnerable sink: new System.Random() used to build a token

using System;
using System.Text;

namespace GuineaPig.Sast
{
    public class CWE_330
    {
        public string GenerateToken(string userInput)
        {
            var rng = new Random();
            var sb = new StringBuilder(userInput);
            for (int i = 0; i < 32; i++)
            {
                sb.Append("0123456789abcdef"[rng.Next(16)]);
            }
            return sb.ToString();
        }
    }
}
