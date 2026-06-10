// Remediation for CWE-330: Use of Insufficiently Random Values
// Fix: Generate the token bytes with the cryptographically secure RandomNumberGenerator.

using System.Security.Cryptography;
using System.Text;

namespace GuineaPig.Sast
{
    class Patched_330
    {
        public string GenerateToken(string userInput)
        {
            const string hex = "0123456789abcdef";
            var sb = new StringBuilder(userInput);
            byte[] randomBytes = new byte[32];

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }

            for (int i = 0; i < randomBytes.Length; i++)
            {
                sb.Append(hex[randomBytes[i] % 16]);
            }
            return sb.ToString();
        }
    }
}
