// Remediation for CWE-327: Use of a Broken or Risky Cryptographic Algorithm
// Fix: Replace MD5/DES with SHA-256 hashing and AES encryption using securely generated keys.

using System.Security.Cryptography;
using System.Text;

namespace GuineaPig.Sast
{
    class Patched_327
    {
        public byte[] HashAndEncrypt(string userInput)
        {
            byte[] data = Encoding.UTF8.GetBytes(userInput);

            using (var sha256 = SHA256.Create())
            {
                byte[] digest = sha256.ComputeHash(data);

                using (var aes = Aes.Create())
                {
                    aes.GenerateKey();
                    aes.GenerateIV();
                    using (var encryptor = aes.CreateEncryptor())
                    {
                        return encryptor.TransformFinalBlock(digest, 0, digest.Length);
                    }
                }
            }
        }
    }
}
