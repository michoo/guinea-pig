// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
// Sensitive input is hashed/encrypted using broken algorithms (MD5 and DES).
// Vulnerable sink: MD5.Create() and new DESCryptoServiceProvider()

using System.Security.Cryptography;
using System.Text;

namespace GuineaPig.Sast
{
    public class CWE_327
    {
        public byte[] HashAndEncrypt(string userInput)
        {
            byte[] data = Encoding.UTF8.GetBytes(userInput);

            using (var md5 = MD5.Create())
            {
                byte[] digest = md5.ComputeHash(data);

                using (var des = new DESCryptoServiceProvider())
                using (var encryptor = des.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(digest, 0, digest.Length);
                }
            }
        }
    }
}
