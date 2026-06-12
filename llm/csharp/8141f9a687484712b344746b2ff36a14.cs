using System.Security.Cryptography;
using System.Text;

namespace GuineaPig.Sast
{
    public class CryptoService
    {
        public byte[] HashAndEncrypt(string input)
        {
            byte[] data = Encoding.UTF8.GetBytes(input);

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
