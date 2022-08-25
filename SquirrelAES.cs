using System;
using System.Text;
using EasyEncrypt2;
using System.IO;
using System.Security.Cryptography;

namespace ScorpionAES
{
    public static class ScorpionAES
    {
        public static void encryptFile(string path, string destination_path)
        {
            var encrypter = new EasyEncrypt();
            encrypter.EncryptFile(path, destination_path);
            return;
        }

        public static void decryptFile(string path, string destination_path)
        {
            var encrypter = new EasyEncrypt();
            encrypter.DecryptFile(path, destination_path);
            return;
        }

        public static byte[] encryptData(string contents, string pwd)
        {
            using var encrypterWithPassword = new EasyEncrypt(pwd, "Salty09820");
            return encrypterWithPassword.Encrypt(Encoding.UTF8.GetBytes(contents));
        }

        public static string decryptData(byte[] contents, string pwd)
        {
            using var encrypterWithPassword = new EasyEncrypt(pwd, "Salty09820");
            var decryptedArray = encrypterWithPassword.Decrypt(contents);
            return Encoding.UTF8.GetString(decryptedArray, 0, decryptedArray.Length);
        }
    }

    public static class ScorpionAESInHouse
    {
        public static void exportNewKey(string path)
        {
            //Generate random bytes for key
            byte[] b_key = new byte[0x10];
            Random rnd = new Random((int)DateTime.Now.Ticks);
            rnd.NextBytes(b_key);

            //Save key to file
            File.WriteAllBytes(path, b_key);
            return;
        }

        public static byte[] importKey(string path)
        {
            return File.ReadAllBytes(path);
        }

        public static byte[] encrypt(string data, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (data == null || data.Length <= 0)
                throw new ArgumentNullException("data");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(data);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        public static string decrypt(byte[] data, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (data == null || data.Length <= 0)
                throw new ArgumentNullException("data");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(data))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }
    }
}
