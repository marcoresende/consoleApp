using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CypherExample
{

    public static class MyCryptoClass
    {
        public static RijndaelManaged myRijndael;

        private static string pin = "0372121493";

        public static string DecryptText(string encryptedString)
        {
            using (myRijndael = new RijndaelManaged())
            {
                SHA256 sha256 = SHA256Managed.Create();
                byte[] bytes = Encoding.UTF8.GetBytes(pin);
                byte[] hash = sha256.ComputeHash(bytes);

                byte[] key = SubArray(hash, 0, 16);

                myRijndael.Key = key;
                myRijndael.IV = new byte[16]; //HexStringToByte(initialisationVector);
                myRijndael.Mode = CipherMode.CBC;
                myRijndael.Padding = PaddingMode.PKCS7;

                Byte[] ourEnc = Convert.FromBase64String(encryptedString);
                string ourDec = DecryptStringFromBytes(ourEnc, myRijndael.Key, myRijndael.IV);

                return ourDec;
            }
        }


        public static string EncryptText(string plainText)
        {
            using (myRijndael = new RijndaelManaged())
            {
                SHA256 sha256 = SHA256Managed.Create();
                byte[] bytes = Encoding.UTF8.GetBytes(pin);
                byte[] hash = sha256.ComputeHash(bytes);

                byte[] key = SubArray(hash, 0, 16);

                myRijndael.Key = key;
                myRijndael.IV = new byte[16]; //HexStringToByte(initialisationVector);
                myRijndael.Mode = CipherMode.CBC;
                myRijndael.Padding = PaddingMode.PKCS7;

                byte[] encrypted = EncryptStringToBytes(plainText, myRijndael.Key, myRijndael.IV);
                string encString = Convert.ToBase64String(encrypted);

                return encString;
            }
        }


        public static  byte[] EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments. 
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("Key");
            byte[] encrypted;
            // Create an RijndaelManaged object 
            // with the specified key and IV. 
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for encryption. 
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }


            // Return the encrypted bytes from the memory stream. 
            return encrypted;

        }

        public static string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments. 
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("Key");

            // Declare the string used to hold 
            // the decrypted text. 
            string plaintext = null;

            // Create an RijndaelManaged object 
            // with the specified key and IV. 
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                // Create the streams used for decryption. 
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
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

        /*public static void GenerateKeyAndIV()
        {
            // This code is only here for an example
            RijndaelManaged myRijndaelManaged = new RijndaelManaged();
            myRijndaelManaged.Mode = CipherMode.CBC;
            myRijndaelManaged.Padding = PaddingMode.PKCS7;

            myRijndaelManaged.GenerateIV();
            myRijndaelManaged.GenerateKey();
            string newKey = ByteArrayToHexString(myRijndaelManaged.Key);
            string newinitVector = ByteArrayToHexString(myRijndaelManaged.IV);
        }*/

        public static byte[] HexStringToByte(string hexString)
        {
            try
            {
                int bytesCount = (hexString.Length) / 2;
                byte[] bytes = new byte[bytesCount];
                for (int x = 0; x < bytesCount; ++x)
                {
                    bytes[x] = Convert.ToByte(hexString.Substring(x * 2, 2), 16);
                }
                return bytes;
            }
            catch
            {
                throw;
            }
        }

        public static string ByteArrayToHexString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public static T[] SubArray<T>(this T[] data, int index, int length)
        {
            T[] result = new T[length];
            Array.Copy(data, index, result, 0, length);
            return result;
        }
    }
}