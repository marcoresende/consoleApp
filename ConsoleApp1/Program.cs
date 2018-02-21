using CypherExample;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("********************Encryption Example******************");
            
            string inputText = "{\"authorization\":\"Basic aG9tb2xvZ2FjYW86ZW1wcmVzYTE=\",\"authToken\":\"aG9tb2xvZ2FjYW8gZW1wcmVzYTEgc3RnNURT\"}";
            Console.WriteLine("CREDENCIAIS: {0}", inputText + "\n\n\n");
            string encryptedText = MyCryptoClass.EncryptText(inputText);
            Console.WriteLine("CRYPT: {0}", encryptedText + "\n\n\n");

            Console.WriteLine();
            Console.WriteLine();

            Console.WriteLine("********************Decryption Example******************");
            Console.WriteLine("RAW: {0}", encryptedText + "\n\n\n");
            string decryptedText = MyCryptoClass.DecryptText(encryptedText);
            Console.WriteLine("DECRYPT: {0}", decryptedText + "\n\n\n");




            Console.ReadLine();
        }
    }
}
