using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            // throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            string ALPHABET = "abcdefghijklmnopqrstuvwxyz";
            string txt = "";
            string key = "";

            int count = 0;
            while (count < cipherText.Length)
            {
                int indx = ((ALPHABET.IndexOf(cipherText[count]) - ALPHABET.IndexOf(plainText[count])) + 26) % 26;
                key = key + ALPHABET[indx];
                count++;
            }

            txt = txt + key[0];
            for (int count1 = 1; count1 < key.Length; count1++)
            {
                if (cipherText == Encrypt(plainText, txt))
                {
                    return txt;
                }
                txt = txt + key[count1];
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            string ALPHABET = "abcdefghijklmnopqrstuvwxyz";
            string plainTxt = "";

            int count = 0;
            while (count < cipherText.Length )
            {
                int indx = ((ALPHABET.IndexOf(cipherText[count]) - ALPHABET.IndexOf(key[count])) + 26) % 26;
                plainTxt += ALPHABET[indx];
                key += plainTxt[count];
                count++;
            }

            return plainTxt;
        }

        public string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            string ALPHABET = "abcdefghijklmnopqrstuvwxyz";
            string cipherTxt = "";

            int count = 0;            
            while (plainText.Length != key.Length)
            {
                key += plainText[count];
                count++;
            }

            int count1 = 0;
            while (count1 < plainText.Length)
            {
               int indx = (ALPHABET.IndexOf(plainText[count1]) + ALPHABET.IndexOf(key[count1])) % 26;
               cipherTxt = cipherTxt + ALPHABET[indx];
               count1++;
            }

            return cipherTxt;
        }
    }
}
