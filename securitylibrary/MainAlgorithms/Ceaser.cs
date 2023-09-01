using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        const string ALPHABET = "abcdefghijklmnopqrstuvwxyz";
        public string Encrypt(string plainText, int key)
        {
            plainText = plainText.ToLower();
            string ciphertxt = "";
            int count = 0;
            int plainLen = plainText.Length;

            while(count < plainLen)
            {
                int indx = ALPHABET.IndexOf(plainText[count]);
                int NewKeyValue = (key + indx) % 26;
                char NewAlphabetValue = ALPHABET[NewKeyValue];
                ciphertxt = ciphertxt + NewAlphabetValue;
                count++;
            }
            return ciphertxt;

            //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            String plaintxt = "";
            int count = 0;
            int cipherLen = cipherText.Length;
            int alphabetLen = ALPHABET.Length;

            while (count < cipherLen)
            {
                int indx = ALPHABET.IndexOf(cipherText[count]);
                int NewKeyValue = (indx - key) % 26;
                if (NewKeyValue < 0)
                {
                    NewKeyValue = alphabetLen + NewKeyValue;
                }
                char NewAlphabetValue = ALPHABET[NewKeyValue];
                plaintxt = plaintxt + NewAlphabetValue;
                count++;
            }
                
            return plaintxt;

            //throw new NotImplementedException();
        }

        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int ciphertxt = cipherText[0];
            int plaintxt = plainText[0];
            int size = (ciphertxt - plaintxt) % 26;
            while (true)
            {
                if (size < 0)
                {
                    size += 26;
                }

                if (size >= 0 && size <= 26) 
                    break; 
            }

            return size;
        }

        //throw new NotImplementedException();
    }
    
}
