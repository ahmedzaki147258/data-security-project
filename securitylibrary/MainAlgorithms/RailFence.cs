using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int key = 0;

            for(int i = 0; i < plainText.Length; i++)
            {
                {
                    if (cipherText.ToLower() == Encrypt(plainText, key))
                        break;
                    key++;
                }
            }
            return key;
            //throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, int key)
        {
            string plaintxt = "";
            int newkey = (int)Math.Ceiling(cipherText.Length / (float)key);
            
            for (int i = 0; i < newkey; i++)
            {
                for (int j = i; j < cipherText.Length; j = j + newkey)
                    plaintxt = plaintxt + cipherText[j];

            }
            return plaintxt;
            
            //  throw new NotImplementedException();
        }

        public string Encrypt(string plainText, int key)
        {
            plainText = plainText.Replace(" ", "");
            string ciphertxt = "";
            int row = key;
            int col = plainText.Length;
            char[,] charcterarr = new char[row, col];
            int plaintxtCount = 0;

            int j;
            for (int i = 0; i < col; i++)
            {
                for (j = 0; j < row; j++)
                {
                    if (plaintxtCount != col)
                    {
                        charcterarr[j, i] = plainText[plaintxtCount++];
                    }


                }
            }

            for (int i = 0; i < row; i++)
            {
                for (j = 0; j < col; j++)
                {
                    if (charcterarr[i, j] != '\0')
                    {
                        ciphertxt = ciphertxt + charcterarr[i, j];
                    }
                }
            }
            return ciphertxt;
           // throw new NotImplementedException();
        }
    }
}
