using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            int plainLeng = plainText.Length;
            int column = 0;
            plainText = plainText.ToLower();
            for (int i = 4; i <= 7; i++)
            {
                int mod = plainLeng % i;
                if (mod == 0)
                {
                    column = i;
                }
            }
            double row = plainLeng / column;
            char[,] matrix1 = new char[(int)row, column];
            char[,] matrix2 = new char[(int)row, column];
            int count = 0;
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < column; j++)
                {
                    if (count < plainLeng)
                    {
                        matrix1[i, j] = plainText[count];
                    }
                    if (count >= plainLeng)
                    {
                        if (matrix1.Length > plainLeng)
                        {
                            continue;

                            matrix1[i, j] = 'x';
                        }
                    }
                    count++;
                }
            }
            count = 0;
            bool countb = true;
            for (int i = 0; i < column; i++)
            {
                int j = 0;
                while (j < row)
                {
                    if (count != plainLeng)
                    {
                        matrix2[j, i] = cipherText[count];
                        if (countb)
                        {
                            count++;
                        }
                    }
                    j++;
                }
            }
            int check;
            check = 0;
            bool checkb = true;
            List<int> key = new List<int>(column);
            for (int i = 0; i < column; i++)
            {
                int j = 0;
                while (j < column)
                {
                    int k = 0;
                    for (; k < row; k++)
                    {
                        bool mat = matrix1[k, i] == matrix2[k, j];
                        if (mat)
                        {
                            if (checkb == true)
                            {
                                check++;
                            }
                            else
                            {
                                check--;
                            }
                        }
                        if (check != row)
                        {
                            continue;
                        }
                        else
                        {
                            key.Add(j + 1);
                        }
                    }
                    check = 0;
                    j++;
                }
            }
            while (key.Count == 0)
            {
                int i = 0;
                while (i < column + 2)
                {
                    key.Add(0);
                    i++;
                }

            }
            return key;
        }

        public string Decrypt(string cipherText, List<int> key)
        {

            int cipherLen = cipherText.Length;
            int column = cipherLen / key.Count;
            string plaintext = "";
            int KEY, Temp = 0;
            char[,] matrix = new char[column, key.Count];
            cipherText = cipherText.ToLower();
            for (int i = 0; i < key.Count; i++)
            {
                KEY = key.IndexOf(i + 1);
                for (int j = 0; j < column; j++)
                {
                    if (Temp < cipherLen)
                    {
                        matrix[j, KEY] = cipherText[Temp];
                        Temp++;
                    }
                }
            }
            for (int i = 0; i < column; i++)
            {
                for (int j = 0; j < key.Count; j++)
                {
                    plaintext += matrix[i, j];
                }
            }
            return plaintext;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            int plainTLeng = plainText.Length;
            double column = key.Count;
            double row = plainTLeng / column;
            double x = plainTLeng / column;
            string cipher = "";
            row = Math.Ceiling(x);
            char[,] matrix = new char[(int)row, (int)column];
            int check = 0;
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < column; j++)
                {
                    if (check < plainTLeng)
                    {

                        matrix[i, j] = plainText[check];
                        check++;
                    }
                    else
                    {
                        matrix[i, j] = 'x';
                    }
                }
            }
            for (int i = 1; i <= column; i++)
            {
                int index = key.IndexOf(i);
                for (int j = 0; j < row; j++)
                {
                    if (matrix[j, index] != ' ')
                    {
                        cipher += matrix[j, index];
                    }
                }
            }
            return cipher;
        }
    }
}