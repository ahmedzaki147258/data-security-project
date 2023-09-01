using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        public string Decrypt(string cipherText, string key)
        {
            string alphapitics = "abcdefghijklmnopqrstuvwxyz";
            int[] char_checked = new int[26];
            cipherText = cipherText.ToLower();
            char[,] arr_key = new char[5, 5];

            string ret = "";

            for (int i = 0; i < 25; i++)
            {
                char_checked[i] = 0;
            }
                

            int row = 5, col = 5;
            for (int i = 0; i < row; i++)
            {
                for (int x = 0; x < col; x++)
                    arr_key[i, x] = '\0';

            }

            int found;
            int index_of_key = 0;
            int index_of_alphabitics = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    found = 0;
                    for (int k = index_of_key; k < key.Length; k++)
                    {

                        if (char_checked[((key[k] - 97) % alphapitics.Length)] == 0)
                        {
                            arr_key[i, j] = key[k];
                            char_checked[((key[k] - 97) % alphapitics.Length)] = 1;
                            found = 1;

                        }
                        if (found == 1)
                            break;
                    }

                    if (found == 0)
                    {
                        for (int k = index_of_alphabitics; k < alphapitics.Length; k++)
                        {


                            if (char_checked[((alphapitics[k] - 97) % alphapitics.Length)] == 0)
                            {
                                if (alphapitics[k] != 'j')
                                {

                                    arr_key[i, j] = (char)(k + 97);
                                    char_checked[((alphapitics[k] - 97) % alphapitics.Length)] = 1;
                                    index_of_alphabitics++;
                                    break;
                                }
                                if (alphapitics[k] == 'j')
                                    index_of_alphabitics++;

                            }
                        }
                    }


                    index_of_key++;
                }
            }

            for (int i = 0; i < cipherText.Length; i += 2)
            {

                char decrpyt_char1;
                char decrypt_char2;
                int[] positions = new int[4];

                for (int t = 0; t < 4; t++)
                {
                    positions[t] = 0;
                }
                for (int t = 0; t < 5; t++)
                {
                    for (int l = 0; l < 5; l++)
                    {
                        if (arr_key[t, l] == cipherText[i])
                        {
                            positions[0] = t; positions[1] = l;
                        }
                        if (arr_key[t, l] == cipherText[i + 1])
                        {
                            positions[2] = t; positions[3] = l;
                        }
                    }
                }
                if (positions[0] == positions[2])
                {
                    int col1 = (positions[1] - 1) % 5;
                    int col2 = (positions[3] - 1) % 5;
                    if (col1 < 0) col1 += 5;
                    if (col2 < 0) col2 += 5;
                    decrpyt_char1 = arr_key[positions[0], col1];
                    decrypt_char2 = arr_key[positions[2], col2];

                    //same row
                }
                else if (positions[1] == positions[3])
                {
                    int row1 = (positions[0] - 1) % 5;
                    int row2 = (positions[2] - 1) % 5;
                    if (row1 < 0) row1 += 5;
                    if (row2 < 0) row2 += 5;
                    decrpyt_char1 = arr_key[row1, positions[1]];
                    decrypt_char2 = arr_key[row2, positions[3]];
                    //same column
                }
                else
                {
                    decrpyt_char1 = arr_key[(positions[0]), (positions[3])];
                    decrypt_char2 = arr_key[(positions[2]), (positions[1])];
                    //diagonal
                }


                ret = ret + decrpyt_char1;
                ret = ret + decrypt_char2;

            }

            string val = ret.Substring(0, 1);
            for (int i = 1; i < ret.Length - 1; i++)
            {
                if (!(ret[i] == 'x' && ret[i - 1] == ret[i + 1] && i % 2 != 0))
                {
                    val += ret.Substring(i, 1);
                }
            }
            if (ret[ret.Length - 1] != 'x')
            {
                val += ret.Substring(ret.Length - 1, 1);
            }
            val = val.ToUpper();
            return val;

            //throw new NotImplementedException();

        }


        public string Encrypt(string plainText, string key)
        {
            string ciphertxt = "";
            plainText = plainText.ToUpper();
            char[,] mat = new char[5, 5];
            string miss_letters = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
            key = key.ToUpper();

            int loopcount = 0;
            while (loopcount < key.Length)
            {
                for (int j = 0; j < key.Length; j++)
                {

                    if (key[loopcount] == key[j] && loopcount != j)
                        key = key.Remove(j, 1);
                }
                loopcount++;

            }

            int row = 0, col = 0, counter = 0;
            int loopcount1 = 0;
            while (loopcount1 < 5)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (counter != key.Length)
                    {
                        mat[loopcount1, j] = key[counter];
                        counter++;
                        col = j;
                        row = loopcount1;

                    }

                }
                loopcount1++;


            }



            int loopcount2 = 0;
            while (loopcount2 < key.Length)
            {
                for (int j = 0; j < miss_letters.Length; j++)
                {
                    if (miss_letters[j] == key[loopcount2])
                    {
                        miss_letters = miss_letters.Remove(j, 1);

                    }
                    else
                        continue;

                }
                loopcount2++;
            }


            if (col == 4)
            {
                row++;
            }
            col = (col + 1) % 5;
            counter = 0;

            int loopcount3 = 0;
            while (loopcount3 < 5)
            {

                for (int j = 0; j < 5; j++)
                {
                    if (loopcount3 == row && j == col)
                    {

                        mat[loopcount3, j] = miss_letters[counter];
                        counter++;

                        if (j == 4 && loopcount3 == row)
                        {
                            col = 0;
                            row += 1;
                        }
                        if (j + 1 != 5)
                        {
                            col++;
                        }


                    }


                }
                loopcount3++;


            }

            int loopcount4 = 0;
            while (loopcount4 < plainText.Length && loopcount4 < plainText.Length && loopcount4 + 1 < plainText.Length)
            {
                if (plainText[loopcount4] == plainText[loopcount4 + 1])
                {
                    plainText = plainText.Insert(loopcount4 + 1, "X");
                }
                loopcount4 = loopcount4 + 2;
            }
            if (plainText.Length % 2 != 0)
            {
                plainText = plainText.Insert(plainText.Length, "X");
            }


            int possX1 = 0, possY1 = 0, possX2 = 0, possY2 = 0;
            char Letter1, Letter2;
            int loopcount5 = 0;
            while (loopcount5 < plainText.Length)
            {
                Letter1 = plainText[loopcount5];
                Letter2 = plainText[loopcount5 + 1];
                int loopcount6 = 0;
                while (loopcount6 < 5)
                {
                    for (int i = 0; i < 5; i++)
                    {
                        if (Letter1 == mat[loopcount6, i])
                        {
                            possX1 = loopcount6;
                            possY1 = i;
                        }

                        if (Letter2 == mat[loopcount6, i])
                        {
                            possX2 = loopcount6;
                            possY2 = i;
                        }
                    }

                    loopcount6++;
                }


                if (possX1 == possX2)
                {
                    possY1 = (possY1 + 1) % 5;
                    possY2 = (possY2 + 1) % 5;
                    ciphertxt = ciphertxt + mat[possX1, possY1];
                    ciphertxt = ciphertxt + mat[possX2, possY2];
                }
                else if (possY1 == possY2)
                {
                    possX1 = (possX1 + 1) % 5;
                    possX2 = (possX2 + 1) % 5;
                    ciphertxt = ciphertxt + mat[possX1, possY1];
                    ciphertxt = ciphertxt + mat[possX2, possY2];
                }
                else
                {
                    ciphertxt = ciphertxt + mat[possX1, possY2];
                    ciphertxt = ciphertxt + mat[possX2, possY1];
                }


                loopcount5 = loopcount5 + 2;
            }
            return ciphertxt.ToUpper();

        }
    }

}
    
