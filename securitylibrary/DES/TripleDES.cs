using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        int[,] Pc1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 }, { 1, 58, 50, 42, 34, 26, 18 }, { 10, 2, 59, 51, 43, 35, 27 }, { 19, 11, 3, 60, 52, 44, 36 }, { 63, 55, 47, 39, 31, 23, 15 }, { 7, 62, 54, 46, 38, 30, 22 }, { 14, 6, 61, 53, 45, 37, 29 }, { 21, 13, 5, 28, 20, 12, 4 } };
        int[,] Pc2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 }, { 3, 28, 15, 6, 21, 10 }, { 23, 19, 12, 4, 26, 8 }, { 16, 7, 27, 20, 13, 2 }, { 41, 52, 31, 37, 47, 55 }, { 30, 40, 51, 45, 33, 48 }, { 44, 49, 39, 56, 34, 53 }, { 46, 42, 50, 36, 29, 32 } };
        int[,] s1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
        int[,] s2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
        int[,] s3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
        int[,] s4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
        int[,] s5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
        int[,] s6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
        int[,] s7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
        int[,] s8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };
        int[,] P = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 }, { 1, 15, 23, 26 }, { 5, 18, 31, 10 }, { 2, 8, 24, 14 }, { 32, 27, 3, 9 }, { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };
        int[,] EB = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };
        int[,] IP1 = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 }, { 60, 52, 44, 36, 28, 20, 12, 4 }, { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8 }, { 57, 49, 41, 33, 25, 17, 9, 1 }, { 59, 51, 43, 35, 27, 19, 11, 3 }, { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 } };
        int[,] IP2 = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };
        
        //total variables
        string temp2 = "", temp1, c, d, left, right, bit, xork, t, tsb, pp, lf, ciphertext = "", Ip = "";
        List<string> Sbox = new List<string>(), keys1 = new List<string>(), keys2 = new List<string>(), Left = new List<string>(), Right = new List<string>(), C = new List<string>(), D = new List<string>();
        int row, col, sb = 0;

        public string Encrypt(string plainText, List<string> key)
        {
            string plain_text = Convert.ToString(Convert.ToInt64(plainText, 16), 2).PadLeft(64, '0'), plain_key = Convert.ToString(Convert.ToInt64(key[0], 16), 2).PadLeft(64, '0');
            //premutate key by pc-1
            for (int i = 0; i < 8; i++)
                for (int j = 0; j < 7; j++)
                    temp2 +=plain_key[Pc1[i, j] - 1];

            //C and D
            c = temp2.Substring(0, 28);
            d = temp2.Substring(28, 28);
            for (int i = 0; i < 17; i++)
            {
                C.Add(c);
                D.Add(d);
                temp1 = "";
                if (i == 0 || i == 1 || i == 8 || i == 15)
                {
                    temp1 +=c[0];
                    c = c.Remove(0, 1);
                    c +=temp1;
                    temp1 = "";
                    temp1 +=d[0];
                    d = d.Remove(0, 1);
                    d +=temp1;
                }
                else
                {
                    temp1 +=c.Substring(0, 2);
                    c = c.Remove(0, 2);
                    c +=temp1;
                    temp1 = "";
                    temp1 +=d.Substring(0, 2);
                    d = d.Remove(0, 2);
                    d +=temp1;
                }
            }
            for (int i = 0; i < D.Count; i++)
                keys1.Add(C[i] + D[i]);

            //k1 --> k16 by pc-2
            for (int k = 1; k < keys1.Count; k++)
            {
                temp2 = "";
                temp1 = keys1[k];
                for (int i = 0; i < 8; i++)
                    for (int j = 0; j < 6; j++)
                        temp2 +=temp1[Pc2[i, j] - 1];
                keys2.Add(temp2);
            }

            //premutation by IP for plain text
            for (int i = 0; i < 8; i++)
                for (int j = 0; j < 8; j++)
                    Ip += plain_text[IP1[i, j] - 1];
                            
            left = Ip.Substring(0, 32);
            right = Ip.Substring(32, 32);
            Left.Add(left);
            Right.Add(right);
            for (int i = 0; i < 16; i++)
            {
                Left.Add(right);
                xork = "";
                bit = "";
                lf = "";
                pp = "";
                Sbox.Clear();
                tsb = "";
                for (int j = 0; j < 8; j++)
                    for (int k = 0; k < 6; k++)
                        bit +=right[EB[j, k] - 1];

                for (int j = 0; j < bit.Length; j++)
                    xork +=(keys2[i][j] ^ bit[j]).ToString();

                for (int j = 0; j < xork.Length; j += 6)
                {
                    t = "";
                    for (int k = j; k < 6 + j; k++)
                        if (5 + j < xork.Length)
                            t += xork[k];
                    Sbox.Add(t);
                }
                
                for (int j = 0; j < Sbox.Count; j++)
                {
                    t = Sbox[j];
                    row = Convert.ToInt32(t[0].ToString() + t[5], 2);
                    col = Convert.ToInt32(t[1].ToString() + t[2] + t[3] + t[4], 2);
                    switch (j)
                    {
                        case 0:
                            sb = s1[row, col];
                            break;
                        case 1:
                            sb = s2[row, col];
                            break;
                        case 2:
                            sb = s3[row, col];
                            break;
                        case 3:
                            sb = s4[row, col];
                            break;
                        case 4:
                            sb = s5[row, col];
                            break;
                        case 5:
                            sb = s6[row, col];
                            break;
                        case 6:
                            sb = s7[row, col];
                            break;
                        case 7:
                            sb = s8[row, col];
                            break;
                    }
                    tsb +=Convert.ToString(sb, 2).PadLeft(4, '0');
                }
                for (int j = 0; j < 8; j++)
                    for (int k = 0; k < 4; k++)
                        pp +=tsb[P[j, k] - 1];
                   
                for (int j = 0; j < pp.Length; j++)
                    lf +=(pp[j] ^ left[j]).ToString();

                right = lf;
                left = Left[i + 1];
                Right.Add(right);
            }
            for (int i = 0; i < 8; i++)
                for (int j = 0; j < 8; j++)
                    ciphertext +=(Right[16] + Left[16])[IP2[i, j] - 1];
            return "0x" +Convert.ToInt64(ciphertext, 2).ToString("X");
        }

        public string Decrypt(string cipherText, List<string> key)
        {
            //throw new NotImplementedException();
            string cipher_text = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0'), cipher_key = Convert.ToString(Convert.ToInt64(key[0], 16), 2).PadLeft(64, '0');

            //premutate key by pc-1
            for (int i = 0; i < 8; i++)
                for (int j = 0; j < 7; j++)
                    temp2 += cipher_key[Pc1[i, j] - 1];

            //C and D
            c = temp2.Substring(0, 28);
            d = temp2.Substring(28, 28);
            for (int i = 0; i <= 16; i++)
            {
                C.Add(c);
                D.Add(d);
                temp1 = "";
                if (i == 0 || i == 1 || i == 8 || i == 15)
                {
                    c += c[0];
                    c = c.Remove(0, 1);
                    d += d[0];
                    d = d.Remove(0, 1);
                }
                else
                {
                    temp1 += c.Substring(0, 2);
                    c = c.Remove(0, 2);
                    c += temp1;
                    d += d.Substring(0, 2);
                    d = d.Remove(0, 2);
                }
            }
            for (int i = 0; i < D.Count; i++)
                keys1.Add(C[i] + D[i]);

            //k1 --> k16 by pc-2
            for (int i = 1; i < keys1.Count; i++)
            {
                temp2 = "";
                temp1 = keys1[i];
                for (int j = 0; j < 8; j++)
                    for (int k = 0; k < 6; k++)
                        temp2 +=temp1[Pc2[j, k] - 1];
                keys2.Add(temp2);
            }

            //premutation by IP for cipher text
            for (int i = 0; i < 8; i++)
                for (int j = 0; j < 8; j++)
                    Ip +=cipher_text[IP1[i, j] - 1];

            left = Ip.Substring(0, 32);
            right = Ip.Substring(32, 32);
            Left.Add(left);
            Right.Add(right);
            for (int i = 0; i < 16; i++)
            {
                Left.Add(right);
                xork = "";
                bit = "";
                lf = "";
                pp = "";
                Sbox.Clear();
                tsb = "";
                col = 0;
                row = 0;
                t = "";
                for (int j = 0; j < 8; j++)
                    for (int k = 0; k < 6; k++)
                        bit +=right[EB[j, k] - 1];

                for (int j = 0; j < bit.Length; j++)
                    xork +=(keys2[keys2.Count - 1 - i][j] ^ bit[j]).ToString();

                for (int j = 0; j < xork.Length; j = j + 6)
                {
                    t = "";
                    for (int k = j; k < 6 + j; k++)
                        if (6 + j <= xork.Length)
                            t +=xork[k];
                    Sbox.Add(t);
                }

                t = "";
                for (int j = 0; j < Sbox.Count; j++)
                {
                    t = Sbox[j];
                    row = Convert.ToInt32(t[0].ToString() + t[5], 2);
                    col = Convert.ToInt32(t[1].ToString() + t[2] + t[3] + t[4], 2);
                    switch (j)
                    {
                        case 0:
                            sb = s1[row, col];
                            break;
                        case 1:
                            sb = s2[row, col];
                            break;
                        case 2:
                            sb = s3[row, col];
                            break;
                        case 3:
                            sb = s4[row, col];
                            break;
                        case 4:
                            sb = s5[row, col];
                            break;
                        case 5:
                            sb = s6[row, col];
                            break;
                        case 6:
                            sb = s7[row, col];
                            break;
                        case 7:
                            sb = s8[row, col];
                            break;
                    }
                    tsb +=Convert.ToString(sb, 2).PadLeft(4, '0');
                }
                for (int k = 0; k < 8; k++)
                    for (int j = 0; j < 4; j++)
                        pp += tsb[P[k, j] - 1];

                for (int k = 0; k < pp.Length; k++)
                    lf +=(pp[k] ^ left[k]).ToString();

                right = lf;
                left = Left[i + 1];
                Right.Add(right);
            }
            for (int i = 0; i < 8; i++)
                for (int j = 0; j < 8; j++)
                    ciphertext +=(Right[16] + Left[16])[IP2[i, j] - 1];
            return "0x" + Convert.ToInt64(ciphertext, 2).ToString("X").PadLeft(16, '0');
        }

        public List<string> Analyse(string plainText,string cipherText)
        {
            throw new NotSupportedException();
        }
    }
}
