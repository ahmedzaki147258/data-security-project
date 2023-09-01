using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DenseMatrix = MathNet.Numerics.LinearAlgebra.Double.DenseMatrix;
using MathNet.Numerics.LinearAlgebra;


namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            //throw new NotImplementedException();
            List<int> possible_Key, temp_list;
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    for (int k = 0; k < 26; k++)
                    {
                        for (int u = 0; u < 26; u++)
                        {
                            possible_Key = new List<int>(new[] { i, j, k, u });
                            temp_list = Encrypt(plainText, possible_Key);
                            if (!temp_list.SequenceEqual(cipherText))
                                continue;
                            else
                                return possible_Key;
                        }
                    }
                }
            }
            throw new InvalidAnlysisException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();

        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            //throw new NotImplementedException();
            List<double> keyD = new List<double>();
            List<double> Ct = new List<double>();
            List<double> Res = new List<double>();
            List<int> finalRes = new List<int>();
            for (int i = 0; i < cipherText.Count; i++)
                Ct.Add(Convert.ToDouble(cipherText[i]));
            for (int i = 0; i < key.Count; i++)
                keyD.Add(Convert.ToDouble(key[i]));
            int num_of_rows = Convert.ToInt32(Math.Sqrt((key.Count)));
            int num_of_cols_for_key = (int)key.Count / num_of_rows;
            int num_of_cols_for_pt = (int)cipherText.Count / num_of_rows;
            Matrix<double> keyMatrix = DenseMatrix.OfColumnMajor(num_of_rows, num_of_cols_for_key, keyD.AsEnumerable());
            Matrix<double> PMatrix = DenseMatrix.OfColumnMajor(num_of_rows, num_of_cols_for_pt, Ct.AsEnumerable());
            Matrix<double> TMatrix = keyMatrix.Transpose();

            if (keyMatrix.ColumnCount != 3)
                keyMatrix = keyMatrix.Inverse();
            else
            {
                double det = TMatrix.Determinant();
                int a = (int)det % 26 + 26;
                int b = -1;
                for (int i = 0; i < 26; i++)
                    if (a * i % 26 == 1)
                        b = i;

                for (int i = 0; i < 3; i++)
                {
                    for (int j = 0; j < 3; j++)
                    {
                        int x = 0, y = 0, x1 = 2, y1 = 2;
                        if (i == 0) x = 1; if (i == 2) x1 = 1;
                        if (j == 0) y = 1; if (j == 2) y1 = 1;
                        double r = ((TMatrix[x, y] * TMatrix[x1, y1] - TMatrix[x, y1] * TMatrix[x1, y]) * b * Math.Pow(-1, i + j)) % 26;
                        keyMatrix[i, j] = r % 26;
                    }
                }
            }
            if (Math.Abs((int)keyMatrix[0, 0]).ToString() != Math.Abs((double)keyMatrix[0, 0]).ToString())
                throw new SystemException();
            int iter = 0;
            while (iter < PMatrix.ColumnCount)
            {
                Res = ((((PMatrix.Column(iter)).ToRowMatrix() * keyMatrix) % 26).Enumerate().ToList());
                iter += 1;
                for (int j = 0; j < Res.Count; j++)
                    finalRes.Add(((int)Res[j] + 26) % 26);
            }
            return finalRes;
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            //throw new NotImplementedException();
            int cnt_plntxt = plainText.Count;
            int cnt_key = key.Count;
            List<int> cipher = new List<int>(cnt_plntxt);
            int k = 0;
            while (k < cnt_plntxt)
            {
                cipher.Add(0);                  //add zeros digits similer plainText lenght
                k += 1;
            }
            int rowORcol = (int)Math.Sqrt(cnt_key);            //To know the matrix kam * kam
            int index = 0, i = 0;
            while (i < cnt_plntxt)
            {
                int cnt = 0, val = 0, j = 0;
                do
                {
                    if (cnt == rowORcol)
                    {
                        while (val < 0 || val > 25)
                        {
                            if (val > 25)
                                val -= 26;
                            else if (val < 0)
                                val += 26;
                            else
                                break;
                        }                               //  Alphabet between 0,25 only

                        cipher[index] = val;
                        cnt = 0;
                        val = 0;
                        index += 1;
                        if (j == cnt_key)
                            break;
                    }
                    val += (plainText[i + cnt] * key[j]);       //Multiply each row in the key column
                    cnt += 1;
                    j -= -1;
                } while (j <= cnt_key);
                i += rowORcol;
            }
            return cipher;
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            //throw new NotImplementedException();
            List<double> PlainText = new List<double>();
            List<double> CipherText = new List<double>();
            for (int i = 0; i < cipher3.Count; i++)
            {
                CipherText.Add(Convert.ToDouble(cipher3[i]));
                PlainText.Add(Convert.ToDouble(plain3[i]));
            }

            int num_of_rows = Convert.ToInt32(Math.Sqrt(CipherText.Count));
            Matrix<double> CMatrix = DenseMatrix.OfColumnMajor(num_of_rows, (int)cipher3.Count / num_of_rows, CipherText.AsEnumerable());
            Matrix<double> PMatrix = DenseMatrix.OfColumnMajor(num_of_rows, (int)plain3.Count / num_of_rows, PlainText.AsEnumerable());
            Matrix<double> RMatrix = PMatrix.Transpose();

            double det = PMatrix.Determinant();
            int a = (int)det % 26, b = -1;
            for (int j = 0; j < 26; j++)
                if (a * j % 26 == 1)
                    b = j;

            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    int x = 0, y = 0, x1 = 2, y1 = 2;
                    if (i == 0) x = 1; if (i == 2) x1 = 1;
                    if (j == 0) y = 1; if (j == 2) y1 = 1;
                    double r = ((RMatrix[x, y] * RMatrix[x1, y1] - RMatrix[x, y1] * RMatrix[x1, y]) * b * Math.Pow(-1, i + j)) % 26;
                    PMatrix[i, j] = (r + 26) % 26;
                }
            }
            return (CMatrix * PMatrix).Transpose().Enumerate().Select(i => (int)i % 26).ToList();
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
            
        }
    }
}
