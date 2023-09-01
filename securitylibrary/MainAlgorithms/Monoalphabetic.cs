using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string ciphertxt = cipherText.ToLower();
            string plaintxt = plainText.ToLower();
            int cipherLen = ciphertxt.Length;
            var key = new char[26];
            int plainLen = plaintxt.Length;
            int keyLen = key.Length;
            var plaintxtarr = new dynamic[26];
            var usedvalues = new dynamic[26];

            var charcter = 'a';
            int indx = 0;
            while (charcter <= 'z')
            {
                plaintxtarr[indx] = charcter;
                indx++;
                charcter++;
            }

            int count = 0, count1;
            while (count < plainLen)
            {
                for (count1 = 0; count1 < 26; count1++) //mesh httghyr
                {
                    if (String.Equals(plaintxt[count], plaintxtarr[count1]))
                    {
                        key[count1] = ciphertxt[count];

                    }

                }
                count++;
            }

            int count2 = 0, count3;
            while (count2 < cipherLen)
            {
                for (count3 = 0; count3 < 26; count3++) //mesh httghyr
                {
                    if (String.Equals(ciphertxt[count2], plaintxtarr[count3]))
                    {

                        usedvalues[count3] = 't';
                    }
                }
                count2++;
            }

            int count4 = 0, count5 = 0;
            while (count4 < 26)
            {
                if (key[count4] == '\0')
                {
                    while (count5 < 26)
                    {
                        if (usedvalues[count5] != 't')
                        {
                            key[count4] = plaintxtarr[count5];
                            usedvalues[count5] = 't';
                            break;
                        }
                        count5++;
                    }
                }
                count4++;
            }

            string res = "";
            int count6 = 0;
            while (count6 < keyLen)
            {
                res = res + key[count6];
                count6++;
            }
            return res;
            //throw new NotImplementedException();
        }


        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            int cipherLen = cipherText.Length;
            char[] plaintxt = new char[cipherLen];
            int count = 0;

            while (count < cipherLen)
            {
                if (char.IsLetter(cipherText[count]) == false)
                {
                    plaintxt[count] = cipherText[count];
                }
                else
                {
                    int NewKeyValue = key.IndexOf(cipherText[count]) + 97;
                    plaintxt[count] = (char)NewKeyValue;
                }
                count++;
            }
            return new string(plaintxt);

            //throw new NotImplementedException();
        }

        public string Encrypt(string plainText, string key)
        {
            int plainLen = plainText.Length;
            char[] ciphertxt = new char[plainLen];
            int count = 0;

            while (count < plainLen)
            {
                if (plainText[count] == ' ')
                {
                    ciphertxt[count] = ' ';
                }
                else
                {
                    int NewKeyValue = plainText[count] - 97;
                    ciphertxt[count] = key[NewKeyValue];
                }
                count++;
            }
            return new string(ciphertxt);

            //throw new NotImplementedException();
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            string ALPHABETMostFrequent = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower();
            string alphabetFreq = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower();
            cipher = cipher.ToLower();
            int cipherLen = cipher.Length;
            string distinct = new String(cipher.Distinct().ToArray());
            int distinctLen = distinct.Length;
            int[] CAlphaFreq = new int[distinctLen];
            List<KeyValuePair<char, int>> alpha = new List<KeyValuePair<char, int>>();

            for (int i = 0; i < cipherLen; i++)
            {
                for (int j = 0; j < distinctLen; j++)
                {
                    if (String.Equals(cipher[i], distinct[j]))
                        CAlphaFreq[j]++;

                }
            }
            for (int counter = 0; counter < distinctLen; counter++)
                alpha.Add(new KeyValuePair<char, int>(distinct[counter], CAlphaFreq[counter]));

            alpha = alpha.OrderBy(x => x.Value).ToList();
            string key = "";
            int pos;
            for (int i = 0; i < cipherLen; i++)
            {
                pos = alpha.FindIndex(x => x.Key == cipher[i]);
                key += alphabetFreq[25 - pos];

            }
            return key;
            //throw new NotImplementedException();

        }

    }
}
