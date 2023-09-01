using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            int x = 0;
            char[] chars = new char[cipherText.Length];
            char[] letters_small = new char[26];
            char[] letters_capital = new char[26];
            char[] key = new char[chars.Length];
            int counter = 0;
            int ind1 = 0, ind2 = 0;

            for (char i = 'a'; counter < letters_small.Length; i++)
            {
                letters_small[counter] = i;
                counter++;
            }
            counter = 0;

            for (char i = 'A'; counter < letters_capital.Length; i++)
            {
                letters_capital[counter] = i;
                counter++;
            }

            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < letters_capital.Length; j++)
                {
                    if (cipherText[i] == letters_capital[j])
                    {
                        ind1 = j;
                    }
                    if (plainText[i] == letters_small[j])
                    {
                        ind2 = j;
                    }
                }

                x = (ind1 - ind2);

                if (x < 0)
                {
                    chars[i] = letters_small[x + 26];
                }
                else
                {
                    chars[i] = letters_small[x % 26];
                }
            }

            int temp = 0;
            int max_char = 0;
            int no_of_occuerenceKey = 0;

            for (int i = 0; i < chars.Length; i++)
            {
                if (temp > max_char)
                {
                    max_char = temp;
                }
                temp = 0;

                for (int j = 0; j < chars.Length; j++)
                {
                    if (chars[i] == chars[j])
                    {
                        temp++;
                    }
                }
            }

            if (chars.Length % max_char == 0)
            {
                no_of_occuerenceKey = chars.Length / max_char;
                for (int i = 0; i < chars.Length / no_of_occuerenceKey; i++)
                {
                    key[i] = chars[i];
                }
            }

            else if (chars.Length % max_char != 0)
            {
                no_of_occuerenceKey = chars.Length / max_char + 1;
                for (int i = 0; i < chars.Length / no_of_occuerenceKey + 1; i++)
                {
                    key[i] = chars[i];
                }
            }

            string str = new string(key);
            return str;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            int x = 0;
            char[] chars = new char[cipherText.Length];
            char[] letters_small = new char[26];
            char[] letters_capital = new char[26];
            char[] plain = new char[cipherText.Length];
            int counter = 0;
            int ind1 = 0, ind2 = 0;

            for (char i = 'a'; counter < letters_small.Length; i++)
            {
                letters_small[counter] = i;
                counter++;
            }
            counter = 0;

            for (char i = 'A'; counter < letters_capital.Length; i++)
            {
                letters_capital[counter] = i;
                counter++;
            }

            if (key.Length.CompareTo(cipherText.Length) == 0)
            {
                for (int i = 0; i < chars.Length; i++)
                {
                    chars[i] = key[x];
                    x++;
                }

            }

            else if (key.Length.CompareTo(cipherText.Length) < 0)
            {
                for (int i = 0; i < chars.Length; i++)
                {
                    chars[i] = key[x];
                    x++;
                    if (x == key.Length)
                        x = 0;
                }

            }

            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < letters_capital.Length; j++)
                {
                    if (cipherText[i] == letters_capital[j])
                    {
                        ind1 = j;
                    }
                    if (chars[i] == letters_small[j])
                    {
                        ind2 = j;
                    }
                }

                x = (ind1 - ind2);

                if (x < 0)
                {
                    plain[i] = letters_small[x + 26];
                }
                else
                {
                    plain[i] = letters_small[x % 26];
                }
            }

            string str = new string(plain);
            return str;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            int x = 0;
            char[] chars = new char[plainText.Length];
            char[] letters = new char[26];
            char[] cypher = new char[plainText.Length];
            int counter = 0;

            int ind1 = 0, ind2 = 0;
            string str;

            for (char i = 'a'; counter < letters.Length; i++)
            {
                letters[counter] = i;
                counter++;
            }

            if (key.Length.CompareTo(plainText.Length) == 0)
            {
                for (int i = 0; i < chars.Length; i++)
                {
                    chars[i] = key[x];
                    x++;
                }

            }
            else if (key.Length.CompareTo(plainText.Length) < 0)
            {

                for (int i = 0; i < chars.Length; i++)
                {
                    chars[i] = key[x];
                    x++;
                    if (x == key.Length)
                        x = 0;
                }

            }

            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < letters.Length; j++)
                {
                    if (plainText[i] == letters[j])
                    {
                        ind1 = j;
                    }
                    if (chars[i] == letters[j])
                    {
                        ind2 = j;
                    }
                }
                cypher[i] = letters[(ind1 + ind2) % 26];

            }

            str = new string(cypher);
            return str.ToUpper();
        }
    }
}