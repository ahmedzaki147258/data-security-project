using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            //throw new NotImplementedException();
            long ya = power(alpha, xa, q);
            long yb = power(alpha, xb, q);
            List<int> list = new List<int>();
            list.Add((int)power(yb, xa, q));
            list.Add((int)power(ya, xb, q));
            return list;
        }
        public long power(long alpha, long n, long mod)
        {
            long result = 1;
            alpha %= mod;
            do
            {
                result = (result * alpha) % mod;
                n--;
            } while (n > 0);
            return result;
        }
    }
}
