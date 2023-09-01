using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            //throw new NotImplementedException();
            int n;
            long c = 0;
            long result = 1;
            n = p * q;
            int i = 0;
            while (i < e / 2)
            {
                c = (long)((M * M) % n);
                result = result * c;
                result = result % (long)n;
                i++;
            }
            if (e % 2 == 1)
            {
                c = (long)(M % n);
                result = result * c;
                result = result % (long)n;
            }
            result = result % (long)n;
            return (int)result;
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            //throw new NotImplementedException();
            int n;
            int totient;
            long cc = 0;
            int d;
            long result = 1;
            n = p * q;
            totient = (p - 1) * (q - 1);
            d = ExtentedEcludien(e, totient);
            int i = 0;
            while (i < d / 2)
            {
                cc = (long)((C * C) % n);
                result = result * cc;
                result = result % (long)n;
                i++;
            }
            if (d % 2 == 1)
            {
                cc = (long)(C % n);
                result = result * cc;
                result = result % (long)n;
            }
            result = result % (long)n;
            return (int)result;
        }
        public int ExtentedEcludien(int b, int m)
        {
            int A1 = 1;
            int A2 = 0;
            int A3 = m;
            int B1 = 0;
            int B2 = 1;
            int B3 = b;
            int a1, a2, a3;
            int Q;
            while (true)
            {
                if (B3 == 0)
                {
                    return -1;
                }
                else if (B3 == 1)
                {
                    if (B2 < 0)
                    {
                        B2 = B2 + m;
                    }
                    return B2;
                }
                Q = A3 / B3;
                a1 = A1 - Q * B1;
                a2 = A2 - Q * B2;
                a3 = A3 - Q * B3;
                A1 = B1;
                A2 = B2;
                A3 = B3;
                B1 = a1;
                B2 = a2;
                B3 = a3;
            }
            return 0;

        }
    }
}
