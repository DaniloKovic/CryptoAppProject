using CryptoAppProject.Services;

namespace CryptoAppProject.Implementation
{
    public class RailFenceService : IRailFenceService
    {
        public string Encrypt(string text, string keyInput)
        {
            int key = Int32.Parse(keyInput);
            if (key < 1)
            {
                return text;
            }

            // Inicijalizacija niza koji će čuvati enkriptovani tekst
            char[] cipher = new char[text.Length];
            int index = 0;

            // Prolazak kroz svaku "šinu" RailFence algoritma
            for (int rail = 0; rail < key; rail++)
            {
                int step1 = (key - rail - 1) * 2;
                int step2 = rail * 2;

                int pos = rail;
                bool toggle = true;

                // Popunjavanje enkriptovanog teksta
                while (pos < text.Length)
                {
                    if (step1 != 0 && toggle)
                    {
                        cipher[index++] = text[pos];
                        pos += step1;
                    }
                    else if (step2 != 0)
                    {
                        cipher[index++] = text[pos];
                        pos += step2;
                    }
                    toggle = !toggle;
                }
            }

            return new string(cipher);
        }

        public string Decrypt(string text, string key)
        {
            throw new NotImplementedException();
        }
    }
}
