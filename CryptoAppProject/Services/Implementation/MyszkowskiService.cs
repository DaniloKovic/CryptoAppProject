using CryptoAppProject.Services;

namespace CryptoAppProject.Implementation
{
    public class MyszkowskiService : IMyszkowskiService
    {
        public string Encrypt(string text, string key)
        {
            // Generate numeric key order
            List<int> keyOrder = GetKeyOrder(key);

            // Create the matrix
            int numCols = key.Length;
            int numRows = (int)Math.Ceiling((double)text.Length / numCols);
            char[,] matrix = new char[numRows, numCols];

            int k = 0;
            for (int i = 0; i < numRows; i++)
            {
                for (int j = 0; j < numCols; j++)
                {
                    if (k < text.Length)
                    {
                        matrix[i, j] = text[k++];
                    }
                    else
                    {
                        matrix[i, j] = 'X'; // Fill with placeholder if needed
                    }
                }
            }

            // Read the matrix columns in key order
            string cipherText = "";
            for (int i = 1; i <= keyOrder.Max(); i++)
            {
                for (int j = 0; j < keyOrder.Count; j++)
                {
                    if (keyOrder[j] == i)
                    {
                        for (int r = 0; r < numRows; r++)
                        {
                            if (matrix[r, j] != 'X')
                            {
                                cipherText += matrix[r, j];
                            }
                        }
                    }
                }
            }
            return cipherText;
        }

        private List<int> GetKeyOrder(string key)
        {
            List<int> keyOrder = new List<int>(new int[key.Length]);
            Dictionary<char, int> keyRank = new Dictionary<char, int>();

            char[] sortedKey = key.ToCharArray();
            Array.Sort(sortedKey);

            int rank = 1;
            foreach (char c in sortedKey)
            {
                if (!keyRank.ContainsKey(c))
                {
                    keyRank[c] = rank++;
                }
            }

            for (int i = 0; i < key.Length; i++)
            {
                keyOrder[i] = keyRank[key[i]];
            }

            return keyOrder;
        }

        public string Decrypt(string text, string key)
        {
            throw new NotImplementedException();
        }
    }
}
