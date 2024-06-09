using CryptoAppProject.Services;

namespace CryptoAppProject.Implementation
{
    public class PlayfairService : IPlayfairService
    {
        private const string alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"; // 'J' is omitted
        public string Encrypt(string plainText, string key)
        {
            try
            {
                char[,] matrix = new char[5, 5];
                Dictionary<char, (int row, int col)> charPositions = new Dictionary<char, (int row, int col)>();
                GenerateMatrix(key.ToUpper(), matrix, charPositions);

                plainText = PrepareText(plainText.ToUpper());

                string ciphertext = "";

                for (int i = 0; i < plainText.Length; i += 2)
                {
                    char a = plainText[i];
                    char b = plainText[i + 1];
                    (int rowA, int colA) = charPositions[a];
                    (int rowB, int colB) = charPositions[b];

                    if (rowA == rowB)
                    {
                        ciphertext += matrix[rowA, (colA + 1) % 5];
                        ciphertext += matrix[rowB, (colB + 1) % 5];
                    }
                    else if (colA == colB)
                    {
                        ciphertext += matrix[(rowA + 1) % 5, colA];
                        ciphertext += matrix[(rowB + 1) % 5, colB];
                    }
                    else
                    {
                        ciphertext += matrix[rowA, colB];
                        ciphertext += matrix[rowB, colA];
                    }
                }
                string s = ciphertext;
                return ciphertext;
            }
            catch (Exception ex) 
            { 
                string str = ex.Message;
                return str;
            }
        }

        private void GenerateMatrix(string key, char[,] matrix, Dictionary<char, (int row, int col)> charPositions)
        {
            HashSet<char> used = new HashSet<char>();
            int row = 0, col = 0;

            foreach (char c in key)
            {
                if (!used.Contains(c) && alphabet.Contains(c))
                {
                    matrix[row, col] = c;
                    charPositions[c] = (row, col);
                    used.Add(c);
                    if (++col == 5)
                    {
                        col = 0;
                        row++;
                    }
                }
            }

            foreach (char c in alphabet)
            {
                if (!used.Contains(c))
                {
                    matrix[row, col] = c;
                    charPositions[c] = (row, col);
                    used.Add(c);
                    if (++col == 5)
                    {
                        col = 0;
                        row++;
                    }
                }
            }
        }

        private string PrepareText(string text)
        {
            text = text.Replace("J", "I");
            string result = "";
            for (int i = 0; i < text.Length; i += 2)
            {
                if (i + 1 >= text.Length || text[i] == text[i + 1])
                {
                    result += text[i];
                    result += 'X';
                    i--;
                }
                else
                {
                    result += text[i];
                    result += text[i + 1];
                }
            }
            return result;
        }

        public string Decrypt(string text, string key)
        {
            throw new NotImplementedException();
        }
    }
}
