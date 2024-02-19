using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace CryptoAppWPFProject
{
    /// <summary>
    /// Interaction logic for AlgorithmOptions.xaml
    /// </summary>
    public partial class AlgorithmOptions : Window
    {
        public AlgorithmOptions()
        {
            InitializeComponent();
        }

        private void btnRailFence_Click(object sender, RoutedEventArgs e)
        {
             ValidateInputText(tbInputTextToCrypt.Text);
        }

        private void btnMyszkowski_Click(object sender, RoutedEventArgs e)
        {
             ValidateInputText(tbInputTextToCrypt.Text);
        }

        private void btnPlayfair_Click(object sender, RoutedEventArgs e)
        {
            ValidateInputText(tbInputTextToCrypt.Text);
        }

        private static void ValidateInputText(string inputText)
        {
            if(string.IsNullOrEmpty(inputText)) 
            {
                MessageBox.Show("Input text cannot be empty! Try again!", "Alert", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            if (inputText.Length > 100)
            {
                MessageBox.Show("Input text cannot have greater than 100 characters! Try again!", "Alert", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
        }
    }
}
