using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
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
    /// Interaction logic for DigitalCertificateInputWindow.xaml
    /// </summary>
    public partial class DigitalCertificateInputWindow : Window
    {
        public DigitalCertificateInputWindow()
        {
            InitializeComponent();
        }

        private void OnFileDrop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);

                foreach (string file in files)
                {
                    try
                    {
                        //if (Path.GetExtension(file).Equals(".pfx", StringComparison.OrdinalIgnoreCase))
                        //{
                            X509Certificate2 certificate = new X509Certificate2(file);
                            // Ovde možete dalje raditi sertifikatom kako želite
                            MessageBox.Show($"Sertifikat učitan:\n{certificate.Subject}", "Uspješno učitan sertifikat", MessageBoxButton.OK, MessageBoxImage.Information);
                        //}
                        //else
                        //{
                        //    MessageBox.Show("Nije podržana ekstenzija fajla. Molimo vas da odaberete fajl sa ekstenzijom .pfx", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                        //}
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Došlo je do greške pri učitavanju sertifikata:\n{ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
        }
    }
}
