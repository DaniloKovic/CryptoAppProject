using CryptoAppWPFProject.ViewModel;
using Microsoft.Win32;
using Newtonsoft.Json;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace CryptoAppWPFProject
{
    /// <summary>
    /// Interaction logic for LogInWindow.xaml
    /// </summary>
    public partial class LogInWindow : Window
    {
        public LogInWindow()
        {
            InitializeComponent();
        }

        //private void btnRegistracija_Click(object sender, RoutedEventArgs e)
        //{
        //    if (this.Height < MaxHeight)
        //    {
        //        pnlRegistracija.Visibility = Visibility.Visible;
        //        this.Height = MaxHeight;
        //    }
        //    else if (this.Height == MaxHeight)
        //    {
        //        pnlRegistracija.Visibility = Visibility.Collapsed;
        //        this.Height = MinHeight;
        //    }

        //}

        private void cbPrikaziLozinku_Checked(object sender, RoutedEventArgs e)
        {
            if (cbPrikaziLozinku.IsChecked == true)
            {
                pbLozinkaText.Text = pbLozinka.Password;
                pbLozinkaText.Visibility = Visibility.Visible;
            }
        }

        private void cbPrikaziLozinku_Unchecked(object sender, RoutedEventArgs e)
        {
            if (cbPrikaziLozinku.IsChecked == false)
            {
                pbLozinkaText.Visibility = Visibility.Collapsed;
            }
        }

        //private async Task<bool> btnPotvrdiPrijavu_ClickAsync(object sender, RoutedEventArgs e)
        //{
        //    if (string.IsNullOrEmpty(tbKorisnickoIme.Text) ||   string.IsNullOrEmpty(pbLozinka.Password))
        //    {
        //        MessageBox.Show("Popunite sva potrebna polja!", "Alert", MessageBoxButton.OK, MessageBoxImage.Error);
        //        return false;
        //    }
            
        //    using (HttpClient client = new HttpClient())
        //    {
        //        UserViewModel userLoginRequest = new UserViewModel()
        //        {
        //            UserName = tbKorisnickoIme.Text,
        //            Password = pbLozinka.Password
        //        };

        //        // Postavljanje sadržaja zahteva
        //        string jsonData = JsonConvert.SerializeObject(userLoginRequest);
        //        HttpContent content = new StringContent(jsonData, System.Text.Encoding.UTF8, "application/json");

        //        client.BaseAddress = new Uri("https://localhost:5110"); // Promenite port prema vašem API-ju
        //        HttpResponseMessage response = await client.PostAsync("api/Login", content);

        //        if (response.IsSuccessStatusCode)
        //        {
        //            string responseBody = await response.Content.ReadAsStringAsync();
        //            return true;
        //        }
        //        else
        //        {
        //            // Obrada neuspešnog odgovora
        //            // ...
        //            return false;
        //        }
        //    }
        //    return false;
        //}

        //private async void btnPotvrdiPrijavu_ClickAsync(object sender, RoutedEventArgs e)
        //{
        //    if (string.IsNullOrEmpty(tbKorisnickoIme.Text) || string.IsNullOrEmpty(pbLozinka.Password))
        //    {
        //        MessageBox.Show("Popunite sva potrebna polja!", "Alert", MessageBoxButton.OK, MessageBoxImage.Error);
        //        return;
        //    }

        //    using (HttpClient client = new HttpClient())
        //    {
        //        UserViewModel userLoginRequest = new UserViewModel()
        //        {
        //            UserName = tbKorisnickoIme.Text,
        //            Password = pbLozinka.Password
        //        };

        //        string jsonData = JsonConvert.SerializeObject(userLoginRequest);
        //        HttpContent content = new StringContent(jsonData, System.Text.Encoding.UTF8, "application/json");

        //        client.BaseAddress = new Uri("https://localhost:5110");
        //        HttpResponseMessage response = await client.PostAsync("api/Login", content);

        //        if (response.IsSuccessStatusCode)
        //        {
        //            string responseBody = await response.Content.ReadAsStringAsync();
        //        }
        //        else
        //        {
        //            // Obrada neuspešnog odgovora
        //            // ...
        //        }
        //    }
        //}

        private void btnSubmit_Click(object sender, RoutedEventArgs e)
        {
            
        }

        private void btnValidateCertificate_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Filter = "DigitalCertificates|*.pfx;";
            // openFileDialog.Filter = "PFX sertifikati (*.pfx)|*.pfx|Svi fajlovi|*.*";
            // openFileDialog.Filter = "DigitalCertificates|*.txt;";

            if (openFileDialog.ShowDialog() == true)
            {
                try
                {
                    // X509Certificate2 certificate = new X509Certificate2(openFileDialog.FileName);

                    X509Certificate2 certificate = new X509Certificate2(openFileDialog.FileName, "", X509KeyStorageFlags.MachineKeySet);
                    // Ovde možete dalje raditi sertifikatom kako želite
                    tbCertificateContent.Text = certificate.Subject + '\n';
                    tbCertificateContent.Text += certificate.FriendlyName + '\n';
                    tbCertificateContent.Text += certificate.Issuer + '\n';
                    MessageBox.Show($"Sertifikat učitan:\n{certificate.Subject}", "Uspješno učitan sertifikat", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (System.Security.Cryptography.CryptographicException)
                {
                    MessageBox.Show("Nije moguće učitati sertifikat. Molimo vas da odaberete validan sertifikat.", "Greška", MessageBoxButton.OK, MessageBoxImage.Error);
                }
                catch (System.Exception ex)
                {
                    MessageBox.Show($"Došlo je do greške:\n{ex.Message}", "Greška", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void btnLoginSubmit_Click(object sender, RoutedEventArgs e)
        {

        }
    }
}