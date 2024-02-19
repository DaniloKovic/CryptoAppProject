using CryptoAppWPFProject.ResponseApiModel;
using CryptoAppWPFProject.ViewModel;
using Newtonsoft.Json;
using System.Net.Http;
using System.Windows;

namespace CryptoAppWPFProject
{
    /// <summary>
    /// Interaction logic for RegistrationWindow.xaml
    /// </summary>
    public partial class RegistrationWindow : Window
    {
        private const string registrationRequestUri = "api/User/Registration";
        private const string loginRequestUri = "api/User/Login";
        // private const string uriString = "https://localhost:5002";
        private const string uriString = "https://localhost:44337";
        public RegistrationWindow()
        {
            InitializeComponent();
        }

        private async void btnConfirmRegistration_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(tbUsernameReg.Text) || string.IsNullOrEmpty(pbPasswordReg.Password) || string.IsNullOrEmpty(pbPasswordRegConfirmation.Password) || string.IsNullOrEmpty(tbEMail.Text))
            {
                MessageBox.Show("All fields are required!", "Alert", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            if (!pbPasswordReg.Password.Equals(pbPasswordRegConfirmation.Password)){
                MessageBox.Show("Passwords do not match!", "Alert", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            using (HttpClient client = new HttpClient())
            {
                UserViewModel userLoginRequest = new UserViewModel()
                {
                    UserName = tbUsernameReg.Text,
                    Password = pbPasswordReg.Password,
                    EMail = tbEMail.Text,
                };

                string jsonData = JsonConvert.SerializeObject(userLoginRequest);
                HttpContent content = new StringContent(jsonData, System.Text.Encoding.UTF8, "application/json");

                client.BaseAddress = new Uri(uriString);
                HttpResponseMessage response = await client.PostAsync(registrationRequestUri, content);
                if (response.IsSuccessStatusCode)
                {
                    string responseBody = await response.Content.ReadAsStringAsync();
                    UserRegistrationResponse? responseObject = JsonConvert.DeserializeObject<UserRegistrationResponse>(responseBody);

                    if(responseObject != null)
                    {
                        registrationWindow.Height = registrationWindow.MaxHeight;
                        registrationWindow.Width = registrationWindow.MaxWidth;
                        pnlRegistrationResult.Visibility = Visibility.Visible;

                        tbPublicKey.Text = responseObject.PublicKeyBase64;
                        tbPrivateKey.Text = responseObject.PrivateKeyBase64;
                        tbCertificatePath.Text = responseObject.DigitalCertificateFilePath;
                    }
                }
                else
                {
                    MessageBox.Show("Registration failed! Try again!", "Alert", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }
            }
            return;

        }
    }
}
