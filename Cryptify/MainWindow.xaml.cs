using Cryptify.Generators;
using Microsoft.Win32;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;

namespace Cryptify;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window
{
    private string selectedFilePath;
    private string privateKeyPath = "privateKey.pem";
    private string publicKeyPath = "publicKey.pem";

    public MainWindow()
    {
        InitializeComponent();
    }

    private void FileEncyptButton_Click(object sender, RoutedEventArgs e)
    {
        // Ініціалізуємо діалог вибору файлу
        OpenFileDialog openFileDialog = new ()
        {
            Filter = "Text Files (*.txt)|*.txt",
            Multiselect = false
        };
        string encryptedFilePath = @"D:\test\encrypted_file.bin";

        // Відкриваємо діалогове вікно
        if (openFileDialog.ShowDialog() == true)
        {
            // Отримуємо шлях до вибраного файлу
            string filePath = openFileDialog.FileName;
            // 1. Генерація ключа та IV для шифрування
            var (key, iv) = AesCryptoService.GenerateKeyAndIV();

            // Генерація додаткового ключа для MAC
            byte[] macKey = AesCryptoService.GenerateKeyAndIV().Key;

            // 2. Шифруємо файл
            AesCryptoService.EncryptFile(filePath, encryptedFilePath, key, iv, macKey, out var mac);
            byte[] encryptedData = File.ReadAllBytes(encryptedFilePath);

            // Читаємо зашифровані дані для створення MAC
            string metadataFilePath = @"D:\test\metadata.bin";
            AesCryptoService.SaveEncryptionMetadata(metadataFilePath, key, iv, mac, macKey);
            MessageBox.Show($"Encrypted file saved: {metadataFilePath}", "Saved", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void FileDecyptButton_Click(object sender, RoutedEventArgs e)
    {
        // Ініціалізуємо діалог вибору файлу
        OpenFileDialog openFileDialog = new()
        {
            Filter = "Text Files (*.bin)|*.bin",
            Multiselect = false
        };
        string encryptedFilePath = @"D:\test\encrypted_file.bin";
        string decryptedFilePath = @"D:\test\decrypted_file.txt";

        // Відкриваємо діалогове вікно
        if (openFileDialog.ShowDialog() == true)
        {
            // Отримуємо шлях до вибраного файлу
            string filePath = openFileDialog.FileName;
            try
            {
                string metadataFilePath = @"D:\test\metadata.bin";
                var (key, iv, mac, macKey) = AesCryptoService.LoadEncryptionMetadata(metadataFilePath);

                // Тепер можеш використовувати параметри для дешифрування
                AesCryptoService.DecryptFile(encryptedFilePath, decryptedFilePath, key, iv, mac, macKey);
                MessageBox.Show("File decrypted successfully and MAC verified!");
            }
            catch (CryptographicException ex)
            {
                MessageBox.Show($"Error during decryption or MAC verification: {ex.Message}");
            }
        }

        MessageBox.Show("File encrypted successfully!");
    }

    // Генерація пари ключів
    private void GenerateKeyPairButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            RsaCryptoService.GenerateKeyPair(privateKeyPath, publicKeyPath);
            MessageBox.Show("RSA key pair generated successfully.");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error generating keys: {ex.Message}");
        }
    }

    // Вибір файлу для шифрування
    private void SelectFileToEncryptButton_Click(object sender, RoutedEventArgs e)
    {
        var openFileDialog = new OpenFileDialog();
        if (openFileDialog.ShowDialog() == true)
        {
            selectedFilePath = openFileDialog.FileName;
            RsaEncryptionStatusText.Text = $"File selected: {selectedFilePath}";
        }
    }

    // Шифрування файлу
    private void EncryptButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var outputFilePath = Path.Combine(Path.GetDirectoryName(selectedFilePath), "encrypted_file.bin");
            RsaCryptoService.EncryptFile(selectedFilePath, outputFilePath, publicKeyPath);
            RsaEncryptionStatusText.Text = $"File encrypted successfully: {outputFilePath}";
        }
        catch (Exception ex)
        {
            RsaEncryptionStatusText.Text = $"Encryption failed: {ex.Message}";
        }
    }

    // Вибір файлу для дешифрування
    private void SelectFileToDecryptButton_Click(object sender, RoutedEventArgs e)
    {
        var openFileDialog = new OpenFileDialog();
        if (openFileDialog.ShowDialog() == true)
        {
            selectedFilePath = openFileDialog.FileName;
            RsaDecryptionStatusText.Text = $"File selected: {selectedFilePath}";
        }
    }

    // Дешифрування файлу
    private void DecryptButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var outputFilePath = Path.Combine(Path.GetDirectoryName(selectedFilePath), "decrypted_file.txt");
            RsaCryptoService.DecryptFile(selectedFilePath, outputFilePath, privateKeyPath);
            RsaDecryptionStatusText.Text = $"File decrypted successfully: {outputFilePath}";
        }
        catch (Exception ex)
        {
            RsaDecryptionStatusText.Text = $"Decryption failed: {ex.Message}";
        }
    }

    // Створення підпису для файлу
    private void SignFileButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            byte[] signature = RsaCryptoService.SignFile(selectedFilePath, privateKeyPath);
            File.WriteAllBytes($"{selectedFilePath}.sig", signature);
            RsaSignatureStatusText.Text = $"File signed successfully. Signature saved as {selectedFilePath}.sig";
        }
        catch (Exception ex)
        {
            RsaSignatureStatusText.Text = $"Signing failed: {ex.Message}";
        }
    }

    // Перевірка підпису
    private void VerifySignatureButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            byte[] signature = File.ReadAllBytes($"{selectedFilePath}.sig");
            bool isVerified = RsaCryptoService.VerifyFileSignature(selectedFilePath, signature, publicKeyPath);
            RsaVerificationStatusText.Text = isVerified ? "Signature is valid." : "Signature is invalid.";
        }
        catch (Exception ex)
        {
            RsaVerificationStatusText.Text = $"Verification failed: {ex.Message}";
        }
    }
}