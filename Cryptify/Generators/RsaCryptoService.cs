using System;
using System.IO;
using System.Security.Cryptography;

namespace Cryptify.Generators
{
    public static class RsaCryptoService
    {
        /// <summary>
        /// Generates an RSA key pair and saves the private key and public key to specified file paths.
        /// </summary>
        /// <param name="privateKeyPath">Path to save the private key file.</param>
        /// <param name="publicKeyPath">Path to save the public key file.</param>
        public static void GenerateKeyPair(string privateKeyPath, string publicKeyPath)
        {
            using (var rsa = RSA.Create())
            {
                rsa.KeySize = 2048;

                // Зберігаємо приватний ключ
                File.WriteAllText(privateKeyPath, Convert.ToBase64String(rsa.ExportRSAPrivateKey()));

                // Зберігаємо публічний ключ
                File.WriteAllText(publicKeyPath, Convert.ToBase64String(rsa.ExportRSAPublicKey()));
            }
        }

        /// <summary>
        /// Encrypts a file using an RSA public key and saves the encrypted content to the specified output file.
        /// </summary>
        /// <param name="inputFilePath">Path of the file to encrypt.</param>
        /// <param name="outputFilePath">Path to save the encrypted file.</param>
        /// <param name="publicKeyPath">Path to the file containing the RSA public key.</param>
        public static void EncryptFile(string inputFilePath, string outputFilePath, string publicKeyPath)
        {
            byte[] data = File.ReadAllBytes(inputFilePath);
            byte[] publicKey = Convert.FromBase64String(File.ReadAllText(publicKeyPath));

            using (var rsa = RSA.Create())
            {
                rsa.ImportRSAPublicKey(publicKey, out _);
                byte[] encryptedData = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
                File.WriteAllBytes(outputFilePath, encryptedData);
            }
        }

        /// <summary>
        /// Decrypts a file using an RSA private key and saves the decrypted content to the specified output file.
        /// </summary>
        /// <param name="inputFilePath">Path of the encrypted file.</param>
        /// <param name="outputFilePath">Path to save the decrypted file.</param>
        /// <param name="privateKeyPath">Path to the file containing the RSA private key.</param>
        public static void DecryptFile(string inputFilePath, string outputFilePath, string privateKeyPath)
        {
            byte[] encryptedData = File.ReadAllBytes(inputFilePath);
            byte[] privateKey = Convert.FromBase64String(File.ReadAllText(privateKeyPath));

            using (var rsa = RSA.Create())
            {
                rsa.ImportRSAPrivateKey(privateKey, out _);
                byte[] decryptedData = rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA256);
                File.WriteAllBytes(outputFilePath, decryptedData);
            }
        }

        /// <summary>
        /// Creates a digital signature for a file using an RSA private key.
        /// </summary>
        /// <param name="filePath">Path of the file to sign.</param>
        /// <param name="privateKeyPath">Path to the file containing the RSA private key.</param>
        /// <returns>The generated digital signature as a byte array.</returns>
        public static byte[] SignFile(string filePath, string privateKeyPath)
        {
            byte[] data = File.ReadAllBytes(filePath);
            byte[] privateKey = Convert.FromBase64String(File.ReadAllText(privateKeyPath));

            using (var rsa = RSA.Create())
            {
                rsa.ImportRSAPrivateKey(privateKey, out _);
                return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        /// <summary>
        /// Verifies a digital signature for a file using an RSA public key.
        /// </summary>
        /// <param name="filePath">Path of the file whose signature needs to be verified.</param>
        /// <param name="signature">Digital signature to verify.</param>
        /// <param name="publicKeyPath">Path to the file containing the RSA public key.</param>
        /// <returns>True if the signature is valid; otherwise, false.</returns>
        public static bool VerifyFileSignature(string filePath, byte[] signature, string publicKeyPath)
        {
            byte[] data = File.ReadAllBytes(filePath);
            byte[] publicKey = Convert.FromBase64String(File.ReadAllText(publicKeyPath));

            using (var rsa = RSA.Create())
            {
                rsa.ImportRSAPublicKey(publicKey, out _);
                return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }
    }
}
