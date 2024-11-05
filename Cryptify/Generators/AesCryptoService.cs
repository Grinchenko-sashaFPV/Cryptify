using System.IO;
using System.Security.Cryptography;

namespace Cryptify.Generators
{
    internal static class AesCryptoService 
    {
        /// <summary>
        /// Generates a new AES encryption key and initialization vector (IV).
        /// </summary>
        /// <returns>A tuple containing the generated key and IV.</returns>
        public static (byte[] Key, byte[] IV) GenerateKeyAndIV()
        {
            using (Aes aes = Aes.Create())
            {
                aes.GenerateKey();
                aes.GenerateIV();
                return (aes.Key, aes.IV);
            }
        }

        /// <summary>
        /// Encrypts a file using AES encryption in CBC mode, generates a MAC for data integrity,
        /// and saves the encrypted data to the specified output file.
        /// </summary>
        /// <param name="inputFilePath">Path of the file to encrypt.</param>
        /// <param name="outputFilePath">Path to save the encrypted file.</param>
        /// <param name="key">AES encryption key.</param>
        /// <param name="iv">AES initialization vector.</param>
        /// <param name="macKey">Key used to generate the MAC.</param>
        /// <param name="mac">Output parameter to store the generated MAC.</param>
        public static void EncryptFile(string inputFilePath, string outputFilePath, byte[] key, byte[] iv, byte[] macKey, out byte[] mac)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (MemoryStream msEncrypted = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(msEncrypted, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open))
                    {
                        fsInput.CopyTo(cs);
                    }

                    byte[] encryptedData = msEncrypted.ToArray();
                    mac = GenerateMAC(encryptedData, macKey);

                    File.WriteAllBytes(outputFilePath, encryptedData);
                }
            }
        }

        /// <summary>
        /// Decrypts an AES-encrypted file in CBC mode, verifies data integrity using the provided MAC,
        /// and saves the decrypted data to the specified output file.
        /// </summary>
        /// <param name="encryptedFilePath">Path of the encrypted file.</param>
        /// <param name="outputFilePath">Path to save the decrypted file.</param>
        /// <param name="key">AES decryption key.</param>
        /// <param name="iv">AES initialization vector.</param>
        /// <param name="expectedMac">MAC expected for data integrity verification.</param>
        /// <param name="macKey">Key used to verify the MAC.</param>
        /// <exception cref="CryptographicException">Thrown if the MAC does not match, indicating data tampering.</exception>
        public static void DecryptFile(string encryptedFilePath, string outputFilePath, byte[] key, byte[] iv, byte[] expectedMac, byte[] macKey)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                byte[] encryptedData = File.ReadAllBytes(encryptedFilePath);

                // Генерація MAC для перевірки
                byte[] computedMac = GenerateMAC(encryptedData, macKey);
                if (!computedMac.SequenceEqual(expectedMac))
                    throw new CryptographicException("MAC does not match. Data integrity check failed.");

                using (MemoryStream msDecrypted = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(new MemoryStream(encryptedData), aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    cs.CopyTo(msDecrypted);
                    File.WriteAllBytes(outputFilePath, msDecrypted.ToArray());
                }
            }
        }

        /// <summary>
        /// Generates a MAC for the given data using HMAC-SHA256 for data integrity verification.
        /// </summary>
        /// <param name="data">Data to generate the MAC for.</param>
        /// <param name="key">Key used to generate the MAC.</param>
        /// <returns>The computed MAC as a byte array.</returns>
        public static byte[] GenerateMAC(byte[] data, byte[] key)
        {
            using (var hmac = new HMACSHA256(key))
            {
                return hmac.ComputeHash(data);
            }
        }

        /// <summary>
        /// Saves encryption metadata including key, IV, MAC, and MAC key to a specified file.
        /// </summary>
        /// <param name="metadataFilePath">Path to save the metadata file.</param>
        /// <param name="key">Encryption key.</param>
        /// <param name="iv">Initialization vector.</param>
        /// <param name="mac">MAC for integrity verification.</param>
        /// <param name="macKey">Key used to generate the MAC.</param>
        public static void SaveEncryptionMetadata(string metadataFilePath, byte[] key, byte[] iv, byte[] mac, byte[] macKey)
        {
            using (var fs = new FileStream(metadataFilePath, FileMode.Create))
            using (var bw = new BinaryWriter(fs))
            {
                bw.Write(key.Length);
                bw.Write(key);
                bw.Write(iv.Length);
                bw.Write(iv);
                bw.Write(mac.Length);
                bw.Write(mac);
                bw.Write(macKey.Length);
                bw.Write(macKey);
            }
        }

        /// <summary>
        /// Loads encryption metadata including key, IV, MAC, and MAC key from a specified file.
        /// </summary>
        /// <param name="metadataFilePath">Path of the metadata file to load.</param>
        /// <returns>A tuple containing the key, IV, MAC, and MAC key.</returns>
        public static (byte[] Key, byte[] IV, byte[] MAC, byte[] MacKey) LoadEncryptionMetadata(string metadataFilePath)
        {
            using (var fs = new FileStream(metadataFilePath, FileMode.Open))
            using (var br = new BinaryReader(fs))
            {
                int keyLength = br.ReadInt32();
                byte[] key = br.ReadBytes(keyLength);

                int ivLength = br.ReadInt32();
                byte[] iv = br.ReadBytes(ivLength);

                int macLength = br.ReadInt32();
                byte[] mac = br.ReadBytes(macLength);

                int macKeyLength = br.ReadInt32();
                byte[] macKey = br.ReadBytes(macKeyLength);

                return (key, iv, mac, macKey);
            }
        }

    }
}
