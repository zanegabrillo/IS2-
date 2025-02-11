using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.IO;
using System.Security.Cryptography;

namespace FileEncryption
{
    public partial class Form1 : Form
    {
        private const int SALT_SIZE = 16;
        private const int KEY_SIZE = 32;

        public Form1()
        {
            InitializeComponent();
        }

        private void btnEncrypt_Click(object sender, EventArgs e)
        {
            using (OpenFileDialog openFileDialog = new OpenFileDialog())
            {
                openFileDialog.Title = "Select a file to encrypt";
                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        string filePath = openFileDialog.FileName;
                        string key = txtKey.Text;

                        if (string.IsNullOrEmpty(key))
                        {
                            MessageBox.Show("Please enter an encryption key.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }

                        byte[] salt = GenerateRandomSalt();
                        byte[] fileContent = File.ReadAllBytes(filePath);
                        byte[] encryptedContent = VigenereCipher(fileContent, DeriveKey(key, salt), true);

                        // Delete original file
                        File.Delete(filePath);

                        // Write encrypted content to the original file path with .enc extension
                        using (var outputStream = new FileStream(filePath + ".enc", FileMode.Create))
                        {
                            outputStream.Write(salt, 0, salt.Length);
                            outputStream.Write(encryptedContent, 0, encryptedContent.Length);
                        }

                        MessageBox.Show("File encrypted successfully!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Error during encryption: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }

        private void btnDecrypt_Click(object sender, EventArgs e)
        {
            using (OpenFileDialog openFileDialog = new OpenFileDialog())
            {
                openFileDialog.Title = "Select encrypted file to decrypt";
                openFileDialog.Filter = "Encrypted Files (*.enc)|*.enc|All Files (*.*)|*.*";

                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        string encryptedFilePath = openFileDialog.FileName;
                        string key = txtKey.Text;

                        if (string.IsNullOrEmpty(key))
                        {
                            MessageBox.Show("Please enter the decryption key.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }

                        string outputPath;
                        if (encryptedFilePath.EndsWith(".enc", StringComparison.OrdinalIgnoreCase))
                        {
                            outputPath = encryptedFilePath.Substring(0, encryptedFilePath.Length - 4);
                        }
                        else
                        {
                            using (SaveFileDialog saveFileDialog = new SaveFileDialog())
                            {
                                saveFileDialog.Title = "Save decrypted file as";
                                saveFileDialog.FileName = Path.GetFileName(encryptedFilePath);
                                if (saveFileDialog.ShowDialog() != DialogResult.OK)
                                    return;
                                outputPath = saveFileDialog.FileName;
                            }
                        }

                        byte[] fileContent = File.ReadAllBytes(encryptedFilePath);

                        if (fileContent.Length < SALT_SIZE)
                        {
                            throw new Exception("Invalid encrypted file format");
                        }

                        // Extract salt and encrypted content
                        byte[] salt = new byte[SALT_SIZE];
                        byte[] encryptedData = new byte[fileContent.Length - SALT_SIZE];
                        Array.Copy(fileContent, 0, salt, 0, SALT_SIZE);
                        Array.Copy(fileContent, SALT_SIZE, encryptedData, 0, encryptedData.Length);

                        // Decrypt the content
                        byte[] decryptedContent = VigenereCipher(encryptedData, DeriveKey(key, salt), false);

                        // Write decrypted content to original path
                        File.WriteAllBytes(outputPath, decryptedContent);

                        // Delete the encrypted file
                        try
                        {
                            SecureDeleteFile(encryptedFilePath);
                            MessageBox.Show("File decrypted successfully!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        }
                        catch (Exception deleteEx)
                        {
                            MessageBox.Show($"File decrypted successfully but could not delete encrypted file: {deleteEx.Message}",
                                          "Partial Success", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        }
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Error during decryption: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }

        private void SecureDeleteFile(string filePath)
        {
            if (File.Exists(filePath))
            {
                FileInfo fi = new FileInfo(filePath);
                long length = fi.Length;

                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Write, FileShare.None))
                {
                    byte[] buffer = new byte[4096];
                    using (var rng = new RNGCryptoServiceProvider())
                    {
                        long remaining = length;
                        while (remaining > 0)
                        {
                            int currentLength = (int)Math.Min(remaining, buffer.Length);
                            rng.GetBytes(buffer);
                            fs.Write(buffer, 0, currentLength);
                            remaining -= currentLength;
                        }
                    }
                    fs.Flush(true);
                }

                File.Delete(filePath);
            }
        }

        private byte[] VigenereCipher(byte[] input, byte[] key, bool encrypt)
        {
            byte[] output = new byte[input.Length];

            for (int i = 0; i < input.Length; i++)
            {
                if (encrypt)
                {
                    output[i] = (byte)(input[i] ^ key[i % key.Length]);
                }
                else
                {
                    output[i] = (byte)(input[i] ^ key[i % key.Length]);
                }
            }

            return output;
        }

        private byte[] GenerateRandomSalt()
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] salt = new byte[SALT_SIZE];
                rng.GetBytes(salt);
                return salt;
            }
        }

        private byte[] DeriveKey(string password, byte[] salt)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 10000))
            {
                return pbkdf2.GetBytes(KEY_SIZE);
            }
        }
    }
}