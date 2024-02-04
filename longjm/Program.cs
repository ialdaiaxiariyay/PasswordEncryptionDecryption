using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class SimpleTextEncryptor
{
    static void Main(string[] args)
    {
        while (true)
        {
            Console.WriteLine("输入'jm'进入加密模式，输入'ja'进入解密模式，输入'exit'退出程序。");
            string mode = Console.ReadLine().Trim().ToLower();

            if (mode == "exit")
            {
                break;
            }

            switch (mode)
            {
                case "jm":
                    EncryptMode();
                    break;
                case "ja":
                    DecryptMode();
                    break;
                default:
                    Console.WriteLine("未知的命令，请重新输入。");
                    break;
            }
        }
    }

    private static void EncryptMode()
    {
        Console.Write("请输入要加密的文本: ");
        string inputText = Console.ReadLine();
        string password = GeneratePassword();
        string encryptedText = Encrypt(inputText, password);
        Console.WriteLine($"密码: {password}");
        Console.WriteLine($"加密文本: {encryptedText}");
    }

    private static void DecryptMode()
    {
        Console.Write("请输入要解密的文本: ");
        string encryptedText = Console.ReadLine();
        Console.Write("请输入密码: ");
        string password = Console.ReadLine();
        try
        {
            string decryptedText = Decrypt(encryptedText, password);
            Console.WriteLine($"解密文本: {decryptedText}");
        }
        catch (Exception ex)
        {
            Console.WriteLine("解密失败: " + ex.Message);
        }
    }

    private static string GeneratePassword()
    {
        using (var rng = new RNGCryptoServiceProvider())
        {
            byte[] randomBytes = new byte[16]; // 128 bits for AES key
            rng.GetBytes(randomBytes);
            return Convert.ToBase64String(randomBytes);
        }
    }

    private static string Encrypt(string plainText, string password)
    {
        byte[] encrypted;
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Convert.FromBase64String(password);
            aesAlg.GenerateIV();
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (var msEncrypt = new MemoryStream())
            {
                using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (var swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plainText);
                    }
                }
                encrypted = aesAlg.IV.Concat(msEncrypt.ToArray()).ToArray();
            }
        }
        return Convert.ToBase64String(encrypted);
    }

    private static string Decrypt(string cipherText, string password)
    {
        string plaintext = null;
        byte[] cipherBytes = Convert.FromBase64String(cipherText);
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = Convert.FromBase64String(password);
            byte[] iv = cipherBytes.Take(16).ToArray();
            byte[] cipher = cipherBytes.Skip(16).ToArray();
            aesAlg.IV = iv;
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (var msDecrypt = new MemoryStream(cipher))
            {
                using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (var srDecrypt = new StreamReader(csDecrypt))
                    {
                        plaintext = srDecrypt.ReadToEnd();
                    }
                }
            }
        }
        return plaintext;
    }
}