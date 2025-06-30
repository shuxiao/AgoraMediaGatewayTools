using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using MessagePack;

class Program
{
    static void Main(string[] args)
    {
        string appcert = "0123456789abcdef0123456789abcdef";  // The app certificate for the project, in hex
        string channel = "";  // The channel name
        string uid = "";      // The uid, can be either a Integer uid or a String uid, a zero or empty value means random uid
        string templateId = ""; // The template id, can be empty
        int expiresAfter = 86400; // Expires after XX seconds

        long expiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + expiresAfter;

        var rtcInfo = new Dictionary<string, object>
        {
            { "C", channel },
            { "U", uid },
            { "E", expiresAt },
            {"T", templateId }
        };

        byte[] data = MessagePackSerializer.Serialize(rtcInfo);

        byte[] iv = RandomNumberGenerator.GetBytes(16);

        byte[] key = Convert.FromHexString(appcert);

        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = key;

        byte[] encrypted = AesCtrEncrypt(aes, data, iv);

        byte[] result = new byte[iv.Length + encrypted.Length];
        Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
        Buffer.BlockCopy(encrypted, 0, result, iv.Length, encrypted.Length);

        string streamkey = Convert.ToBase64String(result)
            .Replace("+", "-")
            .Replace("/", "_")
            .TrimEnd('=');

        Console.WriteLine($"streamkey is {streamkey}");
    }

    static byte[] AesCtrEncrypt(SymmetricAlgorithm aes, byte[] data, byte[] iv)
    {
        using var encryptor = aes.CreateEncryptor();
        byte[] counter = new byte[16];
        Buffer.BlockCopy(iv, 0, counter, 0, 16);

        byte[] result = new byte[data.Length];
        byte[] keystream = new byte[16];
        byte[] block = new byte[16];

        for (int i = 0; i < data.Length; i += 16)
        {
            encryptor.TransformBlock(counter, 0, 16, keystream, 0);

            int blockSize = Math.Min(16, data.Length - i);
            Buffer.BlockCopy(data, i, block, 0, blockSize);

            for (int j = 0; j < blockSize; j++)
                result[i + j] = (byte)(block[j] ^ keystream[j]);

            IncrementCounter(counter);
        }

        return result;
    }

    static void IncrementCounter(byte[] counter)
    {
        for (int i = 15; i >= 0; i--)
        {
            if (++counter[i] != 0)
                break;
        }
    }
}

