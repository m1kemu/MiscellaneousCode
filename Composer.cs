using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Net;
using System.Security.Cryptography;
using System.IO;

public class Program
{
	public static byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
	{
		using (var aes = Aes.Create())
		{
			aes.KeySize = 128;
			aes.BlockSize = 128;
			aes.Key = key;
			aes.IV = iv;

			using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
			{
				using (var ms = new MemoryStream())
				using (var cryptoStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
				{
					cryptoStream.Write(data, 0, data.Length);
					cryptoStream.FlushFinalBlock();

					return ms.ToArray();
				}
			}
		}
	}

	public static void Main(String[] args)
	{
		byte[] input = File.ReadAllBytes("calc_x64.bin");

		var key = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		var iv = new byte[16] { 0x00, 0xFE, 0x00, 0x1E, 0x00, 0x00, 0x00, 0x47, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

		var encrypted = Encrypt(input, key, iv);
		var data_b64 = Convert.ToBase64String(encrypted);
		var iv_b64 = Convert.ToBase64String(iv);
		var message = data_b64 + ":" + iv_b64;

		System.IO.File.WriteAllText(@"download_me_csharp.txt", message);

		return;
	}
}
