using CSERLibrary.Models;
using System;
using System.IO;

namespace Test
{
    class Program
    {
        static void Main(string[] args)
        {
            Encrypt();
            Decrypt();
        }

        private static void Decrypt()
        {
            var ice = new IceKey(2);
            ice.Set(new byte[] { 0x43, 0x53, 0x47, 0x4F, 0xCC, 0x34, 0x00, 0x00, 0x33, 0x0D, 0x00, 0x00, 0x4C, 0x03, 0x00, 0x00 });

            using (var reader = new BinaryReader(File.OpenRead("out.ice")))
            {
                byte[] temp = new byte[reader.BaseStream.Length];
                int bytesLeft = (int)reader.BaseStream.Length;
                while (bytesLeft >= 8)
                {
                    byte[] tmp = new byte[8];
                    byte[] buffer = reader.ReadBytes(8);
                    ice.Decrypt(buffer, ref tmp);
                    bytesLeft -= 8;
                    Array.Copy(tmp, temp, 8);
                }
                File.WriteAllBytes("plain1.txt", temp);
            }
        }

        private static void Encrypt()
        {
            var ice = new IceKey(2);
            ice.Set(new byte[] { 0x43, 0x53, 0x47, 0x4F, 0xCC, 0x34, 0x00, 0x00, 0x33, 0x0D, 0x00, 0x00, 0x4C, 0x03, 0x00, 0x00 });

            using (var reader = new BinaryReader(File.OpenRead("plain.txt")))
            {
                byte[] temp = new byte[reader.BaseStream.Length];
                int bytesLeft = (int)reader.BaseStream.Length;
                while (bytesLeft >= 8)
                {
                    byte[] tmp = new byte[8];
                    byte[] buffer = reader.ReadBytes(8);
                    ice.Encrypt(buffer, ref tmp);
                    bytesLeft -= 8;
                    Array.Copy(tmp, temp, 8);
                }
                File.WriteAllBytes("out.ice", temp);
            }
        }
    }
}
