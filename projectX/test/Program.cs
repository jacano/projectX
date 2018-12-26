using CSERLibrary.Models;
using DemoInfo;
using System;
using System.IO;

namespace Test
{
    class Program
    {
        private static DemoParser parser;

        static void Main(string[] args)
        {
            //Encrypt();
            //Decrypt();

            //StripHeaderToDemo();

            //DemoTest();
            DemoTest1();
        }

        private static void DemoTestHeadless()
        {
            parser = new DemoParser();
            parser.SetStream(File.OpenRead("headerless.dem"));

            parser.TickDone += parser_TickDone;

            parser.ParseToEnd();
        }

        private static void StripHeaderToDemo()
        {
            var file = File.OpenRead("match730_003317647861457354858_2030613425_135.dem");
            file.Position = 1072;

            using (var fileStream = File.Create("headerless.dem"))
            {
                file.CopyTo(fileStream);
            }
        }

        private static void DemoTest()
        {
            parser = new DemoParser();
            parser.SetStream(File.OpenRead("match730_003317647861457354858_2030613425_135.dem"));

            parser.TickDone += parser_TickDone;

            parser.ParseHeader();
            parser.ParseToEnd();
        }

        private static void DemoTest1()
        {
            parser = new DemoParser();
            parser.SetStream(File.OpenRead("demo_base1.dem"));

            parser.TickDone += parser_TickDone;

            parser.ParseHeader();
            parser.ParseToEnd();
        }

        private static void parser_TickDone(object sender, TickDoneEventArgs e)
        {
            Console.WriteLine($"IngameTick: {parser.CurrentTick}");
            foreach (var playingParticipants in parser.PlayingParticipants)
            {
                Console.WriteLine($"{playingParticipants.Name} - position: {playingParticipants.Position}");
            }
        }

        private static void Decrypt()
        {
            var ice = new IceKey(2);
            ice.Set(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });

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
            ice.Set(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });

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
