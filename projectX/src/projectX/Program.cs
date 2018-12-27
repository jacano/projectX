using CSERLibrary.Models;
using DemoInfo;
using DemoInfo.DP;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using projectX.Util;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace ConsoleApp1
{
    class Program
    {
        private static readonly byte[] iceKey = new byte[] { 0x43, 0x53, 0x47, 0x4F, 0x68, 0x35, 0x00, 0x00, 0x5A, 0x0D, 0x00, 0x00, 0x56, 0x03, 0x00, 0x00, };

        //private static int receivedTotal;
        //private static int filter1;
        //private static int filter2;

        private static uint lastAckRecv;
        private static uint sequenceIn;
        private static DemoParser demoParser;

        private enum PacketFlags
        {
            IsReliable = 1,
        }

        static void Main(string[] args)
        {
            InitDemo();

            Sniff();

            //OfflinePackages();
        }

        private static void InitDemo()
        {
            demoParser = new DemoParser(File.OpenRead("pov_qwerty.dem"));
            demoParser.TickDone += parser_TickDone;
            demoParser.ParseHeader();
            demoParser.ParseToEnd();
        }

        private static void OfflinePackages()
        {
            var filePaths = Directory.GetFiles(@".", "*.bin", SearchOption.TopDirectoryOnly).ToArray();

            foreach (var item in filePaths)
            {
                var payloadData = File.ReadAllBytes(item);

                DecipherPayload(payloadData);
            }
        }

        private static void Sniff()
        {
            // Only interfaces with Ipv4
            var allDevices = LivePacketDevice.AllLocalMachine.Where(d => d.Addresses.Any(a => a.Address.Family == SocketAddressFamily.Internet)).ToArray();
            if (allDevices.Length == 0)
            {
                Console.WriteLine("No interfaces found! Make sure WinPcap is installed.");
                return;
            }

            for (var i = 0; i < allDevices.Length; i++)
            {
                var device = allDevices[i];
                var addressName = device.Addresses.First(a => a.Address.Family == SocketAddressFamily.Internet).Address;

                Console.WriteLine($"{i} - {device.Description} - {addressName}");
            }

            var deviceIndex = -1;
            do
            {
                Console.WriteLine($"Enter the interface number to sniff: ");
                var deviceIndexString = Console.ReadLine();

                var isNumber = int.TryParse(deviceIndexString, out deviceIndex);
                var withinExpectedRange = deviceIndex >= 0 && deviceIndex < allDevices.Length;
                if (!isNumber || !withinExpectedRange) deviceIndex = -1;
            }
            while (deviceIndex == -1);

            var selectedDevice = allDevices[deviceIndex];

            using (var communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
            {
                if (communicator.DataLink.Kind != DataLinkKind.Ethernet)
                {
                    Console.WriteLine("This program works only on Ethernet networks.");
                    return;
                }

                using (var filter = communicator.CreateFilter("ip and udp"))
                {
                    communicator.SetFilter(filter);
                }

                Console.WriteLine($"Listening on {selectedDevice.Description}...");

                Console.Clear();

                communicator.ReceivePackets(0, PacketHandler);
            }
        }

        private static void PacketHandler(Packet packet)
        {
            var ip = packet.Ethernet.IpV4;
            var udp = ip.Udp;
            var payload = udp.Payload;

            //Console.WriteLine($"{ip.Source}:{udp.SourcePort} -> {ip.Destination}:{udp.DestinationPort}");
            //Console.WriteLine(payload);

            if (udp.SourcePort != 27015)
            {
                return;
            }

            //receivedTotal++;


            //Console.WriteLine($"receivedTotal: {receivedTotal}");

            using (var ms = payload.ToMemoryStream())
            {
                var payloadData = ms.ToArray();

                //SavePayload(payloadData);
                DecipherPayload(payloadData);

                //GetOnlyValidMsg(payloadData, payloadData.Length);
            }
        }

        private static void SavePayload(byte[] payload)
        {
            //var guid = $"{receivedTotal.ToString("D8")}.bin";

            //File.WriteAllBytes(guid, payload);
        }

        private static void DecipherPayload(byte[] payload)
        {
            var ice = new IceKey(2);
            ice.Set(iceKey);

            var blockSize = ice.BlockSize();
            var ciphertextBlock = new byte[blockSize];
            var plaintextBlock = new byte[blockSize];

            using (var plaintext = new MemoryStream(payload.Length))
            {
                using (var ciphertext = new MemoryStream(payload))
                {
                    while (true)
                    {
                        var bytesRead = ciphertext.Read(ciphertextBlock, 0, blockSize);
                        if (bytesRead < blockSize)
                        {
                            // The end is not ciphered !?!?
                            plaintext.Write(ciphertextBlock, 0, bytesRead);
                            break;
                        }

                        ice.Decrypt(ciphertextBlock, ref plaintextBlock);
                        plaintext.Write(plaintextBlock, 0, blockSize);
                    }
                }

                plaintext.Seek(0, SeekOrigin.Begin);

                var plaintextData = plaintext.ToArray();

                GetOnlyValidMsg(plaintextData, payload.Length);
            }
        }

        private static void GetOnlyValidMsg(byte[] plaintextData, int payloadLength)
        {
            var deltaOffset = plaintextData[0];
            if (deltaOffset > 0 && deltaOffset + 5 < payloadLength)
            {
                var pos1 = plaintextData[deltaOffset + 1];
                var pos2 = plaintextData[deltaOffset + 2];
                var pos3 = plaintextData[deltaOffset + 3];
                var pos4 = plaintextData[deltaOffset + 4];

                var dataFinalSize = SwapBytes(pos4, pos3, pos2, pos1);
                if (dataFinalSize + deltaOffset + 5 == payloadLength)
                {
                    var packetData = new byte[dataFinalSize];
                    Array.Copy(plaintextData, deltaOffset + 5, packetData, 0, dataFinalSize);

                    //filter1++;
                    //Console.WriteLine($"filter1: {filter1}");

                    ProcessPacket(packetData);
                }
            }
        }

        private static uint SwapBytes(byte word1, byte word2, byte word3, byte word4)
        {
            return (uint)(word1 & 0x000000FF) | (uint)((word2 << 8) & 0x0000FF00) | (uint)((word3 << 16) & 0x00FF0000) | (uint)((word4 << 24) & 0xFF000000);
        }


        private static void ProcessPacket(byte[] bytes)
        {
            var length = bytes.Length;
            uint seq, ack;
            byte flags;
            using (var stream = BitStreamUtil.Create(bytes))
            {
                seq = stream.ReadInt(32);
                ack = stream.ReadInt(32);

                flags = stream.ReadByte();
                ushort checksum = (ushort)stream.ReadInt(16);

                stream.BeginChunk((length - 11) * 8);
                ushort computed = CrcUtils.Compute16(stream);
                stream.EndChunk();

                if (checksum != computed)
                {
                    //Console.WriteLine(
                    //    "failed checksum:"
                    //        + "recv seq {0} ack {1} flags {2:x} checksum {3:x} computed {4:x}",
                    //    seq, ack, flags, checksum, computed);
                    return;
                }
            }

            var remaining = new byte[length - 11];
            Array.Copy(bytes, 11, remaining, 0, length - 11);

            using (var stream = BitStreamUtil.Create(remaining))
            {
                byte reliableState = stream.ReadByte();

                if ((flags & 0x10) == 0x10)
                {
                    //Console.WriteLine(
                    //    "choke {0}: recv seq {1} ack {2} flags {3:x}",
                    //    stream.ReadByte(), seq, ack, flags);

                    return;
                }

                if (seq < sequenceIn)
                {
                    // We no longer care.
                    //Console.WriteLine("dropped: recv seq {0} ack {1}", seq, ack);
                    return;
                }

                if ((flags & (uint)PacketFlags.IsReliable) != 0)
                {
                    return;
                }

                //filter2++;
                //Console.WriteLine($"filter2: {filter2}");

                try
                {
                    stream.BeginChunk((remaining.Length - 1) * 8);
                    DemoPacketParser.ParsePacket(stream, demoParser);
                    stream.EndChunk();

                    demoParser.ForceTick(true);
                }
                catch { }

                lastAckRecv = ack;
                sequenceIn = seq;
            }
        }

        private static void parser_TickDone(object sender, TickDoneEventArgs e)
        {
            Console.CursorLeft = 0;
            Console.CursorTop = 0;
            //Console.Clear();

            Console.WriteLine($"IngameTick: {demoParser.CurrentTick}");
            foreach (var playingParticipants in demoParser.PlayingParticipants)
            {
                //Console.WriteLine($"{playingParticipants.Name} - position: {playingParticipants.Position}");
                //if (playingParticipants.Name == "jacano")
                //{
                    Console.WriteLine($"{playingParticipants.Name} - position: {playingParticipants.Position}");
                //}
            }
        }
    }
}
