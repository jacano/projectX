using CSERLibrary.Models;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using System;
using System.IO;
using System.Linq;

namespace ConsoleApp1
{
    class Program
    {
        private static readonly byte[] iceKey = new byte[] { 0x43, 0x53, 0x47, 0x4F, 0x68, 0x35, 0x00, 0x00, 0x5A, 0x0D, 0x00, 0x00, 0x56, 0x03, 0x00, 0x00, };

        static void Main(string[] args)
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

                communicator.ReceivePackets(0, PacketHandler);
            }
        }

        private static void PacketHandler(Packet packet)
        {
            var ip = packet.Ethernet.IpV4;
            var udp = ip.Udp;
            var payload = udp.Payload;

            Console.WriteLine($"{ip.Source}:{udp.SourcePort} -> {ip.Destination}:{udp.DestinationPort}");
            Console.WriteLine(payload);

            if (udp.SourcePort != 27015)
            {
                return;
            }

            using (var ms = payload.ToMemoryStream())
            {
                var payloadData = ms.ToArray();

                //SavePayload(payloadData);
                HandlePayload(payloadData);
            }
        }

        private static void SavePayload(byte[] payload)
        {
            var guid = Guid.NewGuid().ToString();

            File.WriteAllBytes(guid, payload);
        }

        private static void HandlePayload(byte[] payload)
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

                var deltaOffset = plaintextData[0];
                if (deltaOffset > 0 && deltaOffset + 5 < payload.Length)
                {
                    var pos1 = plaintextData[deltaOffset + 1];
                    var pos2 = plaintextData[deltaOffset + 2];
                    var pos3 = plaintextData[deltaOffset + 3];
                    var pos4 = plaintextData[deltaOffset + 4];

                    var dataFinalSize = SwapBytes(pos4, pos3, pos2, pos1);
                    if (dataFinalSize + deltaOffset + 5 == payload.Length)
                    {
                        var packetData = new byte[dataFinalSize];
                        Array.Copy(plaintextData, deltaOffset + 5, packetData, 0, dataFinalSize);

                        using (var ms = new MemoryStream(packetData))
                        {
                            ParseDemo(ms);
                        }
                    }
                }
            }
        }

        public static uint SwapBytes(byte word1, byte word2, byte word3, byte word4)
        {
            return (uint)(word1 & 0x000000FF) | (uint)((word2 << 8) & 0x0000FF00) | (uint)((word3 << 16) & 0x00FF0000) | (uint)((word4 << 24) & 0xFF000000);
        }

        private static void ParseDemo(MemoryStream plaintext)
        {
         //   var bitStream = BitStreamUtil.Create(plaintext);

         //   bitStream.ReadInt(32); // SeqNrIn
         //   bitStream.ReadInt(32); // SeqNrOut

         //   var nFlags = bitStream.ReadVarInt();

         //   var unk0 = bitStream.ReadSignedInt(16); // dunno what this is
         //   var unk1 = bitStream.ReadSignedVarInt(); // dunno what this is

         //   if (nFlags != 0 || nFlags >= 0xE1u)
	        //{
         //       int cmd = bitStream.ReadProtobufVarInt(); //What type of packet is this?
         //       int length = bitStream.ReadProtobufVarInt(); //And how long is it?

         //       if (cmd == (int)SVC_Messages.svc_PacketEntities)
         //       {
         //           ///new PacketEntities().Parse(bitStream, parser);
         //       }

         //       foreach (var playingParticipants in parser.PlayingParticipants)
         //       {
         //           Console.WriteLine($"{playingParticipants.Name} - position: {playingParticipants.Position}");
         //       }

         //   }
        }
    }
}
