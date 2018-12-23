using CSERLibrary.Models;
using DemoInfo;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using System;
using System.IO;
using System.Linq;

namespace ConsoleApp1
{
    class Program
    {
        static readonly byte[] iceKey = new byte[] { 0x6C, 0x06, 0x5F, 0xA4, 0x05, 0xAD, 0x18, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

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

                SavePayload(payloadData);
                //HandlePayload(payloadData);
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

                //ParseDemo(plaintext);
            }
        }

        private static void ParseDemo(MemoryStream plaintext)
        {
            var parser = new DemoParser(plaintext);
            parser.TickDone += (object sender, TickDoneEventArgs e) =>
            {
                foreach (var playingParticipants in parser.PlayingParticipants)
                {
                    Console.WriteLine($"{playingParticipants.Name} - position: {playingParticipants.Position}");
                }
            };

            parser.ParseToEnd();
        }
    }
}
