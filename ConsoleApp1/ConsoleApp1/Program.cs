using CSERLibrary.Models;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using System;
using System.Linq;

namespace ConsoleApp1
{
    class Program
    {
        static readonly byte[] iceKey = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

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

            if (udp.SourcePort == 27015)
            {
                Console.WriteLine($"{packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff")} {ip.Source}:{udp.SourcePort} -> {ip.Destination}:{udp.DestinationPort}");
                Console.WriteLine(udp.Payload);

                var ice = new IceKey(2);
                ice.Set(iceKey);

                var blockSize = ice.BlockSize();
                var ciphertextBlock = new byte[blockSize];
                var plaintextBlock = new byte[blockSize];

                using (var ciphertext = udp.Payload.ToMemoryStream())
                {
                    var plaintext = new byte[ciphertext.Length];
                    var plaintextIndex = 0;

                    while (true)
                    {
                        var bytesRead = ciphertext.Read(ciphertextBlock, 0, blockSize);
                        if (bytesRead < blockSize)
                        {
                            // The end is not cipher !?!?
                            Array.Copy(ciphertextBlock, 0, plaintext, plaintextIndex, bytesRead);
                            break;
                        }

                        ice.Decrypt(ciphertextBlock, ref plaintextBlock);

                        Array.Copy(plaintextBlock, 0, plaintext, plaintextIndex, blockSize);
                        plaintextIndex += blockSize;
                    }

                   

                }
            }
        }
    }
}
