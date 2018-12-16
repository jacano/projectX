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
            var allDevices = LivePacketDevice.AllLocalMachine;
            if (allDevices.Count == 0)
            {
                Console.WriteLine("No interfaces found! Make sure WinPcap is installed.");
                return;
            }

            for (int i = 0; i != allDevices.Count; ++i)
            {
                var device = allDevices[i];

                var addrs = string.Join(", ", device.Addresses.Select(x => x.Address));

                Console.Write((i + 1) + ". " + device.Name + " addrs: " + addrs);

                if (device.Description != null)
                    Console.WriteLine(" (" + device.Description + ")");
                else
                    Console.WriteLine(" (No description available)");
            }

            int deviceIndex = 0;
            do
            {
                Console.WriteLine("Enter the interface number (1-" + allDevices.Count + "):");
                var deviceIndexString = Console.ReadLine();
                if (!int.TryParse(deviceIndexString, out deviceIndex) ||
                    deviceIndex < 1 || deviceIndex > allDevices.Count)
                {
                    deviceIndex = 0;
                }
            } while (deviceIndex == 0);

            var selectedDevice = allDevices[deviceIndex - 1];

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

                Console.WriteLine("Listening on " + selectedDevice.Description + "...");

                communicator.ReceivePackets(0, PacketHandler);
            }
        }

        private static void PacketHandler(Packet packet)
        {
            var ip = packet.Ethernet.IpV4;
            var udp = ip.Udp;

            if (udp.SourcePort == 27015)
            {
                Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " " + ip.Source + ":" + udp.SourcePort + " -> " + ip.Destination + ":" + udp.DestinationPort);
                Console.WriteLine(udp.Payload);

                using (var ms = udp.Payload.ToMemoryStream())
                {
                    var ice = new IceKey(2);
                    ice.Set(iceKey);

                    var blockSize = ice.BlockSize();
                    var p1 = new byte[blockSize];
                    var p2 = new byte[blockSize];

                    var bytesLeft = ms.Length;
                    var plain = new byte[bytesLeft];

                    while (bytesLeft >= blockSize)
                    {
                        ice.Decrypt(p1, ref p2);

                        bytesLeft -= blockSize;
                    }




                }
            }
        }
    }
}
