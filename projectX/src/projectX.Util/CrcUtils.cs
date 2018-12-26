using DemoInfo;
using System;
using System.Collections.Generic;
using System.Text;

namespace projectX.Util
{
    public class CrcUtils
    {

        public static ushort Compute16(byte[] bytes, int offset)
        {
            uint res = Compute32(bytes, offset);

            return (ushort)(((res >> 16) ^ res) & 0xFFFF);
        }

        public static uint Compute32(byte[] bytes, int offset)
        {
            uint crc = 0xFFFFFFFF;

            for (int i = offset; i < bytes.Length; ++i)
            {
                byte index = (byte)(((crc) & 0xFF) ^ bytes[i]);
                crc = (uint)((crc >> 8) ^ table[index]);
            }
            return ~crc;
        }

        public static ushort Compute16(IBitStream stream)
        {
            uint res = Compute32(stream);

            return (ushort)(((res >> 16) ^ res) & 0xFFFF);
        }

        public static uint Compute32(IBitStream stream)
        {
            uint crc = 0xFFFFFFFF;

            while (!stream.ChunkFinished)
            {
                byte index = (byte)(((crc) & 0xFF) ^ stream.ReadByte());
                crc = (uint)((crc >> 8) ^ table[index]);
            }
            return ~crc;
        }

        private static uint[] table;

        static CrcUtils()
        {
            uint poly = 0xedb88320;
            table = new uint[256];
            uint temp = 0;
            for (uint i = 0; i < table.Length; ++i)
            {
                temp = i;

                for (int j = 8; j > 0; --j)
                {
                    if ((temp & 1) == 1)
                    {
                        temp = (uint)((temp >> 1) ^ poly);
                    }
                    else
                    {
                        temp >>= 1;
                    }
                }

                table[i] = temp;
            }
        }
    }
}
