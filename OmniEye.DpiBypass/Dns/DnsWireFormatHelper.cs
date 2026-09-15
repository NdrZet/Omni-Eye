using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;

namespace OmniEye.DpiBypass.Dns;

public static class DnsWireFormatHelper
{
    public const ushort TypeA = 1;
    public const ushort TypeAaaa = 28;
    public const ushort ClassIn = 1;

    public static byte[] BuildQuery(string domainName, ushort qtype = TypeA, ushort queryId = 0x1234)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        // Header
        writer.Write((byte)(queryId >> 8));
        writer.Write((byte)(queryId & 0xFF));
        writer.Write((byte)0x01); // Flags: QR=0, Opcode=0, AA=0, TC=0, RD=1
        writer.Write((byte)0x00); // RA=0, Z=0, RCODE=0
        writer.Write((byte)0x00); writer.Write((byte)0x01); // QDCOUNT = 1
        writer.Write((byte)0x00); writer.Write((byte)0x00); // ANCOUNT = 0
        writer.Write((byte)0x00); writer.Write((byte)0x00); // NSCOUNT = 0
        writer.Write((byte)0x00); writer.Write((byte)0x00); // ARCOUNT = 0

        // Question QNAME
        var labels = domainName.TrimEnd('.').Split('.');
        foreach (var label in labels)
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            writer.Write((byte)bytes.Length);
            writer.Write(bytes);
        }
        writer.Write((byte)0x00); // End of QNAME

        // QTYPE
        writer.Write((byte)(qtype >> 8));
        writer.Write((byte)(qtype & 0xFF));

        // QCLASS
        writer.Write((byte)(ClassIn >> 8));
        writer.Write((byte)(ClassIn & 0xFF));

        return ms.ToArray();
    }

    public static (List<IPAddress> Addresses, uint MinTtl) ParseResponse(byte[] buffer)
    {
        var addresses = new List<IPAddress>();
        uint minTtl = 300;

        if (buffer.Length < 12) return (addresses, minTtl);

        int ancount = (buffer[6] << 8) | buffer[7];
        if (ancount == 0) return (addresses, minTtl);

        int offset = 12;

        // Skip Question section
        while (offset < buffer.Length)
        {
            byte len = buffer[offset++];
            if (len == 0) break;
            offset += len;
        }
        offset += 4; // Skip QTYPE (2) + QCLASS (2)

        // Parse Answers
        for (int i = 0; i < ancount && offset < buffer.Length; i++)
        {
            // Skip NAME (could be compression pointer or label sequence)
            SkipName(buffer, ref offset);
            if (offset + 10 > buffer.Length) break;

            ushort type = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
            offset += 2;

            ushort @class = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
            offset += 2;

            uint ttl = ((uint)buffer[offset] << 24) | ((uint)buffer[offset + 1] << 16) |
                       ((uint)buffer[offset + 2] << 8) | buffer[offset + 3];
            offset += 4;
            if (ttl > 0 && ttl < minTtl) minTtl = ttl;

            ushort rdLength = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
            offset += 2;

            if (offset + rdLength > buffer.Length) break;

            if (type == TypeA && rdLength == 4)
            {
                byte[] ipBytes = new byte[4];
                Array.Copy(buffer, offset, ipBytes, 0, 4);
                addresses.Add(new IPAddress(ipBytes));
            }
            else if (type == TypeAaaa && rdLength == 16)
            {
                byte[] ipBytes = new byte[16];
                Array.Copy(buffer, offset, ipBytes, 0, 16);
                addresses.Add(new IPAddress(ipBytes));
            }

            offset += rdLength;
        }

        return (addresses, minTtl);
    }

    private static void SkipName(byte[] buffer, ref int offset)
    {
        while (offset < buffer.Length)
        {
            byte b = buffer[offset];
            if ((b & 0xC0) == 0xC0) // Compression pointer
            {
                offset += 2;
                return;
            }
            if (b == 0)
            {
                offset += 1;
                return;
            }
            offset += 1 + b;
        }
    }
}
