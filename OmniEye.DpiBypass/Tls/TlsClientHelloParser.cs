using System;
using System.Text;

namespace OmniEye.DpiBypass.Tls;

public static class TlsClientHelloParser
{
    public const byte ContentTypeHandshake = 0x16;
    public const byte HandshakeTypeClientHello = 0x01;

    public static bool IsClientHello(byte[] data, int length)
    {
        if (length < 9) return false;
        // Check ContentType == Handshake (0x16) and major version == 3
        if (data[0] != ContentTypeHandshake || data[1] != 0x03) return false;
        // Check HandshakeType == ClientHello (0x01)
        if (data[5] != HandshakeTypeClientHello) return false;

        return true;
    }

    public static bool TryFindSni(byte[] data, int length, out string? sni, out int sniValueOffset)
    {
        sni = null;
        sniValueOffset = -1;

        if (!IsClientHello(data, length)) return false;

        try
        {
            // Record Header (5 bytes) + Handshake Header (4 bytes) + Version (2 bytes) + Random (32 bytes) = 43 bytes
            int offset = 43;
            if (offset >= length) return false;

            // Session ID
            int sessionIdLen = data[offset++];
            offset += sessionIdLen;
            if (offset + 2 > length) return false;

            // Cipher Suites
            int cipherSuitesLen = (data[offset] << 8) | data[offset + 1];
            offset += 2 + cipherSuitesLen;
            if (offset + 1 > length) return false;

            // Compression Methods
            int compressionLen = data[offset++];
            offset += compressionLen;
            if (offset + 2 > length) return false;

            // Extensions Length
            int extensionsLen = (data[offset] << 8) | data[offset + 1];
            offset += 2;

            int extensionsEnd = Math.Min(offset + extensionsLen, length);

            while (offset + 4 <= extensionsEnd)
            {
                ushort extType = (ushort)((data[offset] << 8) | data[offset + 1]);
                ushort extLen = (ushort)((data[offset + 2] << 8) | data[offset + 3]);
                offset += 4;

                if (extType == 0x0000) // server_name (SNI) extension
                {
                    if (offset + 5 <= extensionsEnd)
                    {
                        // Server Name List Length (2) + Server Name Type (1, 0x00 = hostname) + Host Name Length (2)
                        int hostNameLen = (data[offset + 3] << 8) | data[offset + 4];
                        sniValueOffset = offset + 5;
                        if (sniValueOffset + hostNameLen <= length)
                        {
                            sni = Encoding.ASCII.GetString(data, sniValueOffset, hostNameLen);
                            return true;
                        }
                    }
                    return false;
                }

                offset += extLen;
            }
        }
        catch
        {
            // Malformed packet
        }

        return false;
    }

    /// <summary>
    /// Computes the optimal split offset for TCP fragmentation.
    /// If configured to split by SNI and SNI is found, splits in the middle of the domain name.
    /// Otherwise splits at the requested fixed byte offset (e.g. 2-5 bytes).
    /// </summary>
    public static int CalculateSplitOffset(byte[] data, int length, int preferredOffset = 2, bool splitInsideSni = true)
    {
        if (length <= 2) return length;

        if (splitInsideSni && TryFindSni(data, length, out var sni, out var sniOffset))
        {
            if (!string.IsNullOrEmpty(sni) && sniOffset > 0)
            {
                // Split halfway inside the SNI hostname string
                return Math.Clamp(sniOffset + (sni.Length / 2), 1, length - 1);
            }
        }

        // Fallback to preferred offset (e.g. byte 2 or 5 of the packet)
        return Math.Clamp(preferredOffset, 1, length - 1);
    }
}
