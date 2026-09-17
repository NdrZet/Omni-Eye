using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using OmniEye.Core.CloudTunnel.Crypto;

namespace OmniEye.Core.CloudTunnel.Mtproto;

public record HandshakeResult(
    int DcId,
    short DcIndex,
    bool IsMedia,
    byte[] ProtoTag,
    byte[] RelayInit,
    AesCtrCipher ClientDecryptor,
    AesCtrCipher ClientEncryptor,
    AesCtrCipher TelegramEncryptor,
    AesCtrCipher TelegramDecryptor
) : IDisposable
{
    public void Dispose()
    {
        ClientDecryptor.Dispose();
        ClientEncryptor.Dispose();
        TelegramEncryptor.Dispose();
        TelegramDecryptor.Dispose();
    }
}

public static class MtprotoHandshake
{
    public const int HandshakeLength = 64;
    public const int SkipLen = 8;
    public const int PrekeyLen = 32;
    public const int IvLen = 16;
    public const int ProtoTagPos = 56;
    public const int DcIdxPos = 60;

    public static readonly byte[] TagAbridged = [0xef, 0xef, 0xef, 0xef];
    public static readonly byte[] TagIntermediate = [0xee, 0xee, 0xee, 0xee];
    public static readonly byte[] TagSecure = [0xdd, 0xdd, 0xdd, 0xdd];

    /// <summary>
    /// Attempts to parse Telegram client handshake and initialize cipher context.
    /// </summary>
    public static HandshakeResult? TryParse(ReadOnlySpan<byte> handshake, ReadOnlySpan<byte> secret)
    {
        if (handshake.Length < HandshakeLength)
            return null;

        var prekeyIv = handshake.Slice(SkipLen, PrekeyLen + IvLen); // 48 bytes
        var prekey = prekeyIv[..PrekeyLen];
        var iv = prekeyIv[PrekeyLen..];

        // Key = SHA256(prekey + secret)
        Span<byte> toHash = stackalloc byte[PrekeyLen + secret.Length];
        prekey.CopyTo(toHash);
        secret.CopyTo(toHash[PrekeyLen..]);

        Span<byte> decKey = stackalloc byte[32];
        SHA256.HashData(toHash, decKey);

        Span<byte> decrypted = stackalloc byte[HandshakeLength];
        using (var testCipher = new AesCtrCipher(decKey, iv))
        {
            testCipher.Process(handshake, decrypted);
        }

        var protoTag = decrypted.Slice(ProtoTagPos, 4);
        if (!protoTag.SequenceEqual(TagAbridged) &&
            !protoTag.SequenceEqual(TagIntermediate) &&
            !protoTag.SequenceEqual(TagSecure))
        {
            return null;
        }

        short dcIdx = BinaryPrimitives.ReadInt16LittleEndian(decrypted.Slice(DcIdxPos, 2));
        int dcId = Math.Abs((int)dcIdx);
        bool isMedia = dcIdx < 0;

        // Build Client Ciphers
        var cltDec = new AesCtrCipher(decKey, iv);
        cltDec.Skip(HandshakeLength);

        // clt_enc: prekey_iv reversed
        Span<byte> revPrekeyIv = stackalloc byte[PrekeyLen + IvLen];
        for (int i = 0; i < PrekeyLen + IvLen; i++)
            revPrekeyIv[i] = prekeyIv[PrekeyLen + IvLen - 1 - i];

        Span<byte> toHashEnc = stackalloc byte[PrekeyLen + secret.Length];
        revPrekeyIv[..PrekeyLen].CopyTo(toHashEnc);
        secret.CopyTo(toHashEnc[PrekeyLen..]);

        Span<byte> encKey = stackalloc byte[32];
        SHA256.HashData(toHashEnc, encKey);
        var cltEnc = new AesCtrCipher(encKey, revPrekeyIv[PrekeyLen..]);

        // Generate Relay Handshake for Telegram upstream
        var (relayInit, tgEnc, tgDec) = GenerateRelayInit(protoTag, dcIdx);

        return new HandshakeResult(
            DcId: dcId,
            DcIndex: dcIdx,
            IsMedia: isMedia,
            ProtoTag: protoTag.ToArray(),
            RelayInit: relayInit,
            ClientDecryptor: cltDec,
            ClientEncryptor: cltEnc,
            TelegramEncryptor: tgEnc,
            TelegramDecryptor: tgDec
        );
    }

    public static (byte[] relayInit, AesCtrCipher tgEnc, AesCtrCipher tgDec) GenerateRelayInit(ReadOnlySpan<byte> protoTag, short dcIdx)
    {
        byte[] rnd = new byte[HandshakeLength];

        while (true)
        {
            RandomNumberGenerator.Fill(rnd);
            if (rnd[0] == 0xef)
                continue;

            // Check reserved starts
            if ((rnd[0] == 0x48 && rnd[1] == 0x45 && rnd[2] == 0x41 && rnd[3] == 0x44) || // HEAD
                (rnd[0] == 0x50 && rnd[1] == 0x4f && rnd[2] == 0x53 && rnd[3] == 0x54) || // POST
                (rnd[0] == 0x47 && rnd[1] == 0x45 && rnd[2] == 0x54 && rnd[3] == 0x20) || // GET 
                (rnd[0] == 0xee && rnd[1] == 0xee && rnd[2] == 0xee && rnd[3] == 0xee) ||
                (rnd[0] == 0xdd && rnd[1] == 0xdd && rnd[2] == 0xdd && rnd[3] == 0xdd) ||
                (rnd[0] == 0x16 && rnd[1] == 0x03 && rnd[2] == 0x01 && rnd[3] == 0x02))
                continue;

            if (rnd[4] == 0 && rnd[5] == 0 && rnd[6] == 0 && rnd[7] == 0)
                continue;

            break;
        }

        var relayEncKey = rnd.AsSpan(SkipLen, PrekeyLen);
        var relayEncIv = rnd.AsSpan(SkipLen + PrekeyLen, IvLen);

        Span<byte> relayDecPrekeyIv = stackalloc byte[PrekeyLen + IvLen];
        for (int i = 0; i < PrekeyLen + IvLen; i++)
            relayDecPrekeyIv[i] = rnd[SkipLen + PrekeyLen + IvLen - 1 - i];

        var relayDecKey = relayDecPrekeyIv[..PrekeyLen];
        var relayDecIv = relayDecPrekeyIv[PrekeyLen..];

        var tgEnc = new AesCtrCipher(relayEncKey, relayEncIv);
        var tgDec = new AesCtrCipher(relayDecKey, relayDecIv);

        // Encrypt full rnd to get keystream tail
        Span<byte> encryptedFull = stackalloc byte[HandshakeLength];
        using (var tempEnc = new AesCtrCipher(relayEncKey, relayEncIv))
        {
            tempEnc.Process(rnd, encryptedFull);
        }

        Span<byte> tailPlain = stackalloc byte[8];
        protoTag.CopyTo(tailPlain);
        BinaryPrimitives.WriteInt16LittleEndian(tailPlain[4..6], dcIdx);
        RandomNumberGenerator.Fill(tailPlain[6..8]);

        for (int i = 0; i < 8; i++)
        {
            byte keystream = (byte)(encryptedFull[56 + i] ^ rnd[56 + i]);
            rnd[56 + i] = (byte)(tailPlain[i] ^ keystream);
        }

        tgEnc.Skip(HandshakeLength);

        return (rnd, tgEnc, tgDec);
    }
}
