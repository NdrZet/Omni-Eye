using System;
using System.Security.Cryptography;

namespace OmniEye.Core.CloudTunnel.Crypto;

/// <summary>
/// High-performance stream cipher implementing AES-CTR mode (128-bit / 256-bit).
/// Used for MTProto Obfuscated2 encryption and decryption.
/// </summary>
public sealed class AesCtrCipher : IDisposable
{
    private readonly Aes _aes;
    private readonly ICryptoTransform _encryptor;
    private readonly byte[] _counter = new byte[16];
    private readonly byte[] _keystream = new byte[16];
    private int _keystreamOffset = 16;
    private bool _disposed;

    public AesCtrCipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv)
    {
        if (iv.Length != 16)
            throw new ArgumentException("IV must be exactly 16 bytes", nameof(iv));

        if (key.Length != 16 && key.Length != 32)
            throw new ArgumentException("Key must be 16 or 32 bytes", nameof(key));

        iv.CopyTo(_counter);

        _aes = Aes.Create();
        _aes.Mode = CipherMode.ECB;
        _aes.Padding = PaddingMode.None;
        _aes.Key = key.ToArray();
        _encryptor = _aes.CreateEncryptor();
    }

    /// <summary>
    /// Processes data in-place or into destination buffer.
    /// </summary>
    public void Process(ReadOnlySpan<byte> input, Span<byte> output)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (output.Length < input.Length)
            throw new ArgumentException("Output buffer too small", nameof(output));

        int inputLen = input.Length;
        int processed = 0;

        while (processed < inputLen)
        {
            if (_keystreamOffset >= 16)
            {
                _encryptor.TransformBlock(_counter, 0, 16, _keystream, 0);
                IncrementCounter(_counter);
                _keystreamOffset = 0;
            }

            int available = 16 - _keystreamOffset;
            int toXor = Math.Min(available, inputLen - processed);

            for (int i = 0; i < toXor; i++)
            {
                output[processed + i] = (byte)(input[processed + i] ^ _keystream[_keystreamOffset + i]);
            }

            _keystreamOffset += toXor;
            processed += toXor;
        }
    }

    /// <summary>
    /// Fast-forwards the cipher by processing zero bytes (e.g. past 64-byte handshake).
    /// </summary>
    public void Skip(int count)
    {
        Span<byte> dummy = count <= 256 ? stackalloc byte[count] : new byte[count];
        dummy.Clear();
        Process(dummy, dummy);
    }

    /// <summary>
    /// Transforms an array and returns a new byte array.
    /// </summary>
    public byte[] Transform(byte[] input)
    {
        var result = new byte[input.Length];
        Process(input, result);
        return result;
    }

    private static void IncrementCounter(byte[] counter)
    {
        for (int i = 15; i >= 0; i--)
        {
            if (++counter[i] != 0)
                break;
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _encryptor.Dispose();
            _aes.Dispose();
            _disposed = true;
        }
    }
}
