using System;
using System.IO;
using System.Security.Cryptography;

namespace OmniEye.Core.Security;

/// <summary>
/// Manages the 256-bit encryption key for SQLCipher using Windows DPAPI.
/// Scope: DataProtectionScope.LocalMachine (only SYSTEM and Administrators can decrypt).
/// </summary>
public static class DpapiStorageKeyManager
{
    // Constant optional entropy for application-level domain separation
    private static readonly byte[] Entropy = new byte[] { 0x4F, 0x6D, 0x6E, 0x69, 0x45, 0x79, 0x65, 0x5F, 0x5A, 0x65, 0x72, 0x6F, 0x54, 0x72, 0x75, 0x73, 0x74 };

    public static byte[] GetOrCreateKey(string keyFilePath, bool developerMode = false)
    {
        var directory = Path.GetDirectoryName(keyFilePath);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        if (File.Exists(keyFilePath))
        {
            try
            {
                var encryptedData = File.ReadAllBytes(keyFilePath);
                return ProtectedData.Unprotect(encryptedData, Entropy, DataProtectionScope.LocalMachine);
            }
            catch (Exception) when (developerMode)
            {
                // In developer mode, attempt CurrentUser fallback if LocalMachine was created under different test permissions
                try
                {
                    var encryptedData = File.ReadAllBytes(keyFilePath);
                    return ProtectedData.Unprotect(encryptedData, Entropy, DataProtectionScope.CurrentUser);
                }
                catch
                {
                    // If decryption fails completely in dev mode, re-create key
                }
            }
        }

        // Generate 32 bytes (256-bit) cryptographically strong random key
        var newKey = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(newKey);
        }

        byte[] encrypted;
        try
        {
            encrypted = ProtectedData.Protect(newKey, Entropy, DataProtectionScope.LocalMachine);
        }
        catch when (developerMode)
        {
            // Fallback for non-elevated dev testing
            encrypted = ProtectedData.Protect(newKey, Entropy, DataProtectionScope.CurrentUser);
        }

        File.WriteAllBytes(keyFilePath, encrypted);
        return newKey;
    }

    /// <summary>
    /// Converts a 32-byte key to a hex string for SQLCipher PRAGMA key.
    /// </summary>
    public static string ToHexString(byte[] key)
    {
        return Convert.ToHexString(key);
    }
}
