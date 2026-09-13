using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace OmniEye.Core.Security;

public class SignatureVerificationResult
{
    public bool IsSigned { get; set; }
    public bool IsValid { get; set; }
    public string? SignerSubject { get; set; }
    public string? SignerIssuer { get; set; }
    public uint Win32Error { get; set; }
    public string? StatusMessage { get; set; }
}

/// <summary>
/// Verifies Authenticode digital signatures using WinVerifyTrust from wintrust.dll.
/// </summary>
public static class AuthenticodeVerifier
{
    private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
    private const string WINTRUST_ACTION_GENERIC_VERIFY_V2 = "{00AAC56B-CD44-11d0-8CC2-00C04FC295EE}";

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false, CharSet = CharSet.Unicode)]
    private static extern uint WinVerifyTrust(
        [In] IntPtr hwnd,
        [In] [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID,
        [In] ref WINTRUST_DATA pWVTData);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pcwszCatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pcwszMemberTag;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedHash;
        public uint cbCalculatedHash;
        public IntPtr pcCatalogContext;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pInfo; // union pFile / pCatalog
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext(out IntPtr phCatAdmin, ref Guid pgSubsystem, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile, ref uint pcbHash, [Out] byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, ref IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_CHOICE_CATALOG = 2;
    private const uint WTD_STATEACTION_IGNORE = 0;
    private const uint WTD_SAFER_FLAG = 0x00000100;
    private const uint WTD_REVOCATION_CHECK_NONE = 0x00000010;
    private const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000;

    // WinVerifyTrust return codes
    private const uint ERROR_SUCCESS = 0;
    private const uint TRUST_E_NOSIGNATURE = 0x800B0100;
    private const uint TRUST_E_EXPLICIT_DISTRUST = 0x800B0111;
    private const uint TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004;
    private const uint CRYPT_E_SECURITY_SETTINGS = 0x80092026;

    public static SignatureVerificationResult VerifyFile(string filePath)
    {
        var result = new SignatureVerificationResult();

        if (!File.Exists(filePath))
        {
            result.StatusMessage = "File does not exist.";
            return result;
        }

        // 1. Try extracting certificate information via X509Certificate
        try
        {
#pragma warning disable SYSLIB0057
            using var rawCert = X509Certificate.CreateFromSignedFile(filePath);
            using var cert2 = new X509Certificate2(rawCert);
#pragma warning restore SYSLIB0057
            result.IsSigned = true;
            result.SignerSubject = cert2.Subject;
            result.SignerIssuer = cert2.Issuer;
        }
        catch
        {
            // File is not signed or certificate format is unrecognized
            result.IsSigned = false;
        }

        // 1. Check embedded Authenticode signature
        var embeddedStatus = VerifyEmbedded(filePath, result);
        if (result.IsValid)
            return result;

        // 2. Check Catalog signature (used by Windows system binaries like cmd.exe, notepad.exe)
        VerifyCatalog(filePath, result);
        return result;
    }

    private static bool VerifyEmbedded(string filePath, SignatureVerificationResult result)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var rawCert = X509Certificate.CreateFromSignedFile(filePath);
            using var cert2 = new X509Certificate2(rawCert);
#pragma warning restore SYSLIB0057
            result.IsSigned = true;
            result.SignerSubject = cert2.Subject;
            result.SignerIssuer = cert2.Issuer;
        }
        catch
        {
            // No embedded certificate
            return false;
        }

        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = filePath,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero
        };

        var pFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
        try
        {
            Marshal.StructureToPtr(fileInfo, pFileInfo, false);

            var winTrustData = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOCATION_CHECK_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pInfo = pFileInfo,
                dwStateAction = WTD_STATEACTION_IGNORE,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = null,
                dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL,
                dwUIContext = 0,
                pSignatureSettings = IntPtr.Zero
            };

            var actionGuid = new Guid(WINTRUST_ACTION_GENERIC_VERIFY_V2);
            var status = WinVerifyTrust(INVALID_HANDLE_VALUE, actionGuid, ref winTrustData);

            result.Win32Error = status;
            result.IsValid = (status == ERROR_SUCCESS);
            result.StatusMessage = status == ERROR_SUCCESS ? "Valid Authenticode signature." : $"WinVerifyTrust code: 0x{status:X8}";
            return result.IsValid;
        }
        finally
        {
            Marshal.FreeHGlobal(pFileInfo);
        }
    }

    private static void VerifyCatalog(string filePath, SignatureVerificationResult result)
    {
        var subsystem = Guid.Empty;
        if (!CryptCATAdminAcquireContext(out var hCatAdmin, ref subsystem, 0))
            return;

        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var hFile = fs.SafeFileHandle.DangerousGetHandle();

            uint hashSize = 0;
            CryptCATAdminCalcHashFromFileHandle(hFile, ref hashSize, null, 0);
            if (hashSize == 0)
                return;

            var hash = new byte[hashSize];
            if (!CryptCATAdminCalcHashFromFileHandle(hFile, ref hashSize, hash, 0))
                return;

            var hexMemberTag = Convert.ToHexString(hash);
            var hPrevCat = IntPtr.Zero;
            var hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hash, hashSize, 0, ref hPrevCat);

            if (hCatInfo == IntPtr.Zero)
            {
                result.IsSigned = false;
                result.IsValid = false;
                result.StatusMessage = "File is not signed (no embedded signature or catalog match).";
                return;
            }

            try
            {
                var catInfo = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
                if (CryptCATCatalogInfoFromContext(hCatInfo, ref catInfo, 0))
                {
                    result.IsSigned = true;

                    // Verify the catalog itself via WinVerifyTrust
                    var catFileInfo = new WINTRUST_CATALOG_INFO
                    {
                        cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                        dwCatalogVersion = 0,
                        pcwszCatalogFilePath = catInfo.wszCatalogFile,
                        pcwszMemberTag = hexMemberTag,
                        pcwszMemberFilePath = filePath,
                        hMemberFile = IntPtr.Zero,
                        pbCalculatedHash = IntPtr.Zero,
                        cbCalculatedHash = 0,
                        pcCatalogContext = IntPtr.Zero
                    };

                    var pCatInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WINTRUST_CATALOG_INFO)));
                    try
                    {
                        Marshal.StructureToPtr(catFileInfo, pCatInfo, false);

                        var winTrustData = new WINTRUST_DATA
                        {
                            cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                            pPolicyCallbackData = IntPtr.Zero,
                            pSIPClientData = IntPtr.Zero,
                            dwUIChoice = WTD_UI_NONE,
                            fdwRevocationChecks = WTD_REVOCATION_CHECK_NONE,
                            dwUnionChoice = WTD_CHOICE_CATALOG,
                            pInfo = pCatInfo,
                            dwStateAction = WTD_STATEACTION_IGNORE,
                            hWVTStateData = IntPtr.Zero,
                            pwszURLReference = null,
                            dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL,
                            dwUIContext = 0,
                            pSignatureSettings = IntPtr.Zero
                        };

                        var actionGuid = new Guid(WINTRUST_ACTION_GENERIC_VERIFY_V2);
                        var status = WinVerifyTrust(INVALID_HANDLE_VALUE, actionGuid, ref winTrustData);

                        result.Win32Error = status;
                        result.IsValid = (status == ERROR_SUCCESS);
                        result.SignerSubject = "Microsoft Windows (Catalog Signed)";
                        result.SignerIssuer = "Microsoft Windows Production PCA";
                        result.StatusMessage = status == ERROR_SUCCESS ? "Valid Windows Catalog signature." : $"Catalog verify code: 0x{status:X8}";
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(pCatInfo);
                    }
                }
            }
            finally
            {
                CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            }
        }
        catch (Exception ex)
        {
            result.StatusMessage = $"Catalog verification exception: {ex.Message}";
        }
        finally
        {
            CryptCATAdminReleaseContext(hCatAdmin, 0);
        }
    }
}
