using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using OmniEye.Core.Configuration;
using OmniEye.Core.Models;
using OmniEye.Core.Security;

namespace OmniEye.Core.Storage;

/// <summary>
/// Hardened SQLite + SQLCipher database manager for OmniEye whitelist and audit storage.
/// Enforces DPAPI-protected AES-256 encryption and exclusive file locking.
/// </summary>
public class DatabaseManager : IDisposable
{
    private readonly OmniEyeConfig _config;
    private FileStream? _exclusiveLockStream;
    private string? _connectionString;
    private bool _disposed;

    public DatabaseManager(OmniEyeConfig config)
    {
        _config = config;
    }

    public void Initialize()
    {
        // 1. Ensure directory and harden with NTFS ACL
        AclSecurityHelper.EnsureHardenedDirectory(_config.DbDirectory, _config.DeveloperMode, out _);

        // 2. Initialize SQLCipher provider
        SQLitePCL.Batteries_V2.Init();

        // 3. Acquire DPAPI-protected key
        var keyBytes = DpapiStorageKeyManager.GetOrCreateKey(_config.KeyFilePath, _config.DeveloperMode);
        var hexKey = DpapiStorageKeyManager.ToHexString(keyBytes);

        // 4. Build connection string with SQLCipher password
        var builder = new SqliteConnectionStringBuilder
        {
            DataSource = _config.DbFilePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Password = hexKey,
            Cache = SqliteCacheMode.Shared
        };
        _connectionString = builder.ToString();

        // 5. Apply database schema
        using (var connection = new SqliteConnection(_connectionString))
        {
            connection.Open();

            // Enforce exclusive SQLite locking mode
            using (var cmd = connection.CreateCommand())
            {
                cmd.CommandText = "PRAGMA locking_mode = EXCLUSIVE; PRAGMA journal_mode = WAL;";
                cmd.ExecuteNonQuery();
            }

            using (var cmd = connection.CreateCommand())
            {
                cmd.CommandText = @"
                    CREATE TABLE IF NOT EXISTS Whitelist (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        FilePath TEXT NOT NULL UNIQUE,
                        FileName TEXT NOT NULL,
                        Sha256 TEXT NOT NULL,
                        IsSigned INTEGER NOT NULL,
                        SignerSubject TEXT,
                        CreatedAt TEXT NOT NULL,
                        IsEnabled INTEGER NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_whitelist_path ON Whitelist(FilePath);
                ";
                cmd.ExecuteNonQuery();
            }
        }

        // 6. Acquire exclusive file lock on a lock file or DB in production
        AcquireExclusiveLock();
    }

    private void AcquireExclusiveLock()
    {
        if (_exclusiveLockStream != null)
            return;

        try
        {
            var lockFilePath = Path.Combine(_config.DbDirectory, "omnieye.lock");
            _exclusiveLockStream = new FileStream(
                lockFilePath,
                FileMode.OpenOrCreate,
                FileAccess.ReadWrite,
                FileShare.None);
        }
        catch (Exception ex)
        {
            if (!_config.DeveloperMode)
            {
                throw new InvalidOperationException($"Failed to acquire exclusive lock on OmniEye storage: {ex.Message}", ex);
            }
        }
    }

    public List<WhitelistEntry> GetWhitelist()
    {
        EnsureInitialized();
        var list = new List<WhitelistEntry>();

        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT Id, FilePath, FileName, Sha256, IsSigned, SignerSubject, CreatedAt, IsEnabled FROM Whitelist ORDER BY Id ASC";

        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            list.Add(new WhitelistEntry
            {
                Id = reader.GetInt32(0),
                FilePath = reader.GetString(1),
                FileName = reader.GetString(2),
                Sha256 = reader.GetString(3),
                IsSigned = reader.GetInt32(4) == 1,
                SignerSubject = reader.IsDBNull(5) ? null : reader.GetString(5),
                CreatedAt = DateTime.Parse(reader.GetString(6)),
                IsEnabled = reader.GetInt32(7) == 1
            });
        }

        return list;
    }

    public WhitelistEntry AddEntry(string filePath, bool bypassSignatureCheck = false)
    {
        EnsureInitialized();

        if (!File.Exists(filePath))
            throw new FileNotFoundException("File not found.", filePath);

        var fullPath = Path.GetFullPath(filePath);
        var fileName = Path.GetFileName(fullPath);

        // Compute SHA-256
        string sha256;
        using (var sha = SHA256.Create())
        using (var stream = File.OpenRead(fullPath))
        {
            sha256 = Convert.ToHexString(sha.ComputeHash(stream));
        }

        // Verify signature
        var sigResult = AuthenticodeVerifier.VerifyFile(fullPath);
        if (!sigResult.IsValid && !bypassSignatureCheck && !_config.DeveloperMode)
        {
            throw new InvalidOperationException($"Cannot add unsigned or invalidly signed file to whitelist in non-developer mode. Status: {sigResult.StatusMessage}");
        }

        var entry = new WhitelistEntry
        {
            FilePath = fullPath,
            FileName = fileName,
            Sha256 = sha256,
            IsSigned = sigResult.IsValid,
            SignerSubject = sigResult.SignerSubject,
            CreatedAt = DateTime.UtcNow,
            IsEnabled = true
        };

        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var cmd = connection.CreateCommand();
        cmd.CommandText = @"
            INSERT INTO Whitelist (FilePath, FileName, Sha256, IsSigned, SignerSubject, CreatedAt, IsEnabled)
            VALUES ($path, $name, $sha, $signed, $subject, $created, $enabled)
            ON CONFLICT(FilePath) DO UPDATE SET
                FileName = excluded.FileName,
                Sha256 = excluded.Sha256,
                IsSigned = excluded.IsSigned,
                SignerSubject = excluded.SignerSubject,
                IsEnabled = excluded.IsEnabled;
            SELECT last_insert_rowid();
        ";
        cmd.Parameters.AddWithValue("$path", entry.FilePath);
        cmd.Parameters.AddWithValue("$name", entry.FileName);
        cmd.Parameters.AddWithValue("$sha", entry.Sha256);
        cmd.Parameters.AddWithValue("$signed", entry.IsSigned ? 1 : 0);
        cmd.Parameters.AddWithValue("$subject", (object?)entry.SignerSubject ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$created", entry.CreatedAt.ToString("o"));
        cmd.Parameters.AddWithValue("$enabled", entry.IsEnabled ? 1 : 0);

        var rowId = Convert.ToInt32(cmd.ExecuteScalar());
        if (rowId > 0)
            entry.Id = rowId;

        return entry;
    }

    public bool RemoveEntry(int id)
    {
        EnsureInitialized();

        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var cmd = connection.CreateCommand();
        cmd.CommandText = "DELETE FROM Whitelist WHERE Id = $id";
        cmd.Parameters.AddWithValue("$id", id);

        return cmd.ExecuteNonQuery() > 0;
    }

    public bool RemoveEntryByPath(string filePath)
    {
        EnsureInitialized();

        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var cmd = connection.CreateCommand();
        cmd.CommandText = "DELETE FROM Whitelist WHERE FilePath = $path COLLATE NOCASE";
        cmd.Parameters.AddWithValue("$path", filePath);

        return cmd.ExecuteNonQuery() > 0;
    }

    public bool IsPathWhitelisted(string filePath)
    {
        EnsureInitialized();

        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM Whitelist WHERE FilePath = $path COLLATE NOCASE AND IsEnabled = 1";
        cmd.Parameters.AddWithValue("$path", filePath);

        var count = Convert.ToInt32(cmd.ExecuteScalar());
        return count > 0;
    }

    public void ReleaseLock()
    {
        if (_exclusiveLockStream != null)
        {
            _exclusiveLockStream.Dispose();
            _exclusiveLockStream = null;
        }
    }

    private void EnsureInitialized()
    {
        if (string.IsNullOrEmpty(_connectionString))
            throw new InvalidOperationException("DatabaseManager has not been initialized. Call Initialize() first.");
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        ReleaseLock();
        SqliteConnection.ClearAllPools();
    }
}
