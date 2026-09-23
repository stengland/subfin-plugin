using System;
using System.Security.Cryptography;
using System.Text;

namespace Jellyfin.Plugin.Subsonic.Store;

/// <summary>
/// AES-256-GCM encrypt/decrypt for DB storage.
/// Wire format: IV (12) | AuthTag (16) | Ciphertext.
/// Key derived from plugin salt via Rfc2898 (PBKDF2-SHA256, 100k iterations).
/// </summary>
public static class Crypto
{
    private const int IvLen = 12;
    private const int TagLen = 16;
    private const int KeyLen = 32;
    private const string KdfSalt = "subfin-db-encryption-v1";

    private static byte[]? _cachedKey;

    public static void SetSalt(string salt)
    {
      var newKey = Rfc2898DeriveBytes.Pbkdf2(
          Convert.FromBase64String(salt),
          Encoding.UTF8.GetBytes(KdfSalt),
          100_000, HashAlgorithmName.SHA256, 32);

      Volatile.Write(ref _cachedKey, newKey);
    }

    private static byte[] _GetKey(string salt)
    {
      var key = Volatile.Read(ref _cachedKey);
      if (key != null) return key;

      SetSalt(salt);
      return Volatile.Read(ref _cachedKey)!;
    }

    public static byte[] Encrypt(string plaintext, string salt)
    {
        var key = _GetKey(salt);
        var iv = RandomNumberGenerator.GetBytes(IvLen);
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[TagLen];

        using var aes = new AesGcm(key, TagLen);
        aes.Encrypt(iv, plaintextBytes, ciphertext, tag);

        var result = new byte[IvLen + TagLen + ciphertext.Length];
        Buffer.BlockCopy(iv, 0, result, 0, IvLen);
        Buffer.BlockCopy(tag, 0, result, IvLen, TagLen);
        Buffer.BlockCopy(ciphertext, 0, result, IvLen + TagLen, ciphertext.Length);
        return result;
    }

    public static string Decrypt(byte[] blob, string salt)
    {
        if (blob.Length < IvLen + TagLen)
            throw new ArgumentException("Invalid encrypted blob");

        var key = _GetKey(salt);
        var iv = blob[..IvLen];
        var tag = blob[IvLen..(IvLen + TagLen)];
        var ciphertext = blob[(IvLen + TagLen)..];
        var plaintext = new byte[ciphertext.Length];

        using var aes = new AesGcm(key, TagLen);
        aes.Decrypt(iv, ciphertext, tag, plaintext);
        return Encoding.UTF8.GetString(plaintext);
    }
}
