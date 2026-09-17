using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Loupe.Proxy.Ca;

/// <summary>
/// A self-signed root CA generated and kept on this machine, used only to
/// mint short-lived leaf certificates so Loupe's proxy can terminate
/// TLS for hosts it is asked to intercept. This is the same trust model
/// every HTTPS debugging proxy uses (Charles, Fiddler, mitmproxy, Proxyman):
/// nothing works until the user explicitly installs THIS root into their
/// own trust store, and only for traffic that is actually routed through
/// this proxy (their own apps/devices, proxy-configured on purpose).
///
/// The private key never leaves this machine and is stored per-Windows-user
/// (CurrentUser\My-equivalent app folder), PFX-encrypted with a random
/// password that is itself protected with DPAPI tied to the logged-in user.
/// </summary>
public sealed class RootCertificateAuthority
{
    private const string SubjectName = "CN=Loupe Local CA, O=Loupe (generated on this machine), OU=Do not trust outside Loupe";

    private readonly string _pfxPath;
    private readonly string _protectedPasswordPath;
    private readonly object _lock = new();
    private X509Certificate2? _certificate;

    public RootCertificateAuthority(string? storageDirectory = null)
    {
        string dir = storageDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Loupe", "ca");
        Directory.CreateDirectory(dir);
        _pfxPath = Path.Combine(dir, "loupe-root.pfx");
        _protectedPasswordPath = Path.Combine(dir, "loupe-root.pfx.key");

        AdoptLegacyFiles(dir);
    }

    /// <summary>
    /// Picks up a CA created before the rename. Not optional: the user installed *that*
    /// certificate into their trust store, and generating a new one would silently break HTTPS
    /// interception until they noticed and reinstalled. The certificate itself is unchanged -
    /// only the file names move - so its thumbprint, which is what trust is keyed on, stays the same.
    /// </summary>
    private void AdoptLegacyFiles(string dir)
    {
        string legacyPfx = Path.Combine(dir, "netsniffer-root.pfx");
        string legacyKey = Path.Combine(dir, "netsniffer-root.pfx.key");

        if (File.Exists(_pfxPath) || !File.Exists(legacyPfx) || !File.Exists(legacyKey)) return;

        try
        {
            File.Move(legacyPfx, _pfxPath);
            File.Move(legacyKey, _protectedPasswordPath);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // Leave both in place; LoadOrCreate will simply not find the new names. Better a new
            // CA than a half-moved pair where the key no longer sits next to its certificate.
        }
    }

    /// <summary>The CA certificate + private key, generating and persisting it on first use.</summary>
    public X509Certificate2 Certificate
    {
        get
        {
            lock (_lock)
            {
                return _certificate ??= LoadOrCreate();
            }
        }
    }

    public string Thumbprint => Certificate.Thumbprint;

    /// <summary>The name a person sees in the browser's certificate dialog, e.g. "Loupe Local CA".</summary>
    public string CommonName
    {
        get
        {
            string name = Certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            return name.Length > 0 ? name : Certificate.Subject;
        }
    }

    /// <summary>
    /// True for a CA carried over from before the app was renamed, which still introduces itself
    /// as NetSniffer in every certificate dialog. Harmless - trust is keyed on the thumbprint -
    /// but a certificate that names something you have never heard of is exactly what a person
    /// is supposed to be suspicious of.
    /// </summary>
    public bool HasLegacyName => Certificate.Subject.Contains("NetSniffer", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Throws the current CA away and makes a new one under the current name.
    ///
    /// Everything signed by the old key stops being trusted the moment its root leaves the
    /// store, so this is only ever something the user asks for, and it ends with the new root
    /// needing to be installed again - Windows asks for that separately, as it should.
    /// </summary>
    public void Regenerate()
    {
        lock (_lock)
        {
            TryUninstall();

            foreach (string path in new[] { _pfxPath, _protectedPasswordPath })
            {
                try { File.Delete(path); }
                catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
            }

            _certificate = CreateAndPersist();
        }
    }

    private void TryUninstall()
    {
        try { UninstallForCurrentUser(); }
        catch (Exception e) when (e is System.Security.Cryptography.CryptographicException or UnauthorizedAccessException)
        {
            // The old root stays trusted; harmless, and RemoveOldRoots can still take it out.
        }
    }

    /// <summary>
    /// Removes every root this app has ever installed for this user except the one in use -
    /// the leftovers from earlier installs and from before the rename, which otherwise sit in
    /// the trust store forever, trusted, with nobody holding the matching key any more.
    /// </summary>
    public int RemoveStaleRoots()
    {
        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);

        int removed = 0;
        foreach (var candidate in store.Certificates)
        {
            bool ours = candidate.Subject.Contains("Loupe Local CA", StringComparison.OrdinalIgnoreCase)
                        || candidate.Subject.Contains("NetSniffer Local CA", StringComparison.OrdinalIgnoreCase);

            if (!ours || string.Equals(candidate.Thumbprint, Thumbprint, StringComparison.OrdinalIgnoreCase)) continue;

            try
            {
                store.Remove(candidate);
                removed++;
            }
            catch (Exception e) when (e is System.Security.Cryptography.CryptographicException or UnauthorizedAccessException)
            {
                // Refused (the user said no to Windows' prompt): leave the rest alone too.
                break;
            }
        }

        return removed;
    }

    private X509Certificate2 LoadOrCreate()
    {
        if (File.Exists(_pfxPath) && File.Exists(_protectedPasswordPath))
        {
            try
            {
                string password = UnprotectPassword(File.ReadAllBytes(_protectedPasswordPath));
                var existing = new X509Certificate2(
                    _pfxPath, password, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

                // Regenerate if it somehow expired rather than handing out a dead CA.
                if (existing.NotAfter > DateTime.Now.AddDays(1))
                    return existing;
            }
            catch
            {
                // Corrupt/undecryptable store: fall through and regenerate.
            }
        }

        return CreateAndPersist();
    }

    private X509Certificate2 CreateAndPersist()
    {
        using var key = RSA.Create(3072);
        var request = new CertificateRequest(SubjectName, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddYears(10);
        byte[] serial = RandomNumberGenerator.GetBytes(16);

        using var selfSigned = request.CreateSelfSigned(notBefore, notAfter);

        string password = Convert.ToBase64String(RandomNumberGenerator.GetBytes(24));
        byte[] pfxBytes = selfSigned.Export(X509ContentType.Pfx, password);
        File.WriteAllBytes(_pfxPath, pfxBytes);
        File.WriteAllBytes(_protectedPasswordPath, ProtectPassword(password));

        return new X509Certificate2(
            pfxBytes, password, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
    }

    private static byte[] ProtectPassword(string password) =>
        ProtectedData.Protect(System.Text.Encoding.UTF8.GetBytes(password), optionalEntropy: null, DataProtectionScope.CurrentUser);

    private static string UnprotectPassword(byte[] protectedBytes) =>
        System.Text.Encoding.UTF8.GetString(ProtectedData.Unprotect(protectedBytes, optionalEntropy: null, DataProtectionScope.CurrentUser));

    /// <summary>True if a certificate with this CA's thumbprint is already trusted for the current Windows user.</summary>
    public bool IsInstalledForCurrentUser()
    {
        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        return store.Certificates.Find(X509FindType.FindByThumbprint, Thumbprint, validOnly: false).Count > 0;
    }

    /// <summary>
    /// Adds the CA's public certificate (no private key) to the current Windows
    /// user's Trusted Root store. Per-user, so this does NOT require elevation -
    /// but Windows will still show its own "do you trust this publisher?" prompt,
    /// which is the point: the user has to explicitly say yes.
    /// </summary>
    public void InstallForCurrentUser()
    {
        using var publicOnly = new X509Certificate2(Certificate.Export(X509ContentType.Cert));
        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        store.Add(publicOnly);
    }

    public void UninstallForCurrentUser()
    {
        using var store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadWrite);
        foreach (var cert in store.Certificates.Find(X509FindType.FindByThumbprint, Thumbprint, validOnly: false))
            store.Remove(cert);
    }

    /// <summary>Exports just the public certificate as PEM, e.g. to install manually on a phone.</summary>
    public string ExportPublicCertificatePem()
    {
        byte[] der = Certificate.Export(X509ContentType.Cert);
        return "-----BEGIN CERTIFICATE-----\n" +
               Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks) +
               "\n-----END CERTIFICATE-----\n";
    }
}
