using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace NetSniffer.Proxy.Ca;

/// <summary>
/// A self-signed root CA generated and kept on this machine, used only to
/// mint short-lived leaf certificates so NetSniffer's proxy can terminate
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
    private const string SubjectName = "CN=NetSniffer Local CA, O=NetSniffer (generated on this machine), OU=Do not trust outside NetSniffer";

    private readonly string _pfxPath;
    private readonly string _protectedPasswordPath;
    private readonly object _lock = new();
    private X509Certificate2? _certificate;

    public RootCertificateAuthority(string? storageDirectory = null)
    {
        string dir = storageDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NetSniffer", "ca");
        Directory.CreateDirectory(dir);
        _pfxPath = Path.Combine(dir, "netsniffer-root.pfx");
        _protectedPasswordPath = Path.Combine(dir, "netsniffer-root.pfx.key");
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
