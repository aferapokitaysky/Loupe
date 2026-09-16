using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Loupe.Proxy.Ca;

/// <summary>
/// Mints and caches per-hostname leaf certificates signed by the
/// <see cref="RootCertificateAuthority"/>, so the proxy can present a
/// "real-looking" certificate for whatever host it is intercepting. Cached
/// in memory only (not persisted) - regenerated each time the app starts.
/// </summary>
public sealed class LeafCertificateFactory(RootCertificateAuthority ca)
{
    private readonly ConcurrentDictionary<string, X509Certificate2> _cache = new(StringComparer.OrdinalIgnoreCase);

    public X509Certificate2 GetOrCreate(string hostname) => _cache.GetOrAdd(hostname, Create);

    private X509Certificate2 Create(string hostname)
    {
        // RSA, matching the CA's key algorithm: CertificateRequest.Create(X509Certificate2, ...)
        // requires issuer and subject keys to be the same family unless you drop down to the
        // X509SignatureGenerator overload, which isn't worth the extra complexity here.
        using var key = RSA.Create(2048);
        var request = new CertificateRequest($"CN={hostname}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], critical: false)); // serverAuth

        var sanBuilder = new SubjectAlternativeNameBuilder();
        if (System.Net.IPAddress.TryParse(hostname, out var ip))
            sanBuilder.AddIpAddress(ip);
        else
            sanBuilder.AddDnsName(hostname);
        request.CertificateExtensions.Add(sanBuilder.Build());

        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddYears(1);
        byte[] serial = RandomNumberGenerator.GetBytes(16);

        using var signed = request.Create(ca.Certificate, notBefore, notAfter, serial);
        using var withKey = signed.CopyWithPrivateKey(key);

        // Round-trip through PKCS#12: SslStream on Windows needs the private
        // key to be backed by a CNG/CAPI key container, which CopyWithPrivateKey
        // alone doesn't always guarantee.
        return new X509Certificate2(
            withKey.Export(X509ContentType.Pfx), (string?)null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
    }

    public void Clear() => _cache.Clear();
}
