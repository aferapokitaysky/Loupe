using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Loupe.Proxy.Ca;

/// <summary>
/// The root certificate: what it says about itself, and what happens when it is replaced.
/// Nothing here touches the machine's trust store - installing is the user's decision, and a
/// test suite that added roots to the machine it runs on would be doing exactly what this app
/// promises never to do quietly.
/// </summary>
public static class CertificateTests
{
    public static void Run()
    {
        T.Section("ROOT CERTIFICATE");

        string dir = Path.Combine(Path.GetTempPath(), "loupe-ca-" + Guid.NewGuid().ToString("N"));
        try
        {
            var ca = new RootCertificateAuthority(dir);
            string first = ca.Thumbprint;

            T.Check("a new CA is named after this app", ca.CommonName.Contains("Loupe"), ca.CommonName);
            T.Check("a new CA is not flagged as carrying the old name", !ca.HasLegacyName);
            T.Check("it is a CA", ca.Certificate.Extensions
                .OfType<X509BasicConstraintsExtension>()
                .Any(e => e.CertificateAuthority));
            T.Check("it can sign", ca.Certificate.Extensions
                .OfType<X509KeyUsageExtension>()
                .Any(e => e.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign)));
            T.Check("it keeps its private key", ca.Certificate.HasPrivateKey);

            // The single most important property of a root this app asks people to trust: it may
            // vouch for TLS servers and for nothing else. Without this, a root in the store is
            // trusted for signing code Windows will run, and for signing mail.
            var eku = ca.Certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
            T.Check("the CA names a purpose at all", eku is not null);
            T.Check("the CA is limited to server authentication",
                eku is not null && eku.EnhancedKeyUsages.Cast<Oid>().All(o => o.Value == "1.3.6.1.5.5.7.3.1"),
                string.Join(",", eku?.EnhancedKeyUsages.Cast<Oid>().Select(o => o.Value) ?? []));
            T.Check("a restricted CA is not flagged for replacement", !ca.IsUnrestricted);
            T.Check("the CA cannot sign anything but certificates and revocation lists",
                ca.Certificate.Extensions.OfType<X509KeyUsageExtension>()
                    .All(u => u.KeyUsages == (X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign)));
            T.Check("it is persisted", File.Exists(Path.Combine(dir, "loupe-root.pfx")));

            // Reopening the same folder must hand back the same identity: the user installed
            // that thumbprint, and a second instance quietly minting its own would break trust.
            var reopened = new RootCertificateAuthority(dir);
            T.Eq("reopening the same folder keeps the same certificate", first, reopened.Thumbprint);

            ca.Regenerate();
            T.Check("regenerating produces a different certificate", ca.Thumbprint != first, ca.Thumbprint);
            T.Check("the replacement is still named after this app", ca.CommonName.Contains("Loupe"));
            T.Check("the replacement can still sign", ca.Certificate.HasPrivateKey);

            var afterRegenerate = new RootCertificateAuthority(dir);
            T.Eq("the replacement is the one now on disk", ca.Thumbprint, afterRegenerate.Thumbprint);

            // A CA left over from before the rename is adopted rather than replaced: the user
            // installed *that* certificate, and generating a new one would silently break
            // interception until they noticed and reinstalled.
            string legacyDir = Path.Combine(Path.GetTempPath(), "loupe-ca-legacy-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(legacyDir);
            File.Copy(Path.Combine(dir, "loupe-root.pfx"), Path.Combine(legacyDir, "netsniffer-root.pfx"));
            File.Copy(Path.Combine(dir, "loupe-root.pfx.key"), Path.Combine(legacyDir, "netsniffer-root.pfx.key"));

            var adopted = new RootCertificateAuthority(legacyDir);
            T.Eq("a CA from before the rename is adopted, not replaced", ca.Thumbprint, adopted.Thumbprint);
            T.Check("the adopted files are moved to the current names",
                File.Exists(Path.Combine(legacyDir, "loupe-root.pfx"))
                && !File.Exists(Path.Combine(legacyDir, "netsniffer-root.pfx")));

            try { Directory.Delete(legacyDir, true); } catch { }
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch { }
        }
    }
}
