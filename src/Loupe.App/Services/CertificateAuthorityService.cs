using Loupe.Core;
using Loupe.Proxy.Ca;

namespace Loupe.App.Services;

/// <summary>
/// The one root certificate authority this app uses, shared by the proxy page and the settings
/// page.
///
/// One instance, deliberately: the proxy signs with it while settings can replace it, and two
/// objects reading the same files would disagree the moment one of them did - the proxy would
/// keep signing with a key whose root the user had just removed.
/// </summary>
public static class CertificateAuthorityService
{
    // Explicit path rather than letting the CA compute its own: it must land under the same
    // storage root the rest of the app migrates, whatever order things happen to start in.
    public static RootCertificateAuthority Instance { get; } = new(AppStorage.PathTo("ca"));
}
