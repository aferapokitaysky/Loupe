using System.Diagnostics;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Loupe.App.Localization;
using Loupe.App.Services;
using Loupe.Core;

namespace Loupe.App.ViewModels;

/// <summary>
/// The settings page: the few choices worth keeping, what Loupe stores on this machine, and
/// the way to get rid of any of it. Everything here writes through immediately - a settings
/// page with an Apply button is a page that can be left in a state that isn't true.
/// </summary>
public sealed partial class SettingsViewModel : ObservableObject
{
    public SettingsViewModel()
    {
        _fetchFavicons = AppSettings.Current.FetchFavicons;
        _startCaptureOnLaunch = AppSettings.Current.StartCaptureOnLaunch;
        _maxPackets = PacketLimits.FirstOrDefault(l => l.Value == AppSettings.Current.MaxPackets) ?? PacketLimits[1];
        RefreshUsage();
    }

    // ---------------------------------------------------------------- privacy

    /// <summary>
    /// Site icons are fetched from the sites themselves, never through a third-party favicon
    /// service - one of those would receive the list of every domain in your capture. This
    /// switch turns even that off, leaving Loupe purely a listener.
    /// </summary>
    [ObservableProperty] private bool _fetchFavicons;

    partial void OnFetchFaviconsChanged(bool value) => AppSettings.Update(s => s.FetchFavicons = value);

    public bool HasHiddenRules => !IgnoreListStore.Rules.IsEmpty;

    public string HiddenRulesText => IgnoreListStore.Rules.IsEmpty
        ? Loc.Get("Set_Hidden_None")
        : IgnoreListStore.Rules.Describe();

    [RelayCommand]
    private void ResetHidden()
    {
        IgnoreListStore.Rules.Clear();
        OnPropertyChanged(nameof(HasHiddenRules));
        OnPropertyChanged(nameof(HiddenRulesText));
    }

    // ---------------------------------------------------------------- capture

    /// <summary>Row caps worth offering. Every row pins its frame, so this is memory.</summary>
    public IReadOnlyList<PacketLimit> PacketLimits { get; } =
    [
        new(10_000, "Set_Rows_10k"),
        new(50_000, "Set_Rows_50k"),
        new(200_000, "Set_Rows_200k"),
    ];

    [ObservableProperty] private PacketLimit _maxPackets;

    partial void OnMaxPacketsChanged(PacketLimit value) => AppSettings.Update(s => s.MaxPackets = value.Value);

    [ObservableProperty] private bool _startCaptureOnLaunch;

    partial void OnStartCaptureOnLaunchChanged(bool value) => AppSettings.Update(s => s.StartCaptureOnLaunch = value);

    // ---------------------------------------------------------------- data on this machine

    public string DataFolder => AppStorage.Root;

    [ObservableProperty] private string _usageText = "";

    /// <summary>Adds up what is on disk, so "clear this" is an informed decision rather than a leap.</summary>
    [RelayCommand]
    private void RefreshUsage()
    {
        long sessions = DirectorySize(AppStorage.PathTo("sessions"));
        long favicons = DirectorySize(AppStorage.PathTo("favicons"));
        UsageText = Loc.Format("Set_Usage", Format(sessions), Format(favicons));
    }

    [RelayCommand]
    private void OpenDataFolder()
    {
        try
        {
            Directory.CreateDirectory(AppStorage.Root);
            Process.Start(new ProcessStartInfo(AppStorage.Root) { UseShellExecute = true });
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or IOException or UnauthorizedAccessException)
        {
            // Nothing worth interrupting for: the path is on screen and can be copied.
        }
    }

    [RelayCommand]
    private void ClearFaviconCache()
    {
        try
        {
            var cache = new DirectoryInfo(AppStorage.PathTo("favicons"));
            if (cache.Exists) cache.Delete(recursive: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            // An icon file held open by this very session; the rest are gone either way.
        }

        RefreshUsage();
        ToastService.Show(Loc.Get("Set_IconsCleared"), "Broom24");
    }

    [RelayCommand]
    private void OpenProject()
    {
        try
        {
            Process.Start(new ProcessStartInfo("https://github.com/aferapokitaysky/Loupe") { UseShellExecute = true });
        }
        catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            // No browser association; the URL is printed on the page anyway.
        }
    }

    /// <summary>
    /// The proxy's own root certificate - the identity everything it decrypts is trusted
    /// through. Shown here rather than on the proxy page: it is a thing you check, not a thing
    /// you use.
    /// </summary>
    public string CaThumbprint => SafeCa(ca => ca.Thumbprint);

    public string CaName => SafeCa(ca => ca.CommonName);

    /// <summary>True while the certificate still carries the name from before the rename.</summary>
    public bool CaHasLegacyName => SafeCa(ca => ca.HasLegacyName ? "yes" : "") == "yes";

    /// <summary>
    /// Replaces the root certificate with a fresh one under the current name, and clears out
    /// the roots left behind by earlier ones.
    ///
    /// Asked for rather than done quietly: everything signed by the old key stops working the
    /// moment its root leaves the store, browsers hold the old one until they are restarted,
    /// and Windows asks its own question before trusting the new one.
    /// </summary>
    [RelayCommand]
    private void RegenerateCertificate()
    {
        var answer = System.Windows.MessageBox.Show(
            Loc.Get("Set_Ca_RegenerateConfirm"),
            Loc.Get("Set_Ca_Regenerate"),
            System.Windows.MessageBoxButton.YesNo,
            System.Windows.MessageBoxImage.Warning,
            System.Windows.MessageBoxResult.No);

        if (answer != System.Windows.MessageBoxResult.Yes) return;

        try
        {
            var ca = CertificateAuthorityService.Instance;
            ca.Regenerate();
            int removed = ca.RemoveStaleRoots();
            ca.InstallForCurrentUser();

            OnPropertyChanged(nameof(CaThumbprint));
            OnPropertyChanged(nameof(CaName));
            OnPropertyChanged(nameof(CaHasLegacyName));
            ToastService.Show(Loc.Format("Set_Ca_Regenerated", removed), "ShieldCheckmark24");
        }
        catch (Exception ex) when (ex is System.Security.Cryptography.CryptographicException
                                       or UnauthorizedAccessException or IOException)
        {
            ToastService.Show(Loc.Format("Proxy_Status_CertInstallFailed", ex.Message), "Warning24");
        }
    }

    private static string SafeCa(Func<Loupe.Proxy.Ca.RootCertificateAuthority, string> read)
    {
        try
        {
            return read(CertificateAuthorityService.Instance);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException
                                      or System.Security.Cryptography.CryptographicException)
        {
            return "";
        }
    }

    public string VersionText => Loc.Format("Set_Version",
        System.Reflection.Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "1.0",
        Environment.Version.ToString(3));

    private static long DirectorySize(string path)
    {
        try
        {
            var directory = new DirectoryInfo(path);
            return directory.Exists
                ? directory.EnumerateFiles("*", SearchOption.AllDirectories).Sum(f => f.Length)
                : 0;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return 0;
        }
    }

    private static string Format(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:F1} KB",
        < 1024L * 1024 * 1024 => $"{bytes / (1024.0 * 1024):F1} MB",
        _ => $"{bytes / (1024.0 * 1024 * 1024):F2} GB",
    };
}

/// <summary>One choice in the "rows kept" picker.</summary>
public sealed record PacketLimit(int Value, string LabelKey)
{
    public string Label => Loc.Get(LabelKey);

    public bool Equals(PacketLimit? other) => other is not null && Value == other.Value;

    public override int GetHashCode() => Value;

    public override string ToString() => Label;
}
