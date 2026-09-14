using System.Diagnostics;
using System.Net.Http;
using System.Text.RegularExpressions;

namespace NetSniffer.Capture;

public enum NpcapInstallStage { Downloading, Launching }

/// <summary>
/// Fetches the official Npcap installer from npcap.com and runs it as a
/// normal child process, so the user doesn't have to leave the app to get
/// packet capture working. This does NOT vendor/bundle Npcap - its license
/// doesn't permit free redistribution outside the official installer - it
/// just downloads that same official installer at the user's request and
/// launches it; the installer still shows its own UI and its own EULA, and
/// Windows still shows its own elevation prompt (the installer's manifest
/// requests it, honored via UseShellExecute).
/// </summary>
public static class NpcapInstaller
{
    private const string DownloadPageUrl = "https://npcap.com/#download";
    private const string FallbackInstallerUrl = "https://npcap.com/dist/npcap-1.79.exe";

    /// <summary>Downloads the current Npcap installer and runs it, waiting for it to exit. Returns once the installer process exits, whatever the outcome - caller should re-check adapter availability afterwards.</summary>
    public static async Task RunInstallerAsync(IProgress<NpcapInstallStage>? progress = null, CancellationToken ct = default)
    {
        progress?.Report(NpcapInstallStage.Downloading);

        string installerUrl = await ResolveInstallerUrlAsync(ct).ConfigureAwait(false) ?? FallbackInstallerUrl;
        string tempPath = Path.Combine(Path.GetTempPath(), "netsniffer-npcap-installer.exe");

        using (var http = new HttpClient { Timeout = TimeSpan.FromMinutes(3) })
        using (var response = await http.GetAsync(installerUrl, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false))
        {
            response.EnsureSuccessStatusCode();
            await using var fileStream = File.Create(tempPath);
            await response.Content.CopyToAsync(fileStream, ct).ConfigureAwait(false);
        }

        progress?.Report(NpcapInstallStage.Launching);

        var startInfo = new ProcessStartInfo(tempPath) { UseShellExecute = true };
        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Could not start the Npcap installer process.");
        await process.WaitForExitAsync(ct).ConfigureAwait(false);
    }

    /// <summary>Scrapes the current installer filename off the official download page so this doesn't go stale when Npcap ships a new version. Falls back to a known-good pinned URL on any failure.</summary>
    private static async Task<string?> ResolveInstallerUrlAsync(CancellationToken ct)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
            string html = await http.GetStringAsync(DownloadPageUrl, ct).ConfigureAwait(false);
            var match = Regex.Match(html, @"dist/npcap-[\d.]+\.exe");
            return match.Success ? $"https://npcap.com/{match.Value}" : null;
        }
        catch
        {
            return null;
        }
    }
}
