using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace NetSniffer.Proxy;

/// <summary>
/// Toggles the current Windows user's system-wide HTTP/HTTPS proxy setting -
/// the same per-user registry values the Settings app's "Manual proxy setup"
/// writes. This is what routes browsers/apps through NetSniffer's proxy
/// without configuring each one individually. Entirely opt-in and reversible
/// from the same place; nothing here runs unless the user clicks the button
/// that calls it.
/// </summary>
public static class WindowsProxySettings
{
    private const string InternetSettingsKey = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    [DllImport("wininet.dll", SetLastError = true)]
    private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);

    private const int InternetOptionSettingsChanged = 39;
    private const int InternetOptionRefresh = 37;

    public static bool IsEnabled()
    {
        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey);
        return (key?.GetValue("ProxyEnable") as int?) == 1;
    }

    public static string? CurrentProxyServer()
    {
        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey);
        return key?.GetValue("ProxyServer") as string;
    }

    public static void Enable(string host, int port)
    {
        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true)
            ?? throw new InvalidOperationException("Could not open Internet Settings registry key.");

        key.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
        key.SetValue("ProxyServer", $"{host}:{port}", RegistryValueKind.String);
        // Loopback/local addresses still need to bypass, or the proxy can't reach itself for local dev servers.
        key.SetValue("ProxyOverride", "localhost;127.0.0.1;<local>", RegistryValueKind.String);

        NotifySystem();
    }

    public static void Disable()
    {
        using var key = Registry.CurrentUser.OpenSubKey(InternetSettingsKey, writable: true)
            ?? throw new InvalidOperationException("Could not open Internet Settings registry key.");

        key.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
        NotifySystem();
    }

    private static void NotifySystem()
    {
        InternetSetOption(IntPtr.Zero, InternetOptionSettingsChanged, IntPtr.Zero, 0);
        InternetSetOption(IntPtr.Zero, InternetOptionRefresh, IntPtr.Zero, 0);
    }
}
