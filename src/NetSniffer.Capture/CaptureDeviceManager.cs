using System.Runtime.InteropServices;

namespace NetSniffer.Capture;

public static class CaptureDeviceManager
{
    /// <summary>Enumerates capture-capable adapters. Requires the Npcap runtime to be installed.</summary>
    public static IReadOnlyList<CaptureDeviceInfo> ListDevices()
    {
        int count = NativeMethods.NsListDevices(null, 0);
        if (count < 0)
            throw new CaptureException($"Failed to enumerate adapters: {NativeMethods.GetLastError()}");
        if (count == 0)
            return [];

        var buffer = new NativeDeviceInfo[count];
        int actual = NativeMethods.NsListDevices(buffer, count);
        if (actual < 0)
            throw new CaptureException($"Failed to enumerate adapters: {NativeMethods.GetLastError()}");

        var result = new List<CaptureDeviceInfo>(Math.Min(actual, count));
        for (int i = 0; i < Math.Min(actual, count); i++)
        {
            string name = Marshal.PtrToStringUTF8(buffer[i].Name) ?? "";
            string description = Marshal.PtrToStringUTF8(buffer[i].Description) ?? name;
            result.Add(new CaptureDeviceInfo(name, description));
        }
        return result;
    }

    public static string NativeLibraryVersion => NativeMethods.GetLibVersion();
}

public sealed class CaptureException(string message) : Exception(message);
