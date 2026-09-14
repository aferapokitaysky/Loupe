using System.Runtime.InteropServices;

namespace NetSniffer.Capture;

[StructLayout(LayoutKind.Sequential)]
internal struct NativeDeviceInfo
{
    public IntPtr Name;
    public IntPtr Description;
}

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
internal delegate void PacketCallback(
    IntPtr data,
    int length,
    int originalLength,
    long timestampUnixMicros,
    IntPtr userContext);

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
internal delegate void CaptureStoppedCallback(IntPtr reason, IntPtr userContext);

/// <summary>P/Invoke surface for NetSniffer.Native.dll (see native/NetSniffer.Native/CaptureEngine.h).</summary>
internal static partial class NativeMethods
{
    private const string Lib = "NetSniffer.Native.dll";

    [LibraryImport(Lib, EntryPoint = "NsListDevices")]
    internal static partial int NsListDevices(
        [MarshalAs(UnmanagedType.LPArray)] NativeDeviceInfo[]? outDevices, int maxDevices);

    [LibraryImport(Lib, EntryPoint = "NsOpenDevice", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial ulong NsOpenDevice(string deviceName, int snapLen, int timeoutMs,
        [MarshalAs(UnmanagedType.I1)] bool promiscuous);

    [LibraryImport(Lib, EntryPoint = "NsSetFilter", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int NsSetFilter(ulong handle, string filterExpression);

    [DllImport(Lib, EntryPoint = "NsRunCaptureLoop", CallingConvention = CallingConvention.StdCall)]
    internal static extern int NsRunCaptureLoop(
        ulong handle, PacketCallback onPacket, CaptureStoppedCallback onStopped, IntPtr userContext);

    [LibraryImport(Lib, EntryPoint = "NsStopCapture")]
    internal static partial void NsStopCapture(ulong handle);

    [LibraryImport(Lib, EntryPoint = "NsCloseDevice")]
    internal static partial void NsCloseDevice(ulong handle);

    [LibraryImport(Lib, EntryPoint = "NsGetLastError")]
    internal static partial IntPtr NsGetLastError();

    [LibraryImport(Lib, EntryPoint = "NsGetLibVersion")]
    internal static partial IntPtr NsGetLibVersion();

    internal static string GetLastError() => Marshal.PtrToStringUTF8(NsGetLastError()) ?? "";
    internal static string GetLibVersion() => Marshal.PtrToStringUTF8(NsGetLibVersion()) ?? "";
}
