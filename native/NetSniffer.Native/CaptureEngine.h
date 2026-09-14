#pragma once
#include <cstdint>

// C ABI exported by NetSniffer.Native.dll and consumed from C# via P/Invoke.
// Kept intentionally flat (no C++ types crossing the boundary) so the
// managed side never has to know about pcap_t, struct layouts, etc.

extern "C" {

// One network adapter, as reported by Npcap.
struct NativeDeviceInfo {
    const char* name;         // pcap device name, e.g. \Device\NPF_{GUID}
    const char* description;  // human readable adapter description
};

// Called once per captured frame, on the capture thread.
// data/length describe the raw frame (Ethernet header included) and are
// only valid for the duration of the call - copy what you need.
typedef void (__stdcall *PacketCallback)(
    const uint8_t* data,
    int length,
    int originalLength,
    int64_t timestampUnixMicros,
    void* userContext);

// Called once when the capture loop exits, with a human readable reason
// (empty string on a clean StopCapture()).
typedef void (__stdcall *CaptureStoppedCallback)(const char* reason, void* userContext);

// Populates outDevices with up to maxDevices entries and returns the total
// device count found (which may be larger than maxDevices - call again
// with a bigger buffer if so). Returns -1 on error; call NsGetLastError().
__declspec(dllexport) int __stdcall NsListDevices(NativeDeviceInfo* outDevices, int maxDevices);

// Opens a live capture handle on the named device. snapLen is the max
// bytes captured per frame, timeoutMs is the pcap read timeout.
// Returns an opaque handle (> 0) or 0 on failure.
__declspec(dllexport) uint64_t __stdcall NsOpenDevice(
    const char* deviceName,
    int snapLen,
    int timeoutMs,
    bool promiscuous);

// Compiles and installs a BPF filter expression (same syntax as tcpdump /
// Wireshark capture filters, e.g. "tcp port 443"). Returns 0 on success.
__declspec(dllexport) int __stdcall NsSetFilter(uint64_t handle, const char* filterExpression);

// Blocks the calling thread, invoking onPacket for every captured frame,
// until NsStopCapture() is called from another thread or a fatal capture
// error occurs. Intended to be run on a dedicated background thread from C#.
__declspec(dllexport) int __stdcall NsRunCaptureLoop(
    uint64_t handle,
    PacketCallback onPacket,
    CaptureStoppedCallback onStopped,
    void* userContext);

// Signals a running NsRunCaptureLoop() on this handle to return.
__declspec(dllexport) void __stdcall NsStopCapture(uint64_t handle);

// Releases the capture handle. Do not call while NsRunCaptureLoop is active.
__declspec(dllexport) void __stdcall NsCloseDevice(uint64_t handle);

// Returns the last error message for the calling thread (empty if none).
__declspec(dllexport) const char* __stdcall NsGetLastError();

// Returns the Npcap/libpcap version string the engine linked against.
__declspec(dllexport) const char* __stdcall NsGetLibVersion();

}
