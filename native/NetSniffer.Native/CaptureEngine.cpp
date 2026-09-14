#include "CaptureEngine.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <pcap.h>

#include <atomic>
#include <mutex>
#include <string>
#include <unordered_map>

namespace {

// thread-local so concurrent callers (e.g. one thread listing devices while
// another runs a capture loop) don't stomp each other's error text.
thread_local std::string g_lastError;

void SetLastError(const std::string& message) {
    g_lastError = message;
}

struct OpenHandle {
    pcap_t* pcap = nullptr;
    std::atomic<bool> stopRequested{ false };
};

std::mutex g_handlesMutex;
std::unordered_map<uint64_t, OpenHandle*> g_handles;
std::atomic<uint64_t> g_nextHandleId{ 1 };

OpenHandle* FindHandle(uint64_t id) {
    std::lock_guard<std::mutex> lock(g_handlesMutex);
    auto it = g_handles.find(id);
    return it == g_handles.end() ? nullptr : it->second;
}

int64_t ToUnixMicros(const timeval& tv) {
    return static_cast<int64_t>(tv.tv_sec) * 1'000'000LL + tv.tv_usec;
}

// Per-callback state threaded through pcap_loop via the user pointer.
struct LoopContext {
    OpenHandle* handle;
    PacketCallback onPacket;
    void* userContext;
};

void PcapPacketHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* data) {
    auto* ctx = reinterpret_cast<LoopContext*>(user);
    if (ctx->handle->stopRequested.load(std::memory_order_relaxed)) {
        pcap_breakloop(ctx->handle->pcap);
        return;
    }
    ctx->onPacket(
        data,
        static_cast<int>(header->caplen),
        static_cast<int>(header->len),
        ToUnixMicros(header->ts),
        ctx->userContext);
}

} // namespace

extern "C" {

int __stdcall NsListDevices(NativeDeviceInfo* outDevices, int maxDevices) {
    char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
    pcap_if_t* allDevices = nullptr;

    if (pcap_findalldevs(&allDevices, errbuf) == -1) {
        SetLastError(std::string("pcap_findalldevs failed: ") + errbuf);
        return -1;
    }

    int total = 0;
    for (pcap_if_t* d = allDevices; d != nullptr; d = d->next) {
        if (total < maxDevices && outDevices != nullptr) {
            // Leak-and-forget by design: these strings live for the process
            // lifetime, which is fine for a handful of adapters and keeps the
            // marshalling contract simple (C# copies them out immediately).
            outDevices[total].name = _strdup(d->name ? d->name : "");
            outDevices[total].description = _strdup(d->description ? d->description : d->name);
        }
        total++;
    }

    pcap_freealldevs(allDevices);
    return total;
}

uint64_t __stdcall NsOpenDevice(const char* deviceName, int snapLen, int timeoutMs, bool promiscuous) {
    char errbuf[PCAP_ERRBUF_SIZE] = { 0 };

    pcap_t* handle = pcap_open_live(deviceName, snapLen, promiscuous ? 1 : 0, timeoutMs, errbuf);
    if (handle == nullptr) {
        SetLastError(std::string("pcap_open_live failed: ") + errbuf);
        return 0;
    }

    // We drive stop via pcap_breakloop from inside the handler, which needs
    // periodic timeouts to notice; non-blocking mode also avoids a select()
    // hang on adapters that never see traffic.
    pcap_setnonblock(handle, 0, errbuf);

    auto* entry = new OpenHandle();
    entry->pcap = handle;

    uint64_t id = g_nextHandleId.fetch_add(1);
    {
        std::lock_guard<std::mutex> lock(g_handlesMutex);
        g_handles[id] = entry;
    }
    return id;
}

int __stdcall NsSetFilter(uint64_t handleId, const char* filterExpression) {
    OpenHandle* entry = FindHandle(handleId);
    if (entry == nullptr) {
        SetLastError("NsSetFilter: unknown handle");
        return -1;
    }

    bpf_program program{};
    if (pcap_compile(entry->pcap, &program, filterExpression, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        SetLastError(std::string("pcap_compile failed: ") + pcap_geterr(entry->pcap));
        return -2;
    }

    int result = pcap_setfilter(entry->pcap, &program);
    pcap_freecode(&program);

    if (result < 0) {
        SetLastError(std::string("pcap_setfilter failed: ") + pcap_geterr(entry->pcap));
        return -3;
    }
    return 0;
}

int __stdcall NsRunCaptureLoop(
    uint64_t handleId,
    PacketCallback onPacket,
    CaptureStoppedCallback onStopped,
    void* userContext) {

    OpenHandle* entry = FindHandle(handleId);
    if (entry == nullptr) {
        SetLastError("NsRunCaptureLoop: unknown handle");
        if (onStopped) onStopped("unknown handle", userContext);
        return -1;
    }

    LoopContext ctx{ entry, onPacket, userContext };

    // pcap_loop(-1) = run until pcap_breakloop() or a fatal error.
    int rc = pcap_loop(entry->pcap, -1, PcapPacketHandler, reinterpret_cast<u_char*>(&ctx));

    std::string reason;
    if (rc == -1) {
        reason = std::string("capture error: ") + pcap_geterr(entry->pcap);
        SetLastError(reason);
    } else if (rc == -2) {
        reason.clear(); // clean pcap_breakloop() stop
    }

    if (onStopped) onStopped(reason.c_str(), userContext);
    return rc;
}

void __stdcall NsStopCapture(uint64_t handleId) {
    OpenHandle* entry = FindHandle(handleId);
    if (entry == nullptr) return;
    entry->stopRequested.store(true, std::memory_order_relaxed);
    pcap_breakloop(entry->pcap);
}

void __stdcall NsCloseDevice(uint64_t handleId) {
    OpenHandle* entry = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_handlesMutex);
        auto it = g_handles.find(handleId);
        if (it == g_handles.end()) return;
        entry = it->second;
        g_handles.erase(it);
    }
    if (entry->pcap) pcap_close(entry->pcap);
    delete entry;
}

const char* __stdcall NsGetLastError() {
    return g_lastError.c_str();
}

const char* __stdcall NsGetLibVersion() {
    return pcap_lib_version();
}

} // extern "C"
