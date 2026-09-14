# NetSniffer

A Wireshark-lite packet sniffer for Windows: a native C++ capture engine on
top of [Npcap](https://npcap.com/), a .NET 8 dissection/reassembly core, and
a Fluent-styled WPF desktop UI.

```
Npcap (kernel driver)
  -> NetSniffer.Native   (C++, DynamicLibrary)   pcap_loop, BPF filters
  -> NetSniffer.Capture  (C#, P/Invoke)           adapter list, capture session
  -> NetSniffer.Core     (C#)                     Ethernet/IP/TCP/UDP/DNS/HTTP/TLS
                                                   dissection, TCP reassembly, .pcap I/O
  -> NetSniffer.App      (C#, WPF + WPF-UI)       packet list, protocol tree, hex view
```

## Why a native capture layer

Npcap/libpcap is a C API. `NetSniffer.Native` is a thin `DynamicLibrary`
wrapping `pcap_findalldevs` / `pcap_open_live` / `pcap_compile` /
`pcap_loop` behind a flat, `extern "C"` ABI (see
[`CaptureEngine.h`](native/NetSniffer.Native/CaptureEngine.h)), so packet
capture and BPF filtering happen with no managed overhead per packet - the
callback only crosses into C# once a frame is ready. Everything above that
(protocol dissection, TCP stream reassembly, the UI) is regular C#.

## What it does today

- Lists capture-capable adapters and starts/stops a live capture with an
  optional BPF filter (`tcp port 443`, `udp`, `host 1.2.3.4`, ...).
- Dissects Ethernet II, ARP, IPv4/IPv6, TCP/UDP, ICMP/ICMPv6.
- Recognizes DNS queries/responses, plaintext HTTP/1.x request/response
  lines, and TLS record headers - including reading the **ClientHello SNI**
  and negotiated cipher suite straight out of the handshake, which is sent
  in the clear even under TLS 1.3. It does **not** decrypt Application Data.
- Reassembles each TCP connection's byte stream per direction (out-of-order
  segment buffering, sequence-number wraparound handled per RFC 1982) as a
  foundation for a future "Follow TCP Stream" view.
- Reads/writes the classic `.pcap` file format, so captures interoperate
  with Wireshark/tcpdump.
- A dark, Fluent-styled (WPF-UI / Mica) UI: adapter + filter toolbar, a
  virtualized packet list color-coded by protocol, a protocol detail tree,
  and a hex/ASCII byte view - laid out the way Wireshark's three panes are.

## What it deliberately does not do

Decrypting **other people's** HTTPS traffic passively is not something a
well-behaved tool should make easy - and with TLS 1.3's ephemeral key
exchange it usually isn't even possible without key material the endpoint
chooses to share. If TLS decryption gets added later, it'll be via the same
mechanism Wireshark uses: pointing the app at an `SSLKEYLOGFILE` written by
a client you control (e.g. `set SSLKEYLOGFILE=...` before launching a
browser), never at key extraction or interception of third-party sessions.

## Building

**Requirements:**
- Windows 10/11, Visual Studio 2022 (Desktop development with C++ workload,
  .NET desktop development workload) or the equivalent Build Tools.
- [.NET 8 SDK](https://dotnet.microsoft.com/download).
- [Npcap](https://npcap.com/#download) **runtime** installed (plain
  installer - needed to actually capture at run time).
- [Npcap SDK](https://npcap.com/#download) (needed only to *build*
  `NetSniffer.Native` - provides `pcap.h` and `wpcap.lib`). It has its own
  license that doesn't permit redistribution, so it isn't vendored here.
  Either:
  - extract it to `third_party/npcap-sdk/` at the repo root (gitignored), or
  - set an `NPCAP_SDK_DIR` environment variable pointing at the extracted
    SDK folder.

**Build:**

Open `NetSniffer.sln` in Visual Studio and build (Debug/Release, x64) - it
builds the native project and all three C# projects together and copies
`NetSniffer.Native.dll` next to `NetSniffer.exe` automatically.

From the command line, build the native project and the C# app separately -
`NetSniffer.Native.vcxproj` needs real MSBuild from a **Developer Command
Prompt for VS 2022** (the `dotnet` CLI can't evaluate `.vcxproj` files, and
Build Tools' MSBuild can't always resolve SDK-style `.csproj`s side by side
with it in one `.sln` build), while the C# side builds cleanly with the
`dotnet` CLI once the native DLL exists:

```bash
msbuild native\NetSniffer.Native\NetSniffer.Native.vcxproj /p:Configuration=Release /p:Platform=x64 /p:SolutionDir=%CD%\
dotnet build src\NetSniffer.App\NetSniffer.App.csproj -c Release
```

## Running

Launch `NetSniffer.exe`. It requests administrator rights on startup (via
its app manifest) because Npcap restricts raw capture to elevated processes
by default. Pick an adapter, optionally type a BPF filter, hit Start.

## Roadmap

- [ ] HTTP/2 (HPACK) dissection
- [ ] "Follow TCP Stream" view over `TcpStreamReassembler`'s buffers
- [ ] Optional TLS 1.2/1.3 decryption via `SSLKEYLOGFILE`, AES-GCM/ChaCha20
- [ ] `.pcapng` read/write
- [ ] Display filters (independent of the BPF capture filter)

## License

[MIT](LICENSE).
