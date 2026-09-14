# NetSniffer

A Windows network inspection toolkit with two modes in one app:

- **Packet Capture** - a Wireshark-lite sniffer: a native C++ capture engine
  on top of [Npcap](https://npcap.com/), a .NET 8 dissection/reassembly core.
- **HTTP(S) Proxy** - a Charles/Fiddler/Proxyman-style debugging proxy: a
  local root CA + TLS-intercepting relay that decrypts and displays
  request/response traffic from clients that are deliberately pointed at it.

Both live in one Fluent-styled (WPF-UI / Mica) desktop UI.

```
Packet Capture:
  Npcap (kernel driver)
    -> NetSniffer.Native   (C++, DynamicLibrary)   pcap_loop, BPF filters
    -> NetSniffer.Capture  (C#, P/Invoke)           adapter list, capture session
    -> NetSniffer.Core     (C#)                     Ethernet/IP/TCP/UDP/DNS/HTTP/TLS
                                                     dissection, TCP reassembly, .pcap I/O

HTTP(S) Proxy:
  NetSniffer.Proxy (C#)   local root CA + per-host leaf certs, CONNECT/TLS
                          interception, HTTP/1.1 relay with body capture

  -> NetSniffer.App       (C#, WPF + WPF-UI)   packet list / protocol tree /
                                                hex view, and a request list /
                                                headers / body inspector
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

Separately, the **HTTP(S) Proxy** page is a local MITM debugging proxy:

- Point a client (browser, curl, `mobile app on the same Wi-Fi`, ...) at
  `127.0.0.1:<port>` as its HTTP/HTTPS proxy - the "Enable System Proxy"
  button does this for the whole Windows user account via the standard
  per-user proxy setting, or configure just one app/device manually.
- Plain HTTP is relayed as-is. HTTPS is intercepted via `CONNECT`: the proxy
  terminates TLS towards the client using a certificate minted on the fly
  from **NetSniffer's own locally-generated root CA**, and opens a second,
  independently-verified TLS connection to the real server.
- Nothing decrypts until you click **"Install Root Certificate"**, which
  adds that CA to the current Windows user's trusted root store (no
  elevation needed - it's per-user) - Windows still shows its own trust
  prompt. "Export Certificate" saves the public cert as `.pem` to install
  manually elsewhere (e.g. a phone on the same network).
- The request list shows method/host/path/status/size/duration; selecting
  one shows request and response headers and body, with JSON pretty-printed
  and `gzip`/`deflate`/`br` bodies decompressed for display.

This only works on traffic that is deliberately routed through the proxy by
a client that has also chosen to trust the generated CA - i.e. **your own**
devices and apps, configured by **you**, for debugging. It cannot see or
decrypt anything else, and per-app certificate pinning will still (correctly)
reject NetSniffer's certificate unless you're specifically testing that app
and have disabled pinning in a debug build you control.

## What it deliberately does not do

Decrypting **other people's** HTTPS traffic passively (i.e. in the packet
capture path, without a proxy in the loop) is not something a well-behaved
tool should make easy - and with TLS 1.3's ephemeral key exchange it usually
isn't even possible without key material the endpoint chooses to share. If
that path gets TLS decryption later, it'll be via the same mechanism
Wireshark uses: pointing the app at an `SSLKEYLOGFILE` written by a client
you control (e.g. `set SSLKEYLOGFILE=...` before launching a browser), never
at key extraction or interception of third-party sessions - the same
"your own traffic only" boundary the proxy already enforces.

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

Packet capture:
- [ ] HTTP/2 (HPACK) dissection
- [ ] "Follow TCP Stream" view over `TcpStreamReassembler`'s buffers
- [ ] Optional TLS 1.2/1.3 decryption via `SSLKEYLOGFILE`, AES-GCM/ChaCha20
- [ ] `.pcapng` read/write
- [ ] Display filters (independent of the BPF capture filter)

HTTP(S) Proxy:
- [ ] HTTP/2 between proxy and client/server (currently pinned to HTTP/1.1
      via ALPN on both legs, which is what makes the relay tractable today)
- [ ] Breakpoints - pause a request/response to edit it before it continues
- [ ] Map Local / rewrite rules
- [ ] Export a captured exchange as a `curl` command
- [ ] Upstream connection reuse (currently one TCP+TLS connection per
      request to the real server - correct, but not the fastest)
- [ ] Per-app scoping on Windows (route only a chosen process's traffic)

## License

[MIT](LICENSE).
