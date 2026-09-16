<div align="center">

<img src="docs/screenshots/banner.png" alt="Loupe" width="100%">

<h3>See what your machine is actually saying.</h3>

A network inspector for Windows: a packet capture that names domains and the
programs behind them, and an HTTP(S) proxy that shows the requests in the clear.

<a href="https://github.com/aferapokitaysky/Loupe/actions/workflows/build.yml"><img alt="Build" src="https://img.shields.io/github/actions/workflow/status/aferapokitaysky/Loupe/build.yml?branch=main&style=flat-square&label=build"></a>
<a href="https://github.com/aferapokitaysky/Loupe/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/aferapokitaysky/Loupe?style=flat-square&color=3BE4FF"></a>
<img alt="Windows 10/11" src="https://img.shields.io/badge/Windows-10%20%7C%2011-1266F1?style=flat-square">
<img alt=".NET 8" src="https://img.shields.io/badge/.NET-8-1E9BFF?style=flat-square">
<img alt="C++ capture engine" src="https://img.shields.io/badge/capture-C%2B%2B%20%2B%20Npcap-3BE4FF?style=flat-square">
<img alt="MIT licence" src="https://img.shields.io/badge/licence-MIT-2A3441?style=flat-square">

**English** · [Русский](README.ru.md)

</div>

---

<div align="center">
<img src="docs/screenshots/packets.png" alt="Packet capture" width="900">
</div>

## What makes it different

Most sniffers hand you addresses. Loupe answers the two questions you actually
have while looking at them:

**Which site is this?** Names are learned from the traffic itself - A/AAAA
answers in DNS replies, the SNI in a TLS handshake, HTTP `Host` headers - and
used everywhere an address would otherwise appear. No reverse lookups are
issued: a PTR record names the hosting provider, not the site, and asking a
resolver about every address in a capture would leak the capture.

QUIC gets the same treatment. Its Initial packets are protected with keys
derived from the connection ID using a salt published in RFC 9001 - obfuscation
against middleboxes, not secrecy - so Loupe decrypts them and reads the
ClientHello. That is how HTTP/3 traffic, which is most of a modern browser's,
ends up named instead of sitting there as anonymous "UDP port 443".

**Which program is this?** The Windows TCP and UDP owner tables map a local port
to a process, so every packet and every proxied request carries the program that
sent it, with its icon. The loudest host on a machine stops being
`104.29.148.54` and becomes Discord.

## Packet capture

- Ethernet II, ARP, IPv4/IPv6, TCP/UDP, ICMP/ICMPv6, DNS, plaintext HTTP, TLS
  records, and QUIC with its Initial packets decrypted.
- Per-connection TCP stream reassembly, including out-of-order segments and
  32-bit sequence wraparound (RFC 1982).
- A hosts panel that rolls the capture up per domain - favicon, volume, packet
  count, protocols, and the programs involved - because at 50 000 packets in
  half a minute the grid itself is unreadable.
- Tick any number of hosts to narrow the list to them; search by domain,
  address, protocol, program or summary; hide the noisy ones for good.
- Runs of identical packets fold into one row with a `×420` badge. The folded
  frames are kept, so a saved `.pcap` still contains every packet.
- Reads and writes the classic `.pcap` format, so captures open in Wireshark
  and tcpdump.

## HTTP(S) proxy

<div align="center">
<img src="docs/screenshots/proxy.png" alt="HTTP(S) proxy" width="900">
</div>

A Charles/Fiddler/Proxyman-style debugging proxy, organised by domain: pick a
host, see its requests, open one for headers and body with JSON pretty-printed
and `gzip`/`deflate`/`br` decompressed.

Three things have to be true before a browser shows up here, and the page says
which of them are done:

1. **Start the proxy** - it listens on `127.0.0.1:8080` by default.
2. **Install the certificate** - adds Loupe's locally generated root CA to your
   own Windows user store (no elevation; Windows shows its own prompt).
   Nothing is decrypted before this.
3. **Send the system through it** - one button sets the per-user Windows proxy,
   or point a single app at the address yourself.

Loupe puts the setting back when the proxy stops, including on exit: leaving
Windows aimed at a proxy that is no longer listening takes the machine offline.

**Beyond the browser.** Plenty of programs ignore the Windows proxy setting.
The optional transparent port takes raw connections that carry no `CONNECT`
line at all - the destination is read from the TLS SNI, or the `Host` header for
plaintext - so anything you can redirect (its own config, a hosts entry, a
firewall rule) is intercepted the same way.

Upstream TLS is verified normally. The client can no longer check the server
itself, so the proxy doing it is the only thing left.

## Sessions

<div align="center">
<img src="docs/screenshots/sessions.png" alt="Saved sessions" width="900">
</div>

Save what is on screen as a named session and come back to it: one folder per
session holding an ordinary `.pcap` - it opens in Wireshark, nothing here is
needed to read it back - plus the proxy's requests with their bodies. Rename,
reveal in Explorer, export, delete (which asks first, and names what it is about
to remove).

Export goes out in the formats other tools read: **HAR 1.2** for requests, which
Proxyman, Charles and Chrome DevTools all open, and the raw `.pcap` for captures.

## Getting it running

**Download**

Every tagged version is built and published by CI on the
[Releases](../../releases/latest) page:

| File | For |
|---|---|
| `Loupe-<version>-win-x64.zip` | Any Windows 10/11 x64 machine - unpack and run `Loupe.exe` |
| `Loupe-<version>-win-x64-net8.zip` | Machines that already have the [.NET 8 Desktop Runtime](https://dotnet.microsoft.com/download/dotnet/8.0) - a much smaller download |

`SHA256SUMS.txt` next to them lists the checksums. Loupe asks for
administrator rights on start: opening a network adapter for capture requires it.

**Requirements**

- Windows 10/11.
- [Npcap](https://npcap.com/#download) - the capture driver. If it is missing,
  Loupe offers to fetch the official installer on startup and runs it as a
  normal child process; you still see Npcap's own wizard and accept Npcap's own
  licence. It is never bundled (its licence does not permit redistribution) and
  never installed silently.
- To build: [.NET 8 SDK](https://dotnet.microsoft.com/download), Visual Studio
  2022 or the Build Tools with the C++ workload, and the
  [Npcap SDK](https://npcap.com/#download) extracted to `third_party/npcap-sdk/`
  or pointed at by `NPCAP_SDK_DIR`.

**Build**

```bash
build.cmd
```

One command from any shell: it finds MSBuild through `vswhere`, builds the
native capture DLL, builds the managed projects and runs the tests. The result
is `src\Loupe.App\bin\Release\net8.0-windows\Loupe.exe`.

`dotnet build Loupe.sln` does *not* work - the `dotnet` CLI cannot evaluate a
`.vcxproj`, which is exactly why `build.cmd` exists.

**Tests**

```bash
dotnet run --project tests\Loupe.Tests -c Release
```

The checks need neither Npcap nor a network: the dissector runs on
hand-built frames, the proxy against a byte-exact local origin, QUIC decryption
against the sample packet in RFC 9001 Appendix A.2, and process attribution
against the real Windows socket tables over loopback.

## Keyboard

| | |
|---|---|
| `Ctrl` + `S` | save the current page as a session |
| `Ctrl` + `F` | jump to the search box |
| `Ctrl` + `L` | clear the list |
| `F5` | refresh the session library |

The interface speaks 12 languages, switchable live from the flag at the bottom
of the nav rail.

## Where things are kept

`%LOCALAPPDATA%\Loupe` - saved sessions, the hide list, cached favicons, the
proxy's root certificate and the language choice.

## What it deliberately does not do

Decrypting **other people's** HTTPS passively - in the capture path, with no
proxy in the loop - is not something a well-behaved tool should make easy, and
under TLS 1.3 it usually isn't possible without key material the endpoint
chooses to share. If that ever lands here it will be the way Wireshark does it:
an `SSLKEYLOGFILE` written by a client you control. Never key extraction, never
third-party sessions.

The proxy only ever sees traffic that is deliberately routed through it by a
client that has also chosen to trust the generated CA - your own devices and
apps, configured by you. Certificate pinning will still, correctly, refuse it.

## Architecture

```
Npcap (kernel driver)
  └─ Loupe.Native    C++  pcap_loop, BPF filters, flat extern "C" ABI
      └─ Loupe.Capture  C#   adapters, capture session, socket→process tables
          └─ Loupe.Core     C#   dissection, TCP reassembly, naming, .pcap, sessions

Loupe.Proxy   C#   root CA, per-host leaf certs, CONNECT + transparent
                   interception, HTTP/1.1 relay, HAR export

Loupe.App     C#   WPF + WPF-UI
```

The native layer exists so BPF filtering and the capture loop run with no
managed overhead per packet - the callback crosses into C# only once a frame is
ready. Everything above it is ordinary C#.

## Licence

MIT. See [LICENSE](LICENSE).
