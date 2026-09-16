using Loupe.Core.IO;
using Loupe.Core.Model;
using Loupe.Core.Sessions;

/// <summary>
/// Saved sessions: create, list, rename, delete - and the capture inside one stays an ordinary
/// .pcap that reads back byte for byte.
/// </summary>
public static class SessionTests
{
    public static void Run()
    {
        T.Section("SESSIONS");

        string root = Path.Combine(Path.GetTempPath(), "ns-sessions-" + Guid.NewGuid().ToString("N"));
        var store = new SessionStore(root);

        T.Eq("a store with no folder lists nothing", 0, store.List().Count);

        var first = store.Create("Morning capture", new SessionInfo
        {
            Id = "", Name = "", Created = default,
            Source = "Realtek Gaming 2.5GbE", PacketCount = 2, ByteCount = 102, HostCount = 1,
        });

        T.Check("create returns a usable folder", Directory.Exists(first.Directory));
        T.Eq("name kept", "Morning capture", first.Name);
        T.Check("id is unique-ish and path-safe",
            first.Id.Length > 10 && !first.Id.Contains(Path.DirectorySeparatorChar), first.Id);

        // The payload is written by the caller - here, a real capture file.
        var packets = new List<CapturedPacket>
        {
            new(1, DateTimeOffset.Now, B.Ethernet(0x0800, B.IPv4(6, "10.0.0.1", "10.0.0.2",
                B.Tcp(1, 2, 3, 4, 0x10, [7, 7, 7]))), 60),
            new(2, DateTimeOffset.Now.AddSeconds(1), B.Ethernet(0x0806, B.Arp("10.0.0.1", "10.0.0.9", 2)), 42),
        };
        string capturePath = store.PathTo(first, SessionStore.CaptureFileName);
        PcapFile.Write(capturePath, packets);

        var listed = store.List();
        T.Eq("one session listed", 1, listed.Count);
        T.Eq("listed with its packet count", 2L, listed[0].PacketCount);
        T.Eq("source recorded", "Realtek Gaming 2.5GbE", listed[0].Source);
        T.Check("size on disk measured", listed[0].SizeOnDisk > 0, listed[0].SizeOnDisk.ToString());
        T.Check("has packets, has no requests", listed[0].HasPackets && !listed[0].HasRequests);

        var reread = PcapFile.Read(capturePath).ToList();
        T.Eq("the capture inside is a plain readable .pcap", 2, reread.Count);
        T.Check("its bytes survive the round trip", reread[0].Data.SequenceEqual(packets[0].Data));

        // A second session, to check ordering and that they stay separate.
        Thread.Sleep(1100); // ids carry a whole-second timestamp
        var second = store.Create("Proxy run", new SessionInfo
        {
            Id = "", Name = "", Created = default, RequestCount = 12,
        });
        File.WriteAllText(store.PathTo(second, SessionStore.RequestsFileName), "[]");

        var both = store.List();
        T.Eq("both sessions listed", 2, both.Count);
        T.Eq("newest first", "Proxy run", both[0].Name);
        T.Check("requests-only session reports so", both[0].HasRequests && !both[0].HasPackets);

        var renamed = store.Rename(second.Id, "  Renamed run  ");
        T.Eq("rename trims", "Renamed run", renamed.Name);
        T.Eq("rename persists", "Renamed run", store.Get(second.Id)!.Name);
        T.Eq("renaming doesn't touch the other session", "Morning capture", store.Get(first.Id)!.Name);

        T.Eq("an empty name falls back rather than saving a blank", "Session", store.Rename(second.Id, "   ").Name);

        store.Delete(second.Id);
        T.Eq("delete removes exactly one", 1, store.List().Count);
        T.Check("and takes its folder with it", !Directory.Exists(second.Directory));
        T.Check("deleting a missing session is not an error", Safe(() => store.Delete("nope")));

        // A folder that isn't a session (or a half-written one) must not break listing.
        Directory.CreateDirectory(Path.Combine(root, "junk"));
        File.WriteAllText(Path.Combine(root, "junk", "session.json"), "{not json");
        T.Eq("unreadable folders are skipped", 1, store.List().Count);

        // Path traversal through the id must not escape the store.
        string sentinel = Path.Combine(root, "..", "ns-sentinel-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(sentinel);
        store.Delete("../" + Path.GetFileName(sentinel));
        store.Delete(".." + Path.DirectorySeparatorChar + Path.GetFileName(sentinel));
        T.Check("a traversing id deletes nothing outside the store", Directory.Exists(sentinel));

        try { Directory.Delete(sentinel, true); } catch { }
        try { Directory.Delete(root, true); } catch { }
    }

    private static bool Safe(Action action)
    {
        try { action(); return true; }
        catch { return false; }
    }
}
