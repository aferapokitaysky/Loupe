using Loupe.Core;

/// <summary>
/// The storage root and the one-time move from the app's previous name. Getting this wrong
/// strands somebody's saved sessions and their installed root certificate, so it is tested
/// against a throwaway folder rather than trusted to read correctly.
/// </summary>
public static class StorageTests
{
    public static void Run()
    {
        T.Section("STORAGE ROOT & MIGRATION");

        // ---- Nothing there yet: the root is simply created.
        string fresh = Temp();
        string root = AppStorage.Resolve(fresh);
        T.Eq("root sits under the given base", Path.Combine(fresh, "Loupe"), root);
        T.Check("root is created", Directory.Exists(root));

        // ---- Old folder, no new one: everything moves across.
        string upgrading = Temp();
        string old = Path.Combine(upgrading, "NetSniffer");
        Directory.CreateDirectory(Path.Combine(old, "sessions", "20260916-abc"));
        File.WriteAllText(Path.Combine(old, "ignore.json"), """{"Processes":["powershell"],"Hosts":[]}""");
        File.WriteAllText(Path.Combine(old, "sessions", "20260916-abc", "session.json"), "{}");

        string moved = AppStorage.Resolve(upgrading);
        T.Check("the old folder is gone", !Directory.Exists(old));
        T.Check("the hide rules came across", File.Exists(Path.Combine(moved, "ignore.json")));
        T.Check("saved sessions came across",
            Directory.Exists(Path.Combine(moved, "sessions", "20260916-abc")));
        T.Eq("file contents survive the move", """{"Processes":["powershell"],"Hosts":[]}""",
            File.ReadAllText(Path.Combine(moved, "ignore.json")));

        // ---- Both exist: the new one wins and the old is left strictly alone. Merging two
        // diverged sets of sessions silently would be worse than ignoring the stale one.
        string both = Temp();
        string bothOld = Path.Combine(both, "NetSniffer");
        string bothNew = Path.Combine(both, "Loupe");
        Directory.CreateDirectory(bothOld);
        Directory.CreateDirectory(bothNew);
        File.WriteAllText(Path.Combine(bothOld, "ignore.json"), "old");
        File.WriteAllText(Path.Combine(bothNew, "ignore.json"), "new");

        string kept = AppStorage.Resolve(both);
        T.Eq("the existing folder is used as-is", "new", File.ReadAllText(Path.Combine(kept, "ignore.json")));
        T.Check("the stale folder is left untouched, not deleted", Directory.Exists(bothOld));
        T.Eq("and its contents are not overwritten", "old", File.ReadAllText(Path.Combine(bothOld, "ignore.json")));

        // ---- The proxy's root CA survives the file rename. If it didn't, a fresh CA would be
        // generated and every certificate the user had already chosen to trust would stop matching.
        string caDir = Temp();
        var original = new Loupe.Proxy.Ca.RootCertificateAuthority(caDir);
        string originalThumbprint = original.Thumbprint;

        File.Move(Path.Combine(caDir, "loupe-root.pfx"), Path.Combine(caDir, "netsniffer-root.pfx"));
        File.Move(Path.Combine(caDir, "loupe-root.pfx.key"), Path.Combine(caDir, "netsniffer-root.pfx.key"));

        var reopened = new Loupe.Proxy.Ca.RootCertificateAuthority(caDir);
        T.Eq("a CA saved under the old file names is picked up, not regenerated",
            originalThumbprint, reopened.Thumbprint);
        T.Check("and moved to the new names", File.Exists(Path.Combine(caDir, "loupe-root.pfx"))
                                              && !File.Exists(Path.Combine(caDir, "netsniffer-root.pfx")));

        // ---- PathTo composes under the root.
        T.Check("PathTo composes under the root",
            AppStorage.PathTo("sessions", "x").StartsWith(AppStorage.Root, StringComparison.Ordinal));

        foreach (string dir in new[] { fresh, upgrading, both, caDir })
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }

    private static string Temp()
    {
        string path = Path.Combine(Path.GetTempPath(), "loupe-storage-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }
}
