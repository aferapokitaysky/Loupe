namespace NetSniffer.Core.Naming;

/// <summary>
/// What the user asked not to see: noisy programs and hosts. One chatty app (an updater, a
/// game launcher, a script in a loop) can bury everything else on screen; hiding it is the
/// difference between reading a capture and scrolling past one.
///
/// Rules only hide - they never stop anything from being captured, counted or saved.
/// </summary>
public sealed class IgnoreRules
{
    private readonly HashSet<string> _processes = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _hosts = new(StringComparer.OrdinalIgnoreCase);

    public event EventHandler? Changed;

    public IReadOnlyCollection<string> Processes => _processes;
    public IReadOnlyCollection<string> Hosts => _hosts;

    public bool IsEmpty => _processes.Count == 0 && _hosts.Count == 0;

    public bool AddProcess(string? name) => Mutate(!string.IsNullOrWhiteSpace(name) && _processes.Add(name.Trim()));

    /// <summary>A domain ("github.com", which also covers its subdomains) or a literal address.</summary>
    public bool AddHost(string? host) => Mutate(!string.IsNullOrWhiteSpace(host) && _hosts.Add(Normalize(host)));

    public bool Remove(string entry) => Mutate(_processes.Remove(entry) | _hosts.Remove(Normalize(entry)));

    public void Clear()
    {
        bool had = !IsEmpty;
        _processes.Clear();
        _hosts.Clear();
        Mutate(had);
    }

    /// <summary>Replaces the rules wholesale, e.g. from saved settings, without raising per entry.</summary>
    public void Load(IEnumerable<string>? processes, IEnumerable<string>? hosts)
    {
        _processes.Clear();
        _hosts.Clear();
        foreach (var p in processes ?? []) if (!string.IsNullOrWhiteSpace(p)) _processes.Add(p.Trim());
        foreach (var h in hosts ?? []) if (!string.IsNullOrWhiteSpace(h)) _hosts.Add(Normalize(h));
        Changed?.Invoke(this, EventArgs.Empty);
    }

    public bool IsProcessIgnored(string? name) => name is not null && _processes.Contains(name);

    /// <summary>
    /// True when <paramref name="host"/> - a domain or an address - is hidden, either exactly or
    /// as a subdomain of a hidden domain. Suffix matching is what makes hiding a site work at
    /// all: its traffic is spread over names like "c-waw06-c83c7b4d.discord.media".
    /// </summary>
    public bool IsHostIgnored(string? host)
    {
        if (string.IsNullOrEmpty(host) || _hosts.Count == 0) return false;

        string candidate = Normalize(host);
        if (_hosts.Contains(candidate)) return true;
        if (System.Net.IPAddress.TryParse(candidate, out _)) return false; // "82.121.4" is no parent of an IP

        // Walk up the labels: a.b.example.com -> b.example.com -> example.com. Addresses have
        // no parent domain, and stopping before the last label keeps "com" from ever matching.
        int dot = candidate.IndexOf('.');
        while (dot > 0 && candidate.IndexOf('.', dot + 1) > 0)
        {
            candidate = candidate[(dot + 1)..];
            if (_hosts.Contains(candidate)) return true;
            dot = candidate.IndexOf('.');
        }

        return false;
    }

    /// <summary>Human summary for the "hidden" chip: "powershell, github.com +2".</summary>
    public string Describe(int max = 3)
    {
        var all = _processes.Concat(_hosts).ToList();
        string shown = string.Join(", ", all.Take(max));
        return all.Count > max ? $"{shown} +{all.Count - max}" : shown;
    }

    private static string Normalize(string host)
    {
        string trimmed = host.Trim().TrimEnd('.');

        // Drop a :port, but not the colons of an IPv6 address.
        int colon = trimmed.LastIndexOf(':');
        if (colon > 0 && trimmed.IndexOf(':') == colon) trimmed = trimmed[..colon];

        return trimmed.ToLowerInvariant();
    }

    private bool Mutate(bool changed)
    {
        if (changed) Changed?.Invoke(this, EventArgs.Empty);
        return changed;
    }
}
