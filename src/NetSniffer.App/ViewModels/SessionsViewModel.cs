using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetSniffer.App.Localization;
using NetSniffer.App.Services;
using NetSniffer.Core.Sessions;

namespace NetSniffer.App.ViewModels;

/// <summary>One saved session in the list.</summary>
public sealed partial class SessionRowViewModel(SessionInfo info) : ObservableObject
{
    [ObservableProperty] private SessionInfo _info = info;

    public string Id => Info.Id;
    public string Name => Info.Name;
    public string Created => Info.Created.LocalDateTime.ToString("dd.MM.yyyy HH:mm");
    public string Source => Info.Source ?? "";
    public bool HasSource => !string.IsNullOrEmpty(Info.Source);

    /// <summary>"1 240 packets · 18 hosts · 37 requests" - only the parts that apply.</summary>
    public string Summary
    {
        get
        {
            var parts = new List<string>();
            if (Info.HasPackets) parts.Add(Loc.Format("Sessions_Packets", Info.PacketCount));
            if (Info.HostCount > 0) parts.Add(Loc.Format("Sessions_Hosts", Info.HostCount));
            if (Info.HasRequests) parts.Add(Loc.Format("Sessions_Requests", Info.RequestCount));
            parts.Add(FormatSize(Info.SizeOnDisk));
            return string.Join(" · ", parts);
        }
    }

    public bool HasPackets => Info.HasPackets;
    public bool HasRequests => Info.HasRequests;

    /// <summary>True while the row is being renamed in place.</summary>
    [ObservableProperty] private bool _isRenaming;
    [ObservableProperty] private string _editName = info.Name;

    public void Refresh(SessionInfo info)
    {
        Info = info;
        OnPropertyChanged(nameof(Name));
        OnPropertyChanged(nameof(Summary));
    }

    private static string FormatSize(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:F0} KB",
        < 1024L * 1024 * 1024 => $"{bytes / (1024.0 * 1024):F1} MB",
        _ => $"{bytes / (1024.0 * 1024 * 1024):F2} GB",
    };
}

/// <summary>
/// The saved-sessions library: open one back into the page it came from, rename it, delete it,
/// or reveal the folder so the .pcap can go to Wireshark.
/// </summary>
public partial class SessionsViewModel : ObservableObject
{
    private readonly SessionStore _store = SessionService.Store;

    public ObservableCollection<SessionRowViewModel> Sessions { get; } = [];

    [ObservableProperty] private string _statusMessage = "";
    [ObservableProperty] private SessionRowViewModel? _selected;

    /// <summary>Raised when a session should be opened; the window routes it to the right page.</summary>
    public event EventHandler<SessionInfo>? OpenRequested;

    public bool IsEmpty => Sessions.Count == 0;

    public SessionsViewModel() => Refresh();

    [RelayCommand]
    public void Refresh()
    {
        string? selectedId = Selected?.Id;

        Sessions.Clear();
        foreach (var info in _store.List())
            Sessions.Add(new SessionRowViewModel(info));

        Selected = Sessions.FirstOrDefault(s => s.Id == selectedId);
        OnPropertyChanged(nameof(IsEmpty));
        StatusMessage = Sessions.Count == 0 ? "" : Loc.Format("Sessions_Count", Sessions.Count);
    }

    [RelayCommand]
    private void Open(SessionRowViewModel? row)
    {
        if (row is null) return;
        OpenRequested?.Invoke(this, row.Info);
    }

    [RelayCommand]
    private static void RevealInExplorer(SessionRowViewModel? row)
    {
        if (row is null || !Directory.Exists(row.Info.Directory)) return;

        // Explorer with the folder selected, not an arbitrary shell command.
        Process.Start(new ProcessStartInfo("explorer.exe", $"\"{row.Info.Directory}\"") { UseShellExecute = true });
    }

    [RelayCommand]
    private static void BeginRename(SessionRowViewModel? row)
    {
        if (row is null) return;
        row.EditName = row.Name;
        row.IsRenaming = true;
    }

    [RelayCommand]
    private void CommitRename(SessionRowViewModel? row)
    {
        if (row is null) return;
        row.IsRenaming = false;

        if (row.EditName.Trim() == row.Name) return;

        try
        {
            row.Refresh(_store.Rename(row.Id, row.EditName));
        }
        catch (Exception e) when (e is IOException or DirectoryNotFoundException or UnauthorizedAccessException)
        {
            StatusMessage = Loc.Format("Sessions_RenameFailed", e.Message);
            Refresh();
        }
    }

    [RelayCommand]
    private static void CancelRename(SessionRowViewModel? row)
    {
        if (row is null) return;
        row.EditName = row.Name;
        row.IsRenaming = false;
    }

    /// <summary>
    /// Deletes for good. The confirmation lives in the view: this is the one action here that
    /// destroys data, and it must never happen because a click landed slightly off.
    /// </summary>
    public void Delete(SessionRowViewModel row)
    {
        try
        {
            _store.Delete(row.Id);
            StatusMessage = Loc.Format("Sessions_Deleted", row.Name);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            StatusMessage = Loc.Format("Sessions_DeleteFailed", e.Message);
        }

        Refresh();
    }
}
