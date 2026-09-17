using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Loupe.App.Localization;
using Loupe.App.Services;
using Loupe.Core.Tcp;
using Loupe.Core.Util;
using Microsoft.Win32;

namespace Loupe.App.ViewModels;

/// <summary>
/// One TCP conversation, both directions, put back together - the "what did these two
/// actually say to each other" view. The two directions are shown separately rather than
/// interleaved: reassembly knows the byte order within each direction, but not how the two
/// were spaced in time, and inventing that ordering would be a guess presented as evidence.
/// </summary>
public sealed partial class FollowStreamViewModel : ObservableObject
{
    private readonly TcpStream _stream;
    private readonly bool _selectedSideIsA;

    public FollowStreamViewModel(TcpStream stream, bool selectedSideIsA)
    {
        _stream = stream;
        _selectedSideIsA = selectedSideIsA;

        var key = stream.Key;
        string a = $"{key.EndpointA}:{key.PortA}";
        string b = $"{key.EndpointB}:{key.PortB}";
        (OutgoingLabel, IncomingLabel) = selectedSideIsA ? ($"{a} → {b}", $"{b} → {a}") : ($"{b} → {a}", $"{a} → {b}");

        Refresh();
    }

    public string OutgoingLabel { get; }
    public string IncomingLabel { get; }

    /// <summary>The conversation as "1.2.3.4:5678 ↔ 93.184.216.34:443", for the window title.</summary>
    public string Title => _stream.Key.ToString();

    [ObservableProperty] private string _outgoingText = "";
    [ObservableProperty] private string _incomingText = "";
    [ObservableProperty] private string _outgoingSummary = "";
    [ObservableProperty] private string _incomingSummary = "";

    /// <summary>Hex instead of text. Half of what goes over TCP is not text, and a hex dump is
    /// the only honest way to show it.</summary>
    [ObservableProperty] private bool _asHex;

    partial void OnAsHexChanged(bool value) => Refresh();

    /// <summary>
    /// Re-reads the stream. It keeps growing while the capture runs, so this is a button rather
    /// than a subscription: a pane that rewrites itself under the pointer is unreadable.
    /// </summary>
    [RelayCommand]
    public void Refresh()
    {
        var outgoing = _selectedSideIsA ? _stream.AToB : _stream.BToA;
        var incoming = _selectedSideIsA ? _stream.BToA : _stream.AToB;

        byte[] outgoingBytes = outgoing.GetReassembledBytes();
        byte[] incomingBytes = incoming.GetReassembledBytes();

        OutgoingText = Render(outgoingBytes);
        IncomingText = Render(incomingBytes);
        OutgoingSummary = Loc.Format("Follow_Bytes", outgoingBytes.Length);
        IncomingSummary = Loc.Format("Follow_Bytes", incomingBytes.Length);
    }

    [RelayCommand]
    private void Copy(string? which) =>
        ClipboardService.TrySetText(which == "incoming" ? IncomingText : OutgoingText);

    [RelayCommand]
    private void Save(string? which)
    {
        var buffer = (which == "incoming") == _selectedSideIsA ? _stream.BToA : _stream.AToB;

        var dialog = new SaveFileDialog { FileName = "stream.bin", Filter = "All files (*.*)|*.*" };
        if (dialog.ShowDialog() != true) return;

        try
        {
            // The raw bytes, not what the panes show: a saved stream is evidence, and the panes
            // deliberately replace unprintable bytes to stay readable.
            System.IO.File.WriteAllBytes(dialog.FileName, buffer.GetReassembledBytes());
        }
        catch (Exception e) when (e is System.IO.IOException or UnauthorizedAccessException)
        {
            // The window has no status line of its own; a failed save leaves the file absent,
            // which the save dialog's own error has already made clear.
        }
    }

    /// <summary>
    /// Bytes as something readable: a hex dump, or text with unprintable bytes shown as dots -
    /// the convention every packet tool uses, and the reason a TLS record doesn't scramble
    /// the pane or ring the terminal bell.
    /// </summary>
    private string Render(byte[] bytes)
    {
        if (bytes.Length == 0) return Loc.Get("Follow_Empty");
        return AsHex ? HexDump.Format(bytes) : StreamText.Readable(bytes);
    }
}
