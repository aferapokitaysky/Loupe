using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Loupe.App.Localization;
using Loupe.App.Services;
using Loupe.Core.Tcp;
using Loupe.Core.Util;
using Microsoft.Win32;

namespace Loupe.App.ViewModels;

/// <summary>
/// One TCP conversation, put back together, in whichever shape answers the question:
///
/// - <b>Dialogue</b>: what was said in the order it was said, each turn labelled with its
///   direction and time. This is the one that reads like a request and its answer.
/// - <b>Both sides</b>: each direction reassembled whole, side by side - for reading a body
///   end to end without the other side interrupting it.
/// - <b>Sent</b> / <b>Received</b>: one direction, alone.
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
        (_outgoingEndpoint, _incomingEndpoint) = selectedSideIsA ? (a, b) : (b, a);

        Refresh();
    }

    public string OutgoingLabel { get; }
    public string IncomingLabel { get; }

    private readonly string _outgoingEndpoint;
    private readonly string _incomingEndpoint;

    /// <summary>The conversation as "1.2.3.4:5678 ↔ 93.184.216.34:443", for the window title.</summary>
    public string Title => _stream.Key.ToString();

    // ---------------------------------------------------------------- what is on screen

    /// <summary>"Dialogue", "Both", "Sent" or "Received". Four booleans rather than an enum
    /// because that is what a row of toggle buttons binds to without a converter in between.</summary>
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(IsDialogue), nameof(IsBoth), nameof(IsSentOnly), nameof(IsReceivedOnly))]
    [NotifyPropertyChangedFor(nameof(ShowOutgoingPane), nameof(ShowIncomingPane))]
    private string _mode = "Dialogue";

    public bool IsDialogue
    {
        get => Mode == "Dialogue";
        set { if (value) Mode = "Dialogue"; }
    }

    public bool IsBoth
    {
        get => Mode == "Both";
        set { if (value) Mode = "Both"; }
    }

    public bool IsSentOnly
    {
        get => Mode == "Sent";
        set { if (value) Mode = "Sent"; }
    }

    public bool IsReceivedOnly
    {
        get => Mode == "Received";
        set { if (value) Mode = "Received"; }
    }

    public bool ShowOutgoingPane => Mode is "Both" or "Sent";
    public bool ShowIncomingPane => Mode is "Both" or "Received";

    /// <summary>Hex instead of text. Half of what goes over TCP is not text, and a hex dump is
    /// the only honest way to show it.</summary>
    [ObservableProperty] private bool _asHex;

    /// <summary>
    /// Wrap long lines. On for text, off the moment the panes switch to hex: a hex dump is a
    /// grid of columns, and wrapping it turns it into mush.
    /// </summary>
    [ObservableProperty] private bool _wrapText = true;

    partial void OnAsHexChanged(bool value)
    {
        if (value) WrapText = false;
        Refresh();
    }

    partial void OnModeChanged(string value) => Refresh();

    // ---------------------------------------------------------------- content

    [ObservableProperty] private string _outgoingText = "";
    [ObservableProperty] private string _incomingText = "";
    [ObservableProperty] private string _outgoingSummary = "";
    [ObservableProperty] private string _incomingSummary = "";

    /// <summary>The conversation, turn by turn, for the dialogue view.</summary>
    public ObservableCollection<StreamTurnViewModel> Turns { get; } = [];

    [ObservableProperty] private string _turnsSummary = "";

    public bool IsTruncated => _stream.ConversationTruncated;

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

        BuildTurns();
        OnPropertyChanged(nameof(IsTruncated));
    }

    /// <summary>
    /// Folds the conversation into turns: consecutive chunks going the same way become one
    /// block, because a response split across four segments is one thing that was said, not four.
    /// </summary>
    private void BuildTurns()
    {
        Turns.Clear();

        var chunks = _stream.Conversation;
        int index = 0;
        long bytes = 0;

        while (index < chunks.Count)
        {
            bool fromA = chunks[index].FromA;
            var start = chunks[index].Timestamp;
            var pieces = new List<StreamChunk>();

            while (index < chunks.Count && chunks[index].FromA == fromA)
            {
                pieces.Add(chunks[index]);
                index++;
            }

            // Within one turn the bytes are put back in the order the sender wrote them, not the
            // order they arrived: a response whose second half overtook its first is still one
            // response, and showing it back to front would be reporting the network's accident
            // as what the server said. Serial arithmetic, because sequence numbers wrap (RFC 1982).
            pieces.Sort((left, right) => unchecked(left.Sequence - right.Sequence) > 0x8000_0000 ? -1 : 1);

            var run = new List<byte>();
            foreach (var piece in pieces) run.AddRange(piece.Data);

            bool outgoing = fromA == _selectedSideIsA;
            bytes += run.Count;
            Turns.Add(new StreamTurnViewModel(
                outgoing,
                outgoing ? _outgoingEndpoint : _incomingEndpoint,
                start,
                run.Count,
                Render([.. run])));
        }

        TurnsSummary = Loc.Format("Follow_Turns", Turns.Count, Loc.Format("Follow_Bytes", bytes));
    }

    [RelayCommand]
    private void Copy(string? which)
    {
        string text = which switch
        {
            "incoming" => IncomingText,
            "outgoing" => OutgoingText,
            // The dialogue as it reads on screen, direction markers and all.
            _ => string.Join(Environment.NewLine + Environment.NewLine,
                Turns.Select(t => $"{(t.IsOutgoing ? "→" : "←")} {t.Endpoint}  {t.Time}  {t.Size}{Environment.NewLine}{t.Text}")),
        };

        ToastService.Show(ClipboardService.TrySetText(text)
            ? Loc.Get("Proxy_Copied")
            : Loc.Get("Proxy_CopyFailed"), "Copy24");
    }

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
            // The window has no status line of its own, and the save dialog has already had its
            // own say about why the file could not be written.
        }
    }

    private string Render(byte[] bytes)
    {
        if (bytes.Length == 0) return Loc.Get("Follow_Empty");
        return AsHex ? HexDump.Format(bytes) : StreamText.Readable(bytes);
    }
}

/// <summary>One turn of the conversation: everything one side said before the other answered.</summary>
public sealed class StreamTurnViewModel(bool isOutgoing, string endpoint, DateTimeOffset at, int bytes, string text)
{
    public bool IsOutgoing { get; } = isOutgoing;
    public string Endpoint { get; } = endpoint;
    public string Time { get; } = at.ToString("HH:mm:ss.fff");
    public string Size { get; } = Loc.Format("Follow_Bytes", bytes);
    public string Text { get; } = text;

    /// <summary>Arrow and colour come from the direction; both are read at a glance.</summary>
    public string Arrow => IsOutgoing ? "→" : "←";

    public string AccentKey => IsOutgoing ? "BrandCyanBrush" : "BrandNeonBrush";
}
