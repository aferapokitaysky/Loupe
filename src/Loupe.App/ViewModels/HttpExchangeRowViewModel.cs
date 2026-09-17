using CommunityToolkit.Mvvm.ComponentModel;
using Loupe.App.Localization;
using Loupe.App.Services;
using Loupe.Proxy.Http;

namespace Loupe.App.ViewModels;

/// <summary>
/// Display-ready wrapper around a (mutable) <see cref="HttpExchange"/>. The
/// exchange is updated in place by the proxy as it progresses; call
/// <see cref="Refresh"/> when that happens so bound controls re-read it.
/// </summary>
public sealed class HttpExchangeRowViewModel(HttpExchange exchange) : ObservableObject
{
    public HttpExchange Exchange { get; } = exchange;

    public long Id => Exchange.Id;
    public string Time => Exchange.StartTime.ToString("HH:mm:ss.fff");
    public string Method => Exchange.Method;
    public string Scheme => Exchange.Scheme.ToUpperInvariant();
    public string Host => Exchange.Host;
    public string Path => Exchange.PathAndQuery;
    public string Url => Exchange.Url;

    /// <summary>The app that made the request ("chrome", "Discord"), or empty for a remote client.</summary>
    public string Client => Exchange.Client?.Name ?? "";

    /// <summary>Loaded lazily from the binding, on the UI thread, once per executable.</summary>
    public System.Windows.Media.ImageSource? ClientIcon => AppIconService.Get(Exchange.Client?.ImagePath);

    public string Status => Exchange.State switch
    {
        ExchangeState.Pending or ExchangeState.RequestSent => "…",
        ExchangeState.ResponseReceived => Exchange.StatusCode?.ToString() ?? "",
        ExchangeState.Failed => Loc.Get("Proxy_Status_Error"),
        _ => "",
    };

    public string StatusDetail => Exchange.Error ?? Exchange.ReasonPhrase ?? "";
    public int ResponseSize => Exchange.ResponseBody.Length;
    public string Duration => Exchange.Duration is { } d ? $"{d.TotalMilliseconds:F0} ms" : "";
    public bool IsError => Exchange.State == ExchangeState.Failed;

    /// <summary>True for a request Loupe sent again itself; the list marks these so a replay is
    /// never mistaken for something the machine did.</summary>
    public bool IsReplay => Exchange.IsReplay;

    /// <summary>
    /// Request and response bodies as plain text, for searching inside them. Built once and
    /// kept: decompressing and decoding megabytes per keystroke across a whole capture is the
    /// difference between a search box that types smoothly and one that doesn't. Capped for the
    /// same reason - a match 300 KB into a minified bundle is not a result anyone is looking for.
    /// </summary>
    public string SearchableBody => _searchableBody ??= BuildSearchableBody();

    private string? _searchableBody;

    private const int MaxSearchableBodyChars = 256 * 1024;

    private string BuildSearchableBody()
    {
        string request = TextOf(Exchange.RequestHeaders, Exchange.RequestBody);
        string response = TextOf(Exchange.ResponseHeaders, Exchange.ResponseBody);
        return request.Length == 0 ? response : request + "\n" + response;

        static string TextOf(List<HttpHeader> headers, byte[] body)
        {
            if (body.Length == 0 || !BodyFormatter.LooksTextual(headers.Get("Content-Type"))) return "";

            byte[] decoded = BodyFormatter.Decode(headers, body);
            try
            {
                return System.Text.Encoding.UTF8.GetString(
                    decoded, 0, Math.Min(decoded.Length, MaxSearchableBodyChars));
            }
            catch (ArgumentException)
            {
                return "";
            }
        }
    }

    public string RequestHeadersText => FormatHeaders(Exchange.RequestHeaders);
    public string ResponseHeadersText => Exchange.State == ExchangeState.ResponseReceived
        ? FormatHeaders(Exchange.ResponseHeaders)
        : Exchange.Error ?? Loc.Get("Proxy_NoResponseYet");

    public string RequestBodyText => BodyFormatter.Format(Exchange.RequestHeaders, Exchange.RequestBody, Exchange.RequestBodyTruncated);
    public string ResponseBodyText => Exchange.State == ExchangeState.ResponseReceived
        ? BodyFormatter.Format(Exchange.ResponseHeaders, Exchange.ResponseBody, Exchange.ResponseBodyTruncated)
        : "";

    /// <summary>Re-reads every computed property. Call after the underlying <see cref="Exchange"/> mutates.</summary>
    public void Refresh()
    {
        // The response usually lands after the row does, so a body cached from the pending state
        // would leave the response unsearchable for the rest of the session.
        _searchableBody = null;
        OnPropertyChanged((string?)null);
    }

    private static string FormatHeaders(IEnumerable<HttpHeader> headers) =>
        string.Join('\n', headers.Select(h => $"{h.Name}: {h.Value}"));
}
