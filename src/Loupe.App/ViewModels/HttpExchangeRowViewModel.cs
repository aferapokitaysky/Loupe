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

    public string RequestHeadersText => FormatHeaders(Exchange.RequestHeaders);
    public string ResponseHeadersText => Exchange.State == ExchangeState.ResponseReceived
        ? FormatHeaders(Exchange.ResponseHeaders)
        : Exchange.Error ?? Loc.Get("Proxy_NoResponseYet");

    public string RequestBodyText => BodyFormatter.Format(Exchange.RequestHeaders, Exchange.RequestBody, Exchange.RequestBodyTruncated);
    public string ResponseBodyText => Exchange.State == ExchangeState.ResponseReceived
        ? BodyFormatter.Format(Exchange.ResponseHeaders, Exchange.ResponseBody, Exchange.ResponseBodyTruncated)
        : "";

    /// <summary>Re-reads every computed property. Call after the underlying <see cref="Exchange"/> mutates.</summary>
    public void Refresh() => OnPropertyChanged((string?)null);

    private static string FormatHeaders(IEnumerable<HttpHeader> headers) =>
        string.Join('\n', headers.Select(h => $"{h.Name}: {h.Value}"));
}
