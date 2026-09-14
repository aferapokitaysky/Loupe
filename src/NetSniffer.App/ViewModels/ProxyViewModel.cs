using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.IO;
using System.Windows.Threading;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Win32;
using NetSniffer.App.Localization;
using NetSniffer.Proxy;
using NetSniffer.Proxy.Ca;
using NetSniffer.Proxy.Http;

namespace NetSniffer.App.ViewModels;

public partial class ProxyViewModel : ObservableObject, IDisposable
{
    private const int MaxExchanges = 50_000;
    private const int DrainBatchSize = 500;

    private readonly ConcurrentQueue<HttpExchange> _incoming = new();
    private readonly Dictionary<long, HttpExchangeRowViewModel> _rowsById = [];
    private readonly DispatcherTimer _drainTimer;
    private readonly RootCertificateAuthority _ca = new();

    private ProxyServer? _server;

    public ObservableCollection<HttpExchangeRowViewModel> Exchanges { get; } = [];

    [ObservableProperty] private int _port = 8080;
    [ObservableProperty] private bool _isRunning;
    [ObservableProperty] private string _statusMessage = "";
    [ObservableProperty] private HttpExchangeRowViewModel? _selectedExchange;
    [ObservableProperty] private bool _isCaInstalled;
    [ObservableProperty] private bool _isSystemProxyEnabled;

    public string CaThumbprint => _ca.Thumbprint;

    public ProxyViewModel()
    {
        StatusMessage = Loc.Get("Proxy_Status_Stopped");
        IsCaInstalled = SafeCall(() => _ca.IsInstalledForCurrentUser(), fallback: false);
        IsSystemProxyEnabled = SafeCall(WindowsProxySettings.IsEnabled, fallback: false);

        _drainTimer = new DispatcherTimer(DispatcherPriority.Background) { Interval = TimeSpan.FromMilliseconds(150) };
        _drainTimer.Tick += (_, _) => Drain();
        _drainTimer.Start();
    }

    private bool CanStart() => !IsRunning;

    [RelayCommand(CanExecute = nameof(CanStart))]
    private void StartProxy()
    {
        var server = new ProxyServer(new ProxyOptions { Port = Port }, _ca);
        server.ExchangeStarted += (_, exchange) => _incoming.Enqueue(exchange);
        server.ExchangeUpdated += (_, exchange) => _incoming.Enqueue(exchange);
        server.ConnectionError += (_, message) => System.Windows.Application.Current.Dispatcher.BeginInvoke(() => StatusMessage = message);

        try
        {
            server.Start();
            _server = server;
            IsRunning = true;
            StatusMessage = Loc.Format("Proxy_Status_Listening", Port);
        }
        catch (Exception ex)
        {
            StatusMessage = Loc.Format("Proxy_Status_FailedToStart", ex.Message);
        }

        StartProxyCommand.NotifyCanExecuteChanged();
        StopProxyCommand.NotifyCanExecuteChanged();
    }

    private bool CanStop() => IsRunning;

    [RelayCommand(CanExecute = nameof(CanStop))]
    private void StopProxy()
    {
        _server?.Stop();
        _server = null;
        IsRunning = false;
        StatusMessage = Loc.Get("Proxy_Status_Stopped");

        StartProxyCommand.NotifyCanExecuteChanged();
        StopProxyCommand.NotifyCanExecuteChanged();
    }

    [RelayCommand]
    private void ClearExchanges()
    {
        Exchanges.Clear();
        _rowsById.Clear();
        SelectedExchange = null;
    }

    [RelayCommand]
    private void InstallRootCertificate()
    {
        try
        {
            _ca.InstallForCurrentUser();
            IsCaInstalled = true;
            StatusMessage = Loc.Get("Proxy_Status_CertInstalled");
        }
        catch (Exception ex)
        {
            StatusMessage = Loc.Format("Proxy_Status_CertInstallFailed", ex.Message);
        }
    }

    [RelayCommand]
    private void UninstallRootCertificate()
    {
        try
        {
            _ca.UninstallForCurrentUser();
            IsCaInstalled = false;
            StatusMessage = Loc.Get("Proxy_Status_CertRemoved");
        }
        catch (Exception ex)
        {
            StatusMessage = Loc.Format("Proxy_Status_CertRemoveFailed", ex.Message);
        }
    }

    [RelayCommand]
    private void ExportRootCertificate()
    {
        var dialog = new SaveFileDialog { Filter = "PEM certificate (*.pem)|*.pem", FileName = "netsniffer-root-ca.pem" };
        if (dialog.ShowDialog() != true) return;

        File.WriteAllText(dialog.FileName, _ca.ExportPublicCertificatePem());
        StatusMessage = Loc.Format("Proxy_Status_CertExported", dialog.FileName);
    }

    [RelayCommand]
    private void EnableSystemProxy()
    {
        try
        {
            WindowsProxySettings.Enable("127.0.0.1", Port);
            IsSystemProxyEnabled = true;
            StatusMessage = Loc.Format("Proxy_Status_SystemProxyEnabled", Port);
        }
        catch (Exception ex)
        {
            StatusMessage = Loc.Format("Proxy_Status_SystemProxyEnableFailed", ex.Message);
        }
    }

    [RelayCommand]
    private void DisableSystemProxy()
    {
        try
        {
            WindowsProxySettings.Disable();
            IsSystemProxyEnabled = false;
            StatusMessage = Loc.Get("Proxy_Status_SystemProxyDisabled");
        }
        catch (Exception ex)
        {
            StatusMessage = Loc.Format("Proxy_Status_SystemProxyDisableFailed", ex.Message);
        }
    }

    private void Drain()
    {
        int processed = 0;
        while (processed < DrainBatchSize && _incoming.TryDequeue(out var exchange))
        {
            if (_rowsById.TryGetValue(exchange.Id, out var row))
            {
                row.Refresh();
            }
            else
            {
                row = new HttpExchangeRowViewModel(exchange);
                _rowsById[exchange.Id] = row;
                Exchanges.Add(row);
            }
            processed++;
        }

        while (Exchanges.Count > MaxExchanges)
        {
            var oldest = Exchanges[0];
            Exchanges.RemoveAt(0);
            _rowsById.Remove(oldest.Id);
        }
    }

    private static T SafeCall<T>(Func<T> action, T fallback)
    {
        try { return action(); } catch { return fallback; }
    }

    public void Dispose()
    {
        _drainTimer.Stop();
        _server?.Stop();
    }
}
