using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OmniEye.Core.Configuration;
using OmniEye.Core.Storage;
using OmniEyeSvc.Ipc;
using OmniEyeSvc.Monitor;
using OmniEyeSvc.Network;

namespace OmniEyeSvc;

public class Worker : BackgroundService
{
    private readonly OmniEyeConfig _config;
    private readonly DatabaseManager _dbManager;
    private readonly FirewallEnforcer _firewall;
    private readonly IpcServer _ipcServer;
    private readonly AntiInjectionMonitor _antiInjection;
    private readonly ILogger<Worker> _logger;

    public Worker(
        OmniEyeConfig config,
        DatabaseManager dbManager,
        FirewallEnforcer firewall,
        IpcServer ipcServer,
        AntiInjectionMonitor antiInjection,
        ILogger<Worker> logger)
    {
        _config = config;
        _dbManager = dbManager;
        _firewall = firewall;
        _ipcServer = ipcServer;
        _antiInjection = antiInjection;
        _logger = logger;
    }

    public override Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("==================================================");
        _logger.LogInformation(" OmniEye Zero-Trust Security Service Starting... ");
        _logger.LogInformation(" Mode: {Mode}", _config.DeveloperMode ? "DEVELOPER / TEST MODE" : "RELEASE (STRICT ZERO-TRUST)");
        _logger.LogInformation(" Storage: {Path}", _config.DbFilePath);
        _logger.LogInformation("==================================================");

        try
        {
            // 1. Initialize encrypted database & acquire lock
            _dbManager.Initialize();
            _logger.LogInformation("SQLCipher encrypted database initialized and locked.");

            // 2. Apply Zero-Trust Firewall policy
            _firewall.ApplyPolicy();

            // 3. Start IPC Named Pipe Server
            _ipcServer.Start();

            // 4. Start ETW Anti-Injection Monitor
            _antiInjection.Start();

            _logger.LogInformation("OmniEye core protection systems are fully active.");
        }
        catch (Exception ex)
        {
            _logger.LogCritical(ex, "FATAL: Error initializing OmniEye service: {Message}", ex.Message);
            throw;
        }

        return base.StartAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(5000, stoppingToken);
        }
    }

    public override Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("OmniEye service stop requested.");

        if (!_config.DeveloperMode)
        {
            _logger.LogWarning("RELEASE MODE ACTIVE: Stop command is rejected / restricted.");
            // In release mode, the service does not roll back firewall rules or unlock database
            return Task.CompletedTask;
        }

        _logger.LogInformation("DEVELOPER MODE ACTIVE: Performing graceful shutdown & rollback...");

        try
        {
            // 1. Stop Anti-Injection ETW Monitor
            _antiInjection.Stop();

            // 2. Stop IPC Server
            _ipcServer.Stop();

            // 3. Rollback Firewall: Restore Default Outbound = Allow and delete OmniEye rules
            _firewall.RollbackPolicy();

            // 4. Release exclusive database lock
            _dbManager.ReleaseLock();

            _logger.LogInformation("All protections rolled back cleanly. Goodbye.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during DeveloperMode shutdown: {Message}", ex.Message);
        }

        return base.StopAsync(cancellationToken);
    }
}
