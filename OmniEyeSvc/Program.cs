using System;
using System.IO;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OmniEye.Core.Configuration;
using OmniEye.Core.Storage;
using OmniEyeSvc;
using OmniEyeSvc.Ipc;
using OmniEyeSvc.Monitor;
using OmniEyeSvc.Network;

var builder = Host.CreateDefaultBuilder(args);

builder.UseWindowsService(options =>
{
    options.ServiceName = "OmniEyeSvc";
});

builder.ConfigureAppConfiguration((hostingContext, config) =>
{
    config.SetBasePath(AppContext.BaseDirectory)
          .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
          .AddEnvironmentVariables(prefix: "OMNIEYE_")
          .AddCommandLine(args);
});

builder.ConfigureServices((hostContext, services) =>
{
    var config = new OmniEyeConfig();
    hostContext.Configuration.GetSection("OmniEye").Bind(config);

    // Support command-line overrides, e.g. --DeveloperMode=false
    if (bool.TryParse(hostContext.Configuration["DeveloperMode"], out var devMode))
    {
        config.DeveloperMode = devMode;
    }

    services.AddSingleton(config);
    services.AddSingleton<DatabaseManager>();
    services.AddSingleton<FirewallEnforcer>();
    services.AddSingleton<IpcServer>();
    services.AddSingleton<AntiInjectionMonitor>();

    services.AddHostedService<Worker>();
});

builder.ConfigureLogging(logging =>
{
    logging.ClearProviders();
    logging.AddConsole();
    logging.AddEventLog(eventLogSettings =>
    {
        eventLogSettings.SourceName = "OmniEyeSvc";
    });
});

var host = builder.Build();
await host.RunAsync();
