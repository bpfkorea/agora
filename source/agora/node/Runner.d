/*******************************************************************************

    Contains a function which instantiates either a FullNode or a Validator.

    Copyright:
        Copyright (c) 2019-2021 BOSAGORA Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.node.Runner;

import agora.api.FullNode;
import agora.api.Validator;
import agora.common.Config;
import agora.common.Task : Periodic;
import agora.flash.api.FlashAPI;
import agora.flash.Node;
import agora.node.admin.AdminInterface;
import agora.node.FullNode;
import agora.node.Validator;
import agora.utils.Log;

import ocean.util.log.ILogger;

import vibe.core.core;
import vibe.http.server;
import vibe.http.router;
import vibe.web.rest;
import vibe.stream.tls;

import std.algorithm : filter;
import std.file;
import std.format;
import std.typecons : Tuple, tuple;

import core.time;

///
public alias Listeners = Tuple!(
    FullNode, "node",
    AdminInterface, "admin",
    AgoraFlashNode, "flash",
    HTTPListener[], "http"
 );

/*******************************************************************************

    Boots up a FullNode or Validator that listens for network requests and
    blockchain data.

    This is called from the main or CLI.
    The initialization process of the node is then completed.

    Params:
      config = A parsed and validated config file

*******************************************************************************/

public Listeners runNode (Config config)
{
    foreach (const ref settings; config.logging)
    {
        if (settings.name.length == 0 || settings.name == "vibe")
            setVibeLogLevel(settings.level);
        configureLogger(settings, true);
    }

    auto log = Logger(__MODULE__);
    log.trace("Config is: {}", config);

    auto router = new URLRouter();

    mkdirRecurse(config.node.data_dir);

    Listeners result;
    if (config.validator.enabled)
    {
        log.trace("Started Validator...");
        auto inst = new Validator(config);
        router.registerRestInterface!(agora.api.Validator.API)(inst);
        if (config.admin.enabled)
            result.admin = inst.makeAdminInterface();
        result.node = inst;
    }
    else
    {
        log.trace("Started FullNode...");
        result.node = new FullNode(config);
        router.registerRestInterface!(agora.api.FullNode.API)(result.node);
    }

    if (config.flash.enabled)
    {
        import agora.crypto.Hash;

        log.trace("Started Flash node...");
        const params = FullNode.makeConsensusParams(config);
        auto flash = new AgoraFlashNode(config.flash,
            config.node.data_dir, params.Genesis.hashFull(),
            result.node.getEngine(),
            result.node.getTaskManager(), &result.node.putTransaction,
            result.node.getNetworkManager());
        router.registerRestInterface!FlashAPI(flash);
        result.flash = flash;
    }

    bool delegate (in NetworkAddress address) @safe nothrow isBannedDg = (in address) @safe nothrow {
        return result.node.getBanManager().isBanned(address.toAddressString());
    };

    setTimer(0.seconds, &result.node.start, Periodic.No);  // asynchronous

    auto tls_ctx = getTLSContext();
    if (result.admin !is null)
    {
        log.info("Admin interface listening will be on {}:{}", config.admin.address, config.admin.port);
        auto adminrouter = new URLRouter();
        adminrouter.registerRestInterface(result.admin);
        auto settings = new HTTPServerSettings(config.admin.address);
        settings.port = config.admin.port;
        settings.tlsContext = tls_ctx;
        result.http ~= listenHTTP(settings, adminrouter);
    }

    // HTTP interfaces for the node
    foreach (interface_; config.interfaces.filter!(i => i.type == InterfaceConfig.Type.http))
    {
        auto settings = new HTTPServerSettings(interface_.address);
        settings.port = interface_.port;
        settings.rejectConnectionPredicate = isBannedDg;
        settings.tlsContext = tls_ctx;
        log.info("Node will be listening on HTTP interface: {}:{}", interface_.address, settings.port);
        result.http ~= listenHTTP(settings, router);
    }

    // also register the FlashControlAPI
    if (result.flash !is null)
    {
        log.info("Flash control interface listening will be on {}:{}",
            config.flash.control_address, config.flash.control_port);
        result.http ~= result.flash.startControlInterface();
    }

    return result;
}

/*******************************************************************************

    Set Vibe.d log level according to the configuration's log level

    This is used to ensure we get the right amount of information from Vibe.d
    Since a log level is the "minimum accepted" level, some level values might
    not match. For example, if we want Vibe.d's "diagnostic" to be part of
    the output when we set the loglevel to info, then that's what we must pass
    to Vibe's `setLogLevel` (and since diagnostic < info, it will include the
    latter too).

    Params:
        level = The level at which we want to set the logger

*******************************************************************************/

private void setVibeLogLevel (ILogger.Level level) @safe
{
    import vibe.core.log;

    final switch (level)
    {
    case ILogger.Level.Trace:
        setLogLevel(LogLevel.trace);
        break;
    case ILogger.Level.Info:
        setLogLevel(LogLevel.diagnostic);
        break;
    case ILogger.Level.Warn:
        setLogLevel(LogLevel.warn);
        break;
    case ILogger.Level.Error:
        setLogLevel(LogLevel.error);
        break;
    case ILogger.Level.Fatal:
        setLogLevel(LogLevel.critical);
        break;
    case ILogger.Level.None:
        setLogLevel(LogLevel.none);
        break;
    }
}

/*******************************************************************************

    Search multiple paths for SSL certificate and create the TLS context

    Returns:
        TLS context

*******************************************************************************/

private TLSContext getTLSContext ()
{
    const cert_file = "agora-cert.pem";
    const cert_search_paths = [
        "./",
        "/etc/ssl/certs/",
        "/etc/pki/tls/certs/",
    ];

    const key_file = "agora-key.pem";
    const key_search_paths = [
        "./",
        "/etc/ssl/private/",
        "/etc/pki/tls/private/",
    ];

    TLSContext ctx;
    foreach (idx; 0 .. cert_search_paths.length)
    {
        const cert_path = cert_search_paths[idx] ~ cert_file;
        const key_path = key_search_paths[idx] ~ key_file;

        // Enable TLS
        if (exists(cert_path) && exists(key_path))
        {
            ctx = createTLSContext(TLSContextKind.server);
            ctx.useCertificateChainFile(cert_path);
            ctx.usePrivateKeyFile(key_path);
            break;
        }
    }

    return ctx;
}
