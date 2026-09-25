package com.performance.boost;

import java.io.ByteArrayOutputStream;
import java.util.Map;

/**
 * Remapper — rewrites package names inside class files by editing the
 * constant pool (CONSTANT_Utf8 entries, lengths recomputed). Only UTF8
 * contents change; every other structure references pool indexes, so the
 * rewrite is structurally safe. Pure JDK, no dependencies.
 */
public final class Remapper {
    private Remapper() {}

    /** Applies {@link #remapClass} to every entry whose name ends in .class. */
    public static void remapAll(Map<String, byte[]> entries, String from, String to) {
        for (Map.Entry<String, byte[]> e : entries.entrySet()) {
            if (e.getKey().endsWith(".class")) {
                e.setValue(remapClass(e.getValue(), from, to));
            }
        }
    }

    /** Replaces every occurrence of {@code from} with {@code to} inside the
     *  constant pool UTF8 entries of a class file. Returns the rewritten
     *  bytes, or the input unchanged when the file is not a class file or
     *  contains nothing to rewrite. */
    public static byte[] remapClass(byte[] data, String from, String to) {
        try {
            if (data == null || data.length < 10) return data;
            if ((data[0] & 0xff) != 0xCA || (data[1] & 0xff) != 0xFE
                    || (data[2] & 0xff) != 0xBA || (data[3] & 0xff) != 0xBE) return data;

            byte[] fb = from.getBytes("UTF-8");
            byte[] tb = to.getBytes("UTF-8");
            if (!contains(data, fb)) return data;

            ByteArrayOutputStream out = new ByteArrayOutputStream(data.length + 1024);
            out.write(data, 0, 8); // magic + minor + major
            int pos = 8;
            int cpcount = ((data[pos] & 0xff) << 8) | (data[pos + 1] & 0xff);
            out.write(data, pos, 2); // constant_pool_count
            pos += 2;

            for (int i = 1; i < cpcount; i++) {
                int tag = data[pos] & 0xff;
                switch (tag) {
                    case 1: { // Utf8 — the only entries we rewrite
                        int len = ((data[pos + 1] & 0xff) << 8) | (data[pos + 2] & 0xff);
                        byte[] content = new byte[len];
                        System.arraycopy(data, pos + 3, content, 0, len);
                        byte[] replaced = replace(content, fb, tb);
                        out.write(1);
                        out.write((replaced.length >> 8) & 0xff);
                        out.write(replaced.length & 0xff);
                        out.write(replaced, 0, replaced.length);
                        pos += 3 + len;
                        break;
                    }
                    case 3: case 4: // Integer, Float
                        out.write(data, pos, 5); pos += 5; break;
                    case 5: case 6: // Long, Double — occupy two pool slots
                        out.write(data, pos, 9); pos += 9; i++; break;
                    case 7: case 8: case 16: case 19: case 20:
                        // Class, String, MethodType, Module, Package
                        out.write(data, pos, 3); pos += 3; break;
                    case 9: case 10: case 11: case 12: case 17: case 18:
                        // Field/Method/InterfaceMethod refs, Dynamic, InvokeDynamic
                        out.write(data, pos, 5); pos += 5; break;
                    case 15: // MethodHandle
                        out.write(data, pos, 4); pos += 4; break;
                    default:
                        return data; // unknown tag — leave the file untouched
                }
            }
            out.write(data, pos, data.length - pos);
            return out.toByteArray();
        } catch (Throwable t) {
            return data;
        }
    }

    static boolean contains(byte[] data, byte[] pat) {
        if (pat.length == 0 || data.length < pat.length) return false;
        outer:
        for (int i = 0; i <= data.length - pat.length; i++) {
            for (int j = 0; j < pat.length; j++) {
                if (data[i + j] != pat[j]) continue outer;
            }
            return true;
        }
        return false;
    }

    static byte[] replace(byte[] src, byte[] from, byte[] to) {
        if (from.length == 0 || from.length > src.length) return src;
        int n = 0;
        outer:
        for (int i = 0; i <= src.length - from.length; i++) {
            for (int j = 0; j < from.length; j++) {
                if (src[i + j] != from[j]) continue outer;
            }
            n++;
            i += from.length - 1;
        }
        if (n == 0) return src;
        byte[] out = new byte[src.length + n * (to.length - from.length)];
        int o = 0;
        for (int i = 0; i < src.length; ) {
            if (i <= src.length - from.length && matchesAt(src, i, from)) {
                System.arraycopy(to, 0, out, o, to.length);
                o += to.length;
                i += from.length;
            } else {
                out[o++] = src[i++];
            }
        }
        return out;
    }

    private static boolean matchesAt(byte[] src, int pos, byte[] pat) {
        if (pos + pat.length > src.length) return false;
        for (int j = 0; j < pat.length; j++) {
            if (src[pos + j] != pat[j]) return false;
        }
        return true;
    }
}
