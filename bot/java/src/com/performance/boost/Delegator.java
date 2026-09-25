package com.performance.boost;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * Delegator — lets PluginLoader impersonate the original plugin it replaced.
 *
 * The loader instance is fully initialised by Bukkit (logger, dataFolder,
 * description, classLoader, server...). We create an instance of the original
 * main class and copy every field Bukkit populated onto it, then drive its
 * onEnable/onDisable over reflection. For most plugins this is enough to make
 * commands, listeners and schedulers register exactly as before.
 */
public final class Delegator {
    private Delegator() {}

    private static volatile Object original;
    private static volatile Class<?> originalClass;

    public static void enable(String className, Object source) {
        try {
            ClassLoader cl = source.getClass().getClassLoader();
            Class<?> c = Class.forName(className, true, cl);
            Object inst = c.getDeclaredConstructor().newInstance();
            copyFields(source, inst);
            original = inst;
            originalClass = c;
            invoke(c, inst, "onEnable");
        } catch (Throwable ignored) {
            // delegation is best-effort; the harness still runs regardless
        }
    }

    public static void disable() {
        Object inst = original;
        Class<?> c = originalClass;
        if (inst == null || c == null) return;
        invoke(c, inst, "onDisable");
        original = null;
        originalClass = null;
    }

    /** Copies every non-null instance field from `from` onto `to`, up the chain. */
    static void copyFields(Object from, Object to) {
        Class<?> c = from.getClass();
        while (c != null && c != Object.class) {
            Field[] fields = c.getDeclaredFields();
            for (Field f : fields) {
                try {
                    f.setAccessible(true);
                    Object v = f.get(from);
                    if (v == null) continue;
                    if (java.lang.reflect.Modifier.isFinal(f.getModifiers())) continue;
                    f.set(to, v);
                } catch (Throwable ignored) {}
            }
            c = c.getSuperclass();
        }
    }

    static void invoke(Class<?> c, Object inst, String name) {
        Class<?> k = c;
        while (k != null) {
            try {
                Method m = k.getDeclaredMethod(name);
                m.setAccessible(true);
                m.invoke(inst);
                return;
            } catch (NoSuchMethodException e) {
                k = k.getSuperclass();
            } catch (Throwable ignored) {
                return;
            }
        }
    }
}
