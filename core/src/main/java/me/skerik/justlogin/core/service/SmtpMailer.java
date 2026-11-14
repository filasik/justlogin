package me.skerik.justlogin.core.service;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ThreadFactory;
import java.util.function.Supplier;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import me.skerik.justlogin.core.model.SmtpConfig;

/** Zero-dependency pure-JDK RFC 5321 SMTP client supporting {@code STARTTLS}, {@code SSL}, and {@code NONE}. */
public final class SmtpMailer implements EmailSender {

    private static final ThreadFactory VIRTUAL_FACTORY =
            Thread.ofVirtual().name("justlogin-smtp-", 0).factory();

    private final Supplier<SmtpConfig> configSupplier;

    public SmtpMailer(Supplier<SmtpConfig> configSupplier) {
        this.configSupplier = configSupplier;
    }

    @Override
    public CompletableFuture<Void> send(String toAddress, String subject, String body) {
        CompletableFuture<Void> future = new CompletableFuture<>();
        VIRTUAL_FACTORY.newThread(() -> {
            try {
                sendBlocking(configSupplier.get(), toAddress, subject, body);
                future.complete(null);
            } catch (Throwable t) {
                future.completeExceptionally(t instanceof CompletionException ce ? ce.getCause() : t);
            }
        }).start();
        return future;
    }

    public static void sendBlocking(SmtpConfig cfg, String toAddress, String subject, String body) throws IOException {
        if (!cfg.enabled()) throw new IOException("SMTP is disabled");
        String safeTo = sanitizeHeader(toAddress);
        String safeFrom = sanitizeHeader(cfg.fromAddress());
        String safeFromName = sanitizeHeader(cfg.fromName());
        String safeSubject = sanitizeHeader(subject);
        if (safeTo.isEmpty() || safeFrom.isEmpty()) throw new IOException("Invalid email header address");

        if (cfg.security() == SmtpConfig.Security.NONE && !cfg.username().isEmpty() && !isLoopbackHost(cfg.host())) {
            throw new IOException("Refusing to send SMTP credentials over plaintext connection (security: NONE) to non-loopback host " + cfg.host());
        }

        Socket socket = connect(cfg);
        try {
            socket.setSoTimeout(Math.max(1000, cfg.readTimeoutMs()));
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));

            expect(in, 220);
            String ehloHost = "justlogin.local";
            String ehloReply = sendCmd(out, in, "EHLO " + ehloHost, 250);

            if (cfg.security() == SmtpConfig.Security.STARTTLS) {
                sendCmd(out, in, "STARTTLS", 220);
                SSLSocket tls = upgradeTls(socket, cfg.host(), cfg.port(), cfg.readTimeoutMs());
                socket = tls;
                in = new BufferedReader(new InputStreamReader(tls.getInputStream(), StandardCharsets.UTF_8));
                out = new BufferedWriter(new OutputStreamWriter(tls.getOutputStream(), StandardCharsets.UTF_8));
                ehloReply = sendCmd(out, in, "EHLO " + ehloHost, 250);
            }

            if (!cfg.username().isEmpty()) {
                authenticate(out, in, cfg.username(), cfg.password(), ehloReply);
            }

            sendCmd(out, in, "MAIL FROM:<" + safeFrom + ">", 250);
            sendCmd(out, in, "RCPT TO:<" + safeTo + ">", 250, 251);
            sendCmd(out, in, "DATA", 354);

            String domain = safeFrom.contains("@") ? safeFrom.substring(safeFrom.indexOf('@') + 1) : "justlogin.local";
            StringBuilder msg = new StringBuilder();
            msg.append("From: ").append(safeFromName).append(" <").append(safeFrom).append(">\r\n");
            msg.append("To: <").append(safeTo).append(">\r\n");
            msg.append("Subject: ").append(safeSubject).append("\r\n");
            msg.append("Message-ID: <").append(java.util.UUID.randomUUID()).append("@").append(domain).append(">\r\n");
            msg.append("Date: ").append(DateTimeFormatter.RFC_1123_DATE_TIME.format(ZonedDateTime.now())).append("\r\n");
            msg.append("MIME-Version: 1.0\r\n");
            msg.append("Content-Type: text/plain; charset=UTF-8\r\n\r\n");
            for (String line : body.replace("\r\n", "\n").split("\n", -1)) {
                if (line.startsWith(".")) msg.append('.');
                msg.append(line).append("\r\n");
            }
            msg.append(".\r\n");
            out.write(msg.toString());
            out.flush();
            expect(in, 250);
            sendCmd(out, in, "QUIT", 221);
        } finally {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
    }

    private static Socket connect(SmtpConfig cfg) throws IOException {
        InetSocketAddress addr = new InetSocketAddress(cfg.host(), cfg.port());
        int timeout = Math.max(1000, cfg.connectTimeoutMs());
        if (cfg.security() == SmtpConfig.Security.SSL) {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket tls = (SSLSocket) factory.createSocket();
            tls.connect(addr, timeout);
            tls.setSoTimeout(Math.max(1000, cfg.readTimeoutMs()));
            SSLParameters params = tls.getSSLParameters();
            params.setEndpointIdentificationAlgorithm("HTTPS");
            tls.setSSLParameters(params);
            tls.startHandshake();
            return tls;
        }
        Socket raw = new Socket();
        raw.connect(addr, timeout);
        return raw;
    }

    private static SSLSocket upgradeTls(Socket plain, String host, int port, int readTimeoutMs) throws IOException {
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        SSLSocket tls = (SSLSocket) factory.createSocket(plain, host, port, true);
        tls.setSoTimeout(Math.max(1000, readTimeoutMs));
        SSLParameters params = tls.getSSLParameters();
        params.setEndpointIdentificationAlgorithm("HTTPS");
        tls.setSSLParameters(params);
        tls.startHandshake();
        return tls;
    }

    private static void authenticate(
            BufferedWriter out, BufferedReader in, String user, String pass, String ehloReply) throws IOException {
        if (ehloReply.toUpperCase(Locale.ROOT).contains("PLAIN")) {
            String token = Base64.getEncoder().encodeToString(("\0" + user + "\0" + pass).getBytes(StandardCharsets.UTF_8));
            sendCmd(out, in, "AUTH PLAIN " + token, 235);
            return;
        }
        sendCmd(out, in, "AUTH LOGIN", 334);
        sendCmd(out, in, Base64.getEncoder().encodeToString(user.getBytes(StandardCharsets.UTF_8)), 334);
        sendCmd(out, in, Base64.getEncoder().encodeToString(pass.getBytes(StandardCharsets.UTF_8)), 235);
    }

    private static String sendCmd(BufferedWriter out, BufferedReader in, String cmd, int... expected) throws IOException {
        out.write(cmd);
        out.write("\r\n");
        out.flush();
        return expect(in, expected);
    }

    private static String expect(BufferedReader in, int... expected) throws IOException {
        StringBuilder full = new StringBuilder();
        int code = -1;
        while (true) {
            String line = in.readLine();
            if (line == null) throw new IOException("SMTP server closed connection unexpectedly");
            full.append(line).append('\n');
            if (line.length() >= 3 && Character.isDigit(line.charAt(0))
                    && Character.isDigit(line.charAt(1)) && Character.isDigit(line.charAt(2))) {
                code = Integer.parseInt(line.substring(0, 3));
                if (line.length() == 3 || line.charAt(3) == ' ') break;
            }
        }
        for (int ok : expected) {
            if (code == ok) return full.toString();
        }
        throw new IOException("Unexpected SMTP reply " + code + ": " + full.toString().trim());
    }

    static String sanitizeHeader(String value) {
        if (value == null) return "";
        return value.replace("\r", "").replace("\n", "").trim();
    }

    private static boolean isLoopbackHost(String host) {
        if (host == null) return false;
        String h = host.trim().toLowerCase(Locale.ROOT);
        return "localhost".equals(h) || "127.0.0.1".equals(h) || "::1".equals(h) || "[::1]".equals(h);
    }
}
