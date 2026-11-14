package me.skerik.justlogin.paper.premium;

import io.netty.channel.Channel;
import io.netty.channel.ChannelDuplexHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.util.AttributeKey;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BooleanSupplier;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import javax.crypto.SecretKey;
import me.skerik.justlogin.core.crypto.ServerSecrets;
import me.skerik.justlogin.core.security.UsernameValidator;
import me.skerik.justlogin.core.service.MojangApiClient;
import me.skerik.justlogin.core.service.MojangSessionClient;
import me.skerik.justlogin.core.service.ProxyAuthService;
import me.skerik.justlogin.core.storage.AccountStore;
import me.skerik.justlogin.core.storage.AuditStore;
import me.skerik.justlogin.paper.Scheduler;
import me.skerik.justlogin.paper.config.Messages;
import me.skerik.justlogin.paper.config.Settings;
import me.skerik.justlogin.paper.premium.LoginBridge.HelloPacketInfo;
import me.skerik.justlogin.paper.util.ClientCapabilityCheck;
import net.kyori.adventure.key.Key;
import net.kyori.adventure.text.Component;
import org.bukkit.Bukkit;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.jspecify.annotations.Nullable;

/**
 * Manages standalone Paper Mojang online-mode authentication without BungeeCord or Velocity.
 * Intercepts Login Start at Netty level only for players who require online verification, runs an
 * RSA+AES encryption challenge and Mojang {@code hasJoined} check off-thread, preserves immutable
 * {@code game_uuid}, and forwards Mojang skin textures into {@link AsyncPlayerPreLoginEvent}.
 */
public final class StandalonePremiumManager {

    public record VerifiedChannelData(
            UUID mojangUuid,
            String canonicalName,
            @Nullable String texturesValue,
            @Nullable String texturesSignature
    ) {
    }

    public record VerifiedGrant(
            long accountId,
            UUID gameUuid,
            String nameLower,
            boolean pendingConfirmed,
            long expiresAt
    ) {
    }

    public static final Key LISTENER_KEY = Key.key("justlogin", "standalone_premium");
    public static final String HANDLER_NAME = "justlogin_login";
    public static final AttributeKey<VerifiedChannelData> VERIFIED_ATTR =
            AttributeKey.valueOf("justlogin:verified_standalone");

    private static final long GRANT_TTL_MILLIS = 60_000L;
    private static final SecureRandom RNG = new SecureRandom();

    private final Scheduler scheduler;
    private final Function<String, Component> messageRenderer;
    private final Predicate<UUID> floodgateChecker;
    private final BooleanSupplier onlineModeSupplier;
    private final Supplier<Settings> settingsSupplier;
    private final Supplier<Boolean> forwardingActiveSupplier;
    private final @Nullable LoginBridge bridge;
    private final MojangSessionClient sessionClient;
    private final ProxyAuthService proxyAuth;
    private final Map<UUID, VerifiedGrant> verifiedGrantsByUuid = new ConcurrentHashMap<>();

    public StandalonePremiumManager(
            Scheduler scheduler,
            Messages messages,
            ClientCapabilityCheck capabilities,
            AccountStore accounts,
            AuditStore audit,
            ServerSecrets secrets,
            Supplier<Settings> settingsSupplier,
            Supplier<Boolean> forwardingActiveSupplier,
            @Nullable LoginBridge bridge,
            MojangSessionClient sessionClient
    ) {
        this(
                scheduler,
                messages::component,
                capabilities::isFloodgate,
                () -> Bukkit.getServer() != null && Bukkit.getServer().getOnlineMode(),
                accounts,
                audit,
                secrets,
                settingsSupplier,
                forwardingActiveSupplier,
                bridge,
                sessionClient
        );
    }

    StandalonePremiumManager(
            Scheduler scheduler,
            Function<String, Component> messageRenderer,
            Predicate<UUID> floodgateChecker,
            BooleanSupplier onlineModeSupplier,
            AccountStore accounts,
            AuditStore audit,
            ServerSecrets secrets,
            Supplier<Settings> settingsSupplier,
            Supplier<Boolean> forwardingActiveSupplier,
            @Nullable LoginBridge bridge,
            MojangSessionClient sessionClient
    ) {
        this.scheduler = scheduler;
        this.messageRenderer = messageRenderer;
        this.floodgateChecker = floodgateChecker;
        this.onlineModeSupplier = onlineModeSupplier;
        this.settingsSupplier = settingsSupplier;
        this.forwardingActiveSupplier = forwardingActiveSupplier;
        this.bridge = bridge;
        this.sessionClient = sessionClient;
        long cacheSeconds = settingsSupplier.get().core().mojangCacheSeconds();
        MojangApiClient mojangApi = new MojangApiClient(cacheSeconds, System::currentTimeMillis);
        this.proxyAuth = new ProxyAuthService(
                accounts, audit, mojangApi, secrets,
                () -> this.settingsSupplier.get().core(), System::currentTimeMillis);
    }

    public boolean isHookAvailable() {
        return bridge != null;
    }

    public boolean isActiveRuntime() {
        Settings s = settingsSupplier.get();
        return bridge != null
                && !onlineModeSupplier.getAsBoolean()
                && !s.proxyEnabled()
                && s.standalonePremiumEnabled()
                && !Boolean.TRUE.equals(forwardingActiveSupplier.get());
    }

    public void install() {
        if (bridge == null || onlineModeSupplier.getAsBoolean()) {
            return;
        }
        try {
            bridge.registerChannelListener(LISTENER_KEY, this::attachHandler);
        } catch (Exception ignored) {
        }
    }

    public void uninstall() {
        if (bridge != null) {
            bridge.unregisterChannelListener(LISTENER_KEY);
        }
        verifiedGrantsByUuid.clear();
    }

    private void attachHandler(Channel channel) {
        if (!isActiveRuntime()) return;
        if (channel.pipeline().get("packet_handler") == null) return;
        if (channel.pipeline().get(HANDLER_NAME) != null) return;
        channel.pipeline().addBefore("packet_handler", HANDLER_NAME, new LoginChannelHandler(channel));
    }

    public @Nullable VerifiedChannelData consumeVerifiedChannel(AsyncPlayerPreLoginEvent event) {
        if (bridge == null) return null;
        Channel channel = bridge.extractChannel(event);
        if (channel == null) return null;
        return channel.attr(VERIFIED_ATTR).getAndSet(null);
    }

    public CompletableFuture<ProxyAuthService.JoinResolution> resolveVerifiedJoin(
            String canonicalName, UUID mojangUuid, String ip) {
        return proxyAuth.resolveJoinProfile(canonicalName, mojangUuid, true, ip);
    }

    public void recordVerifiedGrant(long accountId, UUID gameUuid, String name, boolean pendingConfirmed) {
        verifiedGrantsByUuid.put(gameUuid, new VerifiedGrant(
                accountId, gameUuid, UsernameValidator.normalizeLower(name), pendingConfirmed,
                System.currentTimeMillis() + GRANT_TTL_MILLIS));
    }

    public @Nullable VerifiedGrant consumeVerifiedGrant(@Nullable UUID uuid, String username) {
        if (uuid == null) return null;
        VerifiedGrant grant = verifiedGrantsByUuid.remove(uuid);
        if (grant == null) return null;
        if (System.currentTimeMillis() > grant.expiresAt()) return null;
        if (!grant.nameLower().equals(UsernameValidator.normalizeLower(username))) return null;
        return grant;
    }

    public void clearVerifiedGrant(@Nullable UUID uuid) {
        if (uuid != null) verifiedGrantsByUuid.remove(uuid);
    }

    public void pruneExpired() {
        proxyAuth.pruneExpired();
        long now = System.currentTimeMillis();
        verifiedGrantsByUuid.entrySet().removeIf(e -> now > e.getValue().expiresAt());
    }

    private enum Stage {
        INITIAL,
        DECIDING_HELLO,
        AWAITING_KEY,
        AUTHENTICATING_MOJANG,
        PASSTHROUGH,
        CLOSED
    }

    private final class LoginChannelHandler extends ChannelDuplexHandler {

        private final Channel channel;
        private Stage stage = Stage.INITIAL;
        private @Nullable String helloUsername;
        private @Nullable Object pendingHelloPacket;
        private byte @Nullable [] expectedChallenge;

        LoginChannelHandler(Channel channel) {
            this.channel = channel;
        }

        @Override
        public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
            if (bridge == null || stage == Stage.PASSTHROUGH) {
                super.channelRead(ctx, msg);
                return;
            }
            if (stage == Stage.CLOSED) {
                return;
            }

            if (stage == Stage.INITIAL) {
                HelloPacketInfo hello = bridge.inspectHelloPacket(msg);
                if (hello == null) {
                    // Handshake (Intention) or non-login status packets pass straight through
                    super.channelRead(ctx, msg);
                    return;
                }
                if (!isActiveRuntime()) {
                    passThroughAndRemove(ctx, msg);
                    return;
                }

                this.stage = Stage.DECIDING_HELLO;
                this.helloUsername = hello.username();
                this.pendingHelloPacket = msg;
                boolean floodgate = hello.profileId() != null && floodgateChecker.test(hello.profileId());

                CompletableFuture.supplyAsync(() -> proxyAuth.decidePreLogin(hello.username(), floodgate).join(),
                        runnable -> scheduler.runAsync(runnable))
                        .whenComplete((dec, ex) -> channel.eventLoop().execute(() -> handlePreLoginDecision(ctx, dec, ex)));
                return;
            }

            if (stage == Stage.AWAITING_KEY && bridge.isKeyPacket(msg)) {
                handleKeyPacket(ctx, msg);
                return;
            }

            // Unexpected packet while waiting on async decision / Mojang challenge -> fail closed
            failClosed(ctx, "premium.verification-failed");
        }

        @Override
        public void channelInactive(ChannelHandlerContext ctx) throws Exception {
            if (helloUsername != null && stage != Stage.PASSTHROUGH) {
                proxyAuth.onDisconnect(helloUsername);
            }
            stage = Stage.CLOSED;
            super.channelInactive(ctx);
        }

        private void handlePreLoginDecision(
                ChannelHandlerContext ctx, ProxyAuthService.@Nullable PreLoginDecision dec, @Nullable Throwable ex) {
            if (!channel.isActive() || stage != Stage.DECIDING_HELLO) return;
            if (ex != null || dec == null || bridge == null) {
                failClosed(ctx, "general.internal-error");
                return;
            }

            switch (dec.action()) {
                case DENY_INVALID_USERNAME -> failClosed(ctx, "general.invalid-username");
                case DENY_MOJANG_UNAVAILABLE -> failClosed(ctx, "proxy.deny-mojang-unavailable");
                case ALLOW_OFFLINE, FORCE_OFFLINE -> {
                    Object original = pendingHelloPacket;
                    pendingHelloPacket = null;
                    if (original != null) {
                        passThroughAndRemove(ctx, original);
                    }
                }
                case FORCE_ONLINE -> {
                    byte[] challenge = new byte[4];
                    RNG.nextBytes(challenge);
                    this.expectedChallenge = challenge;
                    this.stage = Stage.AWAITING_KEY;
                    try {
                        Object req = bridge.newEncryptionRequestPacket(challenge);
                        channel.writeAndFlush(req);
                    } catch (Throwable e) {
                        failClosed(ctx, "general.internal-error");
                    }
                }
            }
        }

        private void handleKeyPacket(ChannelHandlerContext ctx, Object msg) {
            if (bridge == null || expectedChallenge == null || helloUsername == null) {
                failClosed(ctx, "premium.verification-failed");
                return;
            }
            SecretKey secret = bridge.decryptVerifiedKeyPacket(msg, expectedChallenge);
            if (secret == null) {
                // RSA/challenge mismatch before encryption starts -> close socket immediately
                stage = Stage.CLOSED;
                proxyAuth.onDisconnect(helloUsername);
                ctx.close();
                return;
            }

            stage = Stage.AUTHENTICATING_MOJANG;
            try {
                bridge.enableEncryption(channel, secret);
            } catch (Throwable e) {
                stage = Stage.CLOSED;
                proxyAuth.onDisconnect(helloUsername);
                ctx.close();
                return;
            }

            String serverId = MojangSessionClient.computeServerIdHash(
                    "", bridge.publicKeyEncoded(), secret.getEncoded());
            String clientIp = resolvePreventProxyIp();
            String targetUser = helloUsername;

            CompletableFuture.supplyAsync(() -> sessionClient.verifyHasJoined(targetUser, serverId, clientIp).join(),
                    runnable -> scheduler.runAsync(runnable))
                    .whenComplete((res, ex) -> channel.eventLoop().execute(() -> handleHasJoinedResult(ctx, res, ex)));
        }

        private void handleHasJoinedResult(
                ChannelHandlerContext ctx, MojangSessionClient.@Nullable HasJoinedResult res, @Nullable Throwable ex) {
            if (!channel.isActive() || stage != Stage.AUTHENTICATING_MOJANG || bridge == null) return;
            if (ex != null || res == null || res.status() == MojangSessionClient.Status.UNAVAILABLE) {
                failClosed(ctx, "premium.auth-servers-unavailable");
                return;
            }
            if (res.status() != MojangSessionClient.Status.VERIFIED
                    || res.uuid() == null || res.name() == null) {
                failClosed(ctx, "premium.verification-failed");
                return;
            }

            channel.attr(VERIFIED_ATTR).set(new VerifiedChannelData(
                    res.uuid(), res.name(), res.texturesValue(), res.texturesSignature()));
            Object original = pendingHelloPacket;
            pendingHelloPacket = null;
            Object canonicalHello = bridge.newHelloPacket(res.name(), res.uuid(), original);
            passThroughAndRemove(ctx, canonicalHello);
        }

        private @Nullable String resolvePreventProxyIp() {
            Settings s = settingsSupplier.get();
            if (!s.standalonePreventProxyConnections()) return null;
            if (channel.remoteAddress() instanceof InetSocketAddress isa && isa.getAddress() != null) {
                return isa.getAddress().getHostAddress();
            }
            return null;
        }

        private void passThroughAndRemove(ChannelHandlerContext ctx, Object helloPacket) {
            stage = Stage.PASSTHROUGH;
            ctx.fireChannelRead(helloPacket);
            if (ctx.pipeline().get(HANDLER_NAME) != null) {
                ctx.pipeline().remove(this);
            }
        }

        private void failClosed(ChannelHandlerContext ctx, String messageKey) {
            stage = Stage.CLOSED;
            pendingHelloPacket = null;
            if (helloUsername != null) {
                proxyAuth.onDisconnect(helloUsername);
            }
            if (bridge != null) {
                bridge.sendDisconnect(ctx, messageRenderer.apply(messageKey));
            } else {
                ctx.close();
            }
        }
    }
}
