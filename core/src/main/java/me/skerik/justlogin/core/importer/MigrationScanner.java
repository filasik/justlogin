package me.skerik.justlogin.core.importer;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Stream;
import me.skerik.justlogin.core.crypto.ServerSecrets;
import me.skerik.justlogin.core.storage.AccountStore;
import me.skerik.justlogin.core.storage.AuditStore;
import org.jspecify.annotations.Nullable;

/**
 * Automatic 1-click migration scanner and runner (Plan Section 4.1).
 * Scans {@code plugins/} for legacy authentication plugins (AuthMe, LibreLogin, LoginSecurity, nLogin, FastLogin),
 * parses their SQLite or MySQL/MariaDB settings without external config libraries, executes password importers
 * before FastLogin so Mojang UUIDs and online-mode flags pair onto imported accounts, and writes a detailed
 * {@code import-report-<timestamp>.txt} when any rows are skipped.
 */
public final class MigrationScanner {

    public static final List<String> LEGACY_PLUGIN_NAMES = List.of(
            "AuthMe", "FastLogin", "LibreLogin", "LibrePremium",
            "LoginSecurity", "nLogin", "OpeNLogin", "OpenLogin", "LimboAuth", "Authy"
    );

    public enum SourceType {
        AUTHME("AuthMe", 10),
        LIBRELOGIN("LibreLogin", 20),
        LOGINSECURITY("LoginSecurity", 30),
        NLOGIN("nLogin", 40),
        OPENLOGIN("OpeNLogin", 45),
        LIMBOAUTH("LimboAuth", 50),
        AUTHY("Authy", 60),
        FASTLOGIN("FastLogin", 100);

        private final String displayName;
        private final int order;

        SourceType(String displayName, int order) {
            this.displayName = displayName;
            this.order = order;
        }

        public String displayName() {
            return displayName;
        }

        public int order() {
            return order;
        }
    }

    public enum Backend {
        SQLITE,
        MYSQL
    }

    public record DetectedSource(
            SourceType type,
            Backend backend,
            @Nullable Path sqliteFile,
            String jdbcUrl,
            @Nullable String user,
            @Nullable String password,
            String tableName,
            String summary,
            @Nullable String sslMode,
            boolean preserveGameUuid
    ) {
        public String displayName() {
            return type.displayName();
        }

        public boolean isSqlite() {
            return backend == Backend.SQLITE;
        }

        public boolean isMysql() {
            return backend == Backend.MYSQL;
        }

        public static DetectedSource sqlite(SourceType type, Path sqliteFile, String tableName) {
            Path abs = sqliteFile.toAbsolutePath().normalize();
            return new DetectedSource(
                    type,
                    Backend.SQLITE,
                    abs,
                    "jdbc:sqlite:" + abs,
                    null,
                    null,
                    tableName,
                    "SQLite (" + sqliteFile.getFileName() + ", table=" + tableName + ")",
                    null,
                    false
            );
        }

        public static DetectedSource mysql(
                SourceType type, String host, int port, String database,
                String user, String password, String tableName) {
            return mysql(type, host, port, database, user, password, tableName, null);
        }

        /**
         * @param sslMode MariaDB Connector/J {@code sslMode} (see {@link #normalizeSslMode}); {@code null} or blank
         *                keeps the driver default (no TLS parameter in the URL)
         */
        public static DetectedSource mysql(
                SourceType type, String host, int port, String database,
                String user, String password, String tableName, @Nullable String sslMode) {
            String ssl = normalizeSslMode(sslMode);
            String jdbc = "jdbc:mariadb://" + host + ":" + port + "/" + database
                    + (ssl == null ? "" : "?sslMode=" + ssl);
            return new DetectedSource(
                    type,
                    Backend.MYSQL,
                    null,
                    jdbc,
                    user,
                    password,
                    tableName,
                    "MySQL (" + host + ":" + port + "/" + database + ", table=" + tableName
                            + (ssl == null ? "" : ", sslMode=" + ssl) + ")",
                    ssl,
                    false
            );
        }

        /** FastLogin only: keep the offline {@code game_uuid} and just attach the Mojang UUID as {@code premium_uuid}. */
        public DetectedSource withPreserveGameUuid(boolean preserve) {
            String base = summary.replaceFirst(", game_uuid=[a-z-]+\\)$", ")");
            String sum = type == SourceType.FASTLOGIN
                    ? base.substring(0, base.length() - 1) + ", game_uuid=" + (preserve ? "keep-offline" : "rewrite-to-mojang") + ")"
                    : base;
            return new DetectedSource(type, backend, sqliteFile, jdbcUrl, user, password, tableName,
                    sum, sslMode, preserve);
        }
    }

    public record SkippedRecord(SourceType source, String username, String reason) {
    }

    public record SourceResult(
            DetectedSource source,
            int imported,
            int updated,
            int skippedExisting,
            int skippedInvalid,
            List<SkippedRecord> skippedDetails,
            @Nullable String note
    ) {
        public SourceResult(DetectedSource source, int imported, int updated, int skippedExisting,
                            int skippedInvalid, List<SkippedRecord> skippedDetails) {
            this(source, imported, updated, skippedExisting, skippedInvalid, skippedDetails, null);
        }
    }

    /**
     * Optional overrides for {@link #scan(Path, ScanOptions)}.
     *
     * @param sslModeOverride explicit sslMode (e.g. {@code --ssl-mode=trust}); beats the legacy plugin config
     * @param sslModeFallback used only when the legacy plugin config does not say anything about TLS
     *                        (typically JustLogin's own {@code storage.mariadb.ssl-mode})
     * @param preserveGameUuidOverride FastLogin: {@code TRUE} = keep offline game_uuid, {@code FALSE} = rewrite to
     *                        Mojang UUID, {@code null} = follow FastLogin's {@code premiumUuid} (default true = rewrite)
     */
    public record ScanOptions(
            @Nullable String sslModeOverride,
            @Nullable String sslModeFallback,
            @Nullable Boolean preserveGameUuidOverride
    ) {
        public static final ScanOptions NONE = new ScanOptions(null, null, null);
    }

    /**
     * Maps a user/legacy value to a MariaDB Connector/J {@code sslMode}: {@code disable}, {@code trust},
     * {@code verify-ca} or {@code verify-full}. MySQL spellings ({@code DISABLED}, {@code REQUIRED},
     * {@code PREFERRED}, {@code VERIFY_IDENTITY}) and booleans are accepted ({@code true} becomes {@code trust}:
     * encrypted, certificate not verified - legacy plugins did the same and this is a one-off local import).
     * Returns {@code null} for blank/unknown input.
     */
    public static @Nullable String normalizeSslMode(@Nullable String raw) {
        if (raw == null || raw.isBlank()) return null;
        return switch (raw.strip().toLowerCase(Locale.ROOT).replace('_', '-')) {
            case "disable", "disabled", "false", "off", "no", "none" -> "disable";
            case "trust", "true", "on", "yes", "required", "require", "preferred", "prefer" -> "trust";
            case "verify-ca" -> "verify-ca";
            case "verify-full", "verify-identity" -> "verify-full";
            default -> null;
        };
    }

    private static final List<String> SSL_KEYS = List.of(
            "sslmode", "ssl-mode", "mysqlsslmode", "datasource.mysqlsslmode",
            "usessl", "mysqlusessl", "datasource.mysqlusessl", "use-ssl", "ssl", "datasource.usessl");

    private static @Nullable String detectSslMode(Map<String, String> kv, ScanOptions opts) {
        String override = normalizeSslMode(opts.sslModeOverride());
        if (override != null) return override;
        String fromConfig = normalizeSslMode(firstValue(kv, SSL_KEYS.toArray(String[]::new)));
        if (fromConfig != null) return fromConfig;
        return normalizeSslMode(opts.sslModeFallback());
    }

    /**
     * Reads FastLogin's {@code premiumUuid} option. FastLogin's own default is {@code true} (premium players get
     * their Mojang UUID), so a missing config/key returns {@code true}. {@code false} means FastLogin kept the
     * offline UUIDs, so JustLogin must not rewrite {@code game_uuid} either.
     */
    public static boolean fastLoginPremiumUuid(Path pluginsDir) {
        Path dir = pluginsDir == null ? null : findSubdir(pluginsDir, "FastLogin");
        if (dir == null) return true;
        String v = firstValue(parseConfigKeys(dir.resolve("config.yml")), "premiumuuid");
        return v == null || !v.strip().equalsIgnoreCase("false");
    }

    public record AutoMigrationSummary(
            List<SourceResult> results,
            int totalImported,
            int totalUpdated,
            int totalSkippedExisting,
            int totalSkippedInvalid,
            List<SkippedRecord> skippedDetails,
            boolean dryRun,
            @Nullable Path reportFile
    ) {
        public int imported() {
            return totalImported;
        }

        public int updated() {
            return totalUpdated;
        }

        public int skippedExisting() {
            return totalSkippedExisting;
        }

        public int skippedInvalid() {
            return totalSkippedInvalid;
        }

        public int totalSkipped() {
            return totalSkippedExisting + totalSkippedInvalid;
        }
    }

    private MigrationScanner() {
    }

    /**
     * Scans {@code pluginsDir} for AuthMe, LibreLogin/LibrePremium, LoginSecurity, nLogin, OpeNLogin,
     * LimboAuth, Authy, and FastLogin data folders, returning detected sources ordered so password
     * importers always run before {@link SourceType#FASTLOGIN}.
     */
    public static List<DetectedSource> scan(Path pluginsDir) {
        return scan(pluginsDir, ScanOptions.NONE);
    }

    public static List<DetectedSource> scan(Path pluginsDir, ScanOptions opts) {
        if (pluginsDir == null || !Files.isDirectory(pluginsDir)) {
            return List.of();
        }
        List<DetectedSource> detected = new ArrayList<>();

        Path authMeDir = findSubdir(pluginsDir, "AuthMe");
        if (authMeDir != null) {
            DetectedSource src = detectAuthMe(authMeDir, opts);
            if (src != null) detected.add(src);
        }

        Path libreDir = findSubdir(pluginsDir, "LibreLogin");
        if (libreDir == null) {
            libreDir = findSubdir(pluginsDir, "LibrePremium");
        }
        if (libreDir != null) {
            DetectedSource src = detectLibreLogin(libreDir, opts);
            if (src != null) detected.add(src);
        }

        Path lsDir = findSubdir(pluginsDir, "LoginSecurity");
        if (lsDir != null) {
            DetectedSource src = detectLoginSecurity(lsDir, opts);
            if (src != null) detected.add(src);
        }

        Path nLoginDir = findSubdir(pluginsDir, "nLogin");
        if (nLoginDir != null) {
            DetectedSource src = detectNLogin(nLoginDir, opts);
            if (src != null) detected.add(src);
        }

        Path openLoginDir = findSubdir(pluginsDir, "OpeNLogin");
        if (openLoginDir == null) {
            openLoginDir = findSubdir(pluginsDir, "OpenLogin");
        }
        if (openLoginDir != null) {
            DetectedSource src = detectOpenLogin(openLoginDir, opts);
            if (src != null) detected.add(src);
        }

        Path limboDir = findSubdir(pluginsDir, "LimboAuth");
        if (limboDir != null) {
            DetectedSource src = detectLimboAuth(limboDir, opts);
            if (src != null) detected.add(src);
        }

        Path authyDir = findSubdir(pluginsDir, "Authy");
        if (authyDir != null) {
            DetectedSource src = detectAuthy(authyDir, opts);
            if (src != null) detected.add(src);
        }

        Path fastLoginDir = findSubdir(pluginsDir, "FastLogin");
        if (fastLoginDir != null) {
            DetectedSource src = detectFastLogin(fastLoginDir, opts);
            if (src != null) detected.add(src);
        }

        detected.sort(Comparator.comparingInt(s -> s.type().order()));
        return List.copyOf(detected);
    }

    public static CompletableFuture<AutoMigrationSummary> importSingle(
            DetectedSource source,
            AccountStore accounts,
            AuditStore audit,
            ServerSecrets secrets,
            String actor,
            boolean dryRun,
            @Nullable Path reportDir,
            long now
    ) {
        return importAll(List.of(source), accounts, audit, secrets, actor, dryRun, reportDir, now);
    }

    public static CompletableFuture<AutoMigrationSummary> importAll(
            List<DetectedSource> sources,
            AccountStore accounts,
            AuditStore audit,
            ServerSecrets secrets,
            String actor,
            boolean dryRun,
            @Nullable Path reportDir,
            long now
    ) {
        List<DetectedSource> ordered = new ArrayList<>(sources);
        ordered.sort(Comparator.comparingInt(s -> s.type().order()));

        return CompletableFuture.supplyAsync(() -> {
            List<SourceResult> results = new ArrayList<>();
            List<SkippedRecord> allSkipped = new ArrayList<>();
            int totalImported = 0;
            int totalUpdated = 0;
            int totalSkippedExisting = 0;
            int totalSkippedInvalid = 0;

            for (DetectedSource src : ordered) {
                SourceResult res = runSourceBlocking(src, accounts, audit, secrets, actor, dryRun, now);
                results.add(res);
                totalImported += res.imported();
                totalUpdated += res.updated();
                totalSkippedExisting += res.skippedExisting();
                totalSkippedInvalid += res.skippedInvalid();
                allSkipped.addAll(res.skippedDetails());
            }

            Path reportFile = null;
            if (!allSkipped.isEmpty() && reportDir != null) {
                reportFile = writeSkippedReport(
                        reportDir, now, actor, dryRun,
                        totalImported, totalUpdated, totalSkippedExisting, totalSkippedInvalid, allSkipped,
                        results.stream().map(SourceResult::note).filter(java.util.Objects::nonNull).toList());
            }

            return new AutoMigrationSummary(
                    List.copyOf(results),
                    totalImported,
                    totalUpdated,
                    totalSkippedExisting,
                    totalSkippedInvalid,
                    List.copyOf(allSkipped),
                    dryRun,
                    reportFile
            );
        });
    }

    private static SourceResult runSourceBlocking(
            DetectedSource src,
            AccountStore accounts,
            AuditStore audit,
            ServerSecrets secrets,
            String actor,
            boolean dryRun,
            long now
    ) {
        return switch (src.type()) {
            case AUTHME -> {
                AuthMeImporter.ImportReport rep = AuthMeImporter.importFromJdbc(
                        src.jdbcUrl(), src.user(), src.password(), src.tableName(),
                        accounts, audit, secrets, actor, dryRun, now).join();
                List<SkippedRecord> skipped = rep.skippedDetails().stream()
                        .map(e -> new SkippedRecord(SourceType.AUTHME, e.username(), e.reason()))
                        .toList();
                yield new SourceResult(src, rep.imported(), 0, rep.skippedExisting(), rep.skippedInvalid(), skipped);
            }
            case LIBRELOGIN -> {
                LibreLoginImporter.ImportReport rep = LibreLoginImporter.importFromJdbc(
                        src.jdbcUrl(), src.user(), src.password(), src.tableName(),
                        accounts, audit, secrets, actor, dryRun, now).join();
                List<SkippedRecord> skipped = rep.skippedDetails().stream()
                        .map(e -> new SkippedRecord(SourceType.LIBRELOGIN, e.username(), e.reason()))
                        .toList();
                yield new SourceResult(src, rep.imported(), 0, rep.skippedExisting(), rep.skippedInvalid(), skipped);
            }
            case LOGINSECURITY -> {
                LoginSecurityImporter.ImportReport rep = LoginSecurityImporter.importFromJdbc(
                        src.jdbcUrl(), src.user(), src.password(), src.tableName(),
                        accounts, audit, secrets, actor, dryRun, now).join();
                List<SkippedRecord> skipped = rep.skippedDetails().stream()
                        .map(e -> new SkippedRecord(SourceType.LOGINSECURITY, e.username(), e.reason()))
                        .toList();
                yield new SourceResult(src, rep.imported(), 0, rep.skippedExisting(), rep.skippedInvalid(), skipped);
            }
            case NLOGIN, OPENLOGIN -> {
                NLoginImporter.ImportReport rep = NLoginImporter.importFromJdbc(
                        src.jdbcUrl(), src.user(), src.password(), src.tableName(),
                        accounts, audit, secrets, actor, dryRun, now).join();
                List<SkippedRecord> skipped = rep.skippedDetails().stream()
                        .map(e -> new SkippedRecord(src.type(), e.username(), e.reason()))
                        .toList();
                yield new SourceResult(src, rep.imported(), 0, rep.skippedExisting(), rep.skippedInvalid(), skipped);
            }
            case LIMBOAUTH, AUTHY -> {
                LimboAuthImporter.ImportReport rep = LimboAuthImporter.importFromJdbc(
                        src.jdbcUrl(), src.user(), src.password(), src.tableName(),
                        accounts, audit, secrets, actor, dryRun, now).join();
                List<SkippedRecord> skipped = rep.skippedDetails().stream()
                        .map(e -> new SkippedRecord(src.type(), e.username(), e.reason()))
                        .toList();
                yield new SourceResult(src, rep.imported(), 0, rep.skippedExisting(), rep.skippedInvalid(), skipped);
            }
            case FASTLOGIN -> {
                FastLoginImporter.ImportReport rep = FastLoginImporter.importFromJdbc(
                        src.jdbcUrl(), src.user(), src.password(), src.tableName(),
                        accounts, audit, actor, dryRun, src.preserveGameUuid(), now).join();
                List<SkippedRecord> skipped = rep.skippedDetails().stream()
                        .map(e -> new SkippedRecord(SourceType.FASTLOGIN, e.username(), e.reason()))
                        .toList();
                String note = rep.preserveGameUuid()
                        ? "FastLogin: keeping offline game_uuid (premium_uuid only; OP/whitelist/playerdata untouched)"
                        : "FastLogin: game_uuid of premium accounts still on an offline UUID " + (dryRun ? "would be" : "is")
                                + " rewritten to the Mojang UUID (" + rep.gameUuidRewrites() + " candidate(s)); "
                                + "use --keep-offline-uuid if the server ran with premiumUuid: false";
                yield new SourceResult(src, rep.importedNew(), rep.updatedExisting(), 0, rep.skipped(), skipped, note);
            }
        };
    }

    private static @Nullable Path writeSkippedReport(
            Path reportDir,
            long now,
            String actor,
            boolean dryRun,
            int totalImported,
            int totalUpdated,
            int totalSkippedExisting,
            int totalSkippedInvalid,
            List<SkippedRecord> skipped,
            List<String> notes
    ) {
        try {
            Files.createDirectories(reportDir);
            Path file = reportDir.resolve("import-report-" + now + ".txt");
            StringBuilder sb = new StringBuilder();
            sb.append("# JustLogin Migration Report\n");
            sb.append("timestamp: ").append(Instant.ofEpochMilli(now)).append(" (").append(now).append(")\n");
            sb.append("actor: ").append(actor).append('\n');
            sb.append("dryRun: ").append(dryRun).append('\n');
            sb.append("imported: ").append(totalImported)
                    .append(", updated: ").append(totalUpdated)
                    .append(", skippedExisting: ").append(totalSkippedExisting)
                    .append(", skippedInvalid: ").append(totalSkippedInvalid).append('\n');
            for (String n : notes) {
                sb.append("note: ").append(n).append('\n');
            }
            sb.append('\n');
            sb.append("SOURCE\tUSERNAME\tREASON\n");
            for (SkippedRecord r : skipped) {
                sb.append(r.source().displayName()).append('\t')
                        .append(r.username()).append('\t')
                        .append(r.reason()).append('\n');
            }
            Files.writeString(file, sb.toString(), StandardCharsets.UTF_8);
            return file;
        } catch (IOException e) {
            throw new RuntimeException("Failed to write migration report: " + e.getMessage(), e);
        }
    }

    private static @Nullable DetectedSource detectAuthMe(Path dir, ScanOptions opts) {
        Map<String, String> kv = parseConfigKeys(dir.resolve("config.yml"));
        String backend = firstValue(kv, "backend", "datasource.backend");
        String table = sanitizeTable(firstValue(kv, "mysqltablename", "datasource.mysqltablename"), "authme");
        String database = firstValue(kv, "mysqldatabase", "datasource.mysqldatabase");
        if (isMysqlBackend(backend)) {
            HostPort hp = HostPort.parse(
                    firstValue(kv, "mysqlhost", "datasource.mysqlhost"),
                    firstValue(kv, "mysqlport", "datasource.mysqlport"),
                    3306);
            String dbName = defaultIfBlank(database, "authme");
            String user = defaultIfBlank(firstValue(kv, "mysqlusername", "datasource.mysqlusername"), "root");
            String pass = defaultIfNull(firstValue(kv, "mysqlpassword", "datasource.mysqlpassword"), "");
            return DetectedSource.mysql(SourceType.AUTHME, hp.host(), hp.port(), dbName, user, pass, table, detectSslMode(kv, opts));
        }
        Path dbFile = findSqliteFile(dir,
                database != null && !database.isBlank() ? database + ".db" : "authme.db",
                "authme.db");
        return dbFile != null ? DetectedSource.sqlite(SourceType.AUTHME, dbFile, table) : null;
    }

    private static @Nullable DetectedSource detectFastLogin(Path dir, ScanOptions opts) {
        Map<String, String> kv = parseConfigKeys(dir.resolve("config.yml"));
        String driver = firstValue(kv, "driver", "backend", "type");
        String table = sanitizeTable(firstValue(kv, "table", "tablename"), "premium");
        // premiumUuid: false in FastLogin => the server kept offline UUIDs => do not rewrite game_uuid.
        String premiumUuid = firstValue(kv, "premiumuuid");
        boolean configPreserve = premiumUuid != null && premiumUuid.strip().equalsIgnoreCase("false");
        boolean preserve = opts.preserveGameUuidOverride() != null ? opts.preserveGameUuidOverride() : configPreserve;
        DetectedSource src;
        if (isMysqlBackend(driver)) {
            HostPort hp = HostPort.parse(
                    firstValue(kv, "host", "mysqlhost"),
                    firstValue(kv, "port", "mysqlport"),
                    3306);
            String dbName = defaultIfBlank(firstValue(kv, "database", "mysqldatabase"), "fastlogin");
            String user = defaultIfBlank(firstValue(kv, "username", "user"), "root");
            String pass = defaultIfNull(firstValue(kv, "password"), "");
            src = DetectedSource.mysql(SourceType.FASTLOGIN, hp.host(), hp.port(), dbName, user, pass, table,
                    detectSslMode(kv, opts));
        } else {
            String customDb = firstValue(kv, "database");
            Path dbFile = findSqliteFile(dir,
                    customDb != null && customDb.endsWith(".db") ? customDb : "FastLogin.db",
                    "FastLogin.db", "fastlogin.db");
            if (dbFile == null) return null;
            src = DetectedSource.sqlite(SourceType.FASTLOGIN, dbFile, table);
        }
        return src.withPreserveGameUuid(preserve);
    }

    private static @Nullable DetectedSource detectLibreLogin(Path dir, ScanOptions opts) {
        Path conf = Files.isRegularFile(dir.resolve("config.conf"))
                ? dir.resolve("config.conf")
                : dir.resolve("config.yml");
        Map<String, String> kv = parseConfigKeys(conf);
        String type = firstValue(kv, "database.type", "type", "driver");
        String table = sanitizeTable(firstValue(kv, "table", "tablename"), "librepremium_data");
        if (isMysqlBackend(type)) {
            HostPort hp = HostPort.parse(
                    firstValue(kv, "database.properties.mysql.host", "mysql.host", "host"),
                    firstValue(kv, "database.properties.mysql.port", "mysql.port", "port"),
                    3306);
            String dbName = defaultIfBlank(firstValue(kv, "database.properties.mysql.database", "mysql.database", "database"), "librelogin");
            String user = defaultIfBlank(firstValue(kv, "database.properties.mysql.user", "mysql.user", "user", "username"), "root");
            String pass = defaultIfNull(firstValue(kv, "database.properties.mysql.password", "mysql.password", "password"), "");
            return DetectedSource.mysql(SourceType.LIBRELOGIN, hp.host(), hp.port(), dbName, user, pass, table, detectSslMode(kv, opts));
        }
        String sqlitePath = firstValue(kv, "database.properties.sqlite.path", "sqlite.path", "path");
        Path dbFile = findSqliteFile(dir,
                sqlitePath != null ? sqlitePath : "user-data.db",
                "user-data.db", "database.db", "librelogin.db");
        return dbFile != null ? DetectedSource.sqlite(SourceType.LIBRELOGIN, dbFile, table) : null;
    }

    private static @Nullable DetectedSource detectLoginSecurity(Path dir, ScanOptions opts) {
        Map<String, String> kv = new LinkedHashMap<>();
        kv.putAll(parseConfigKeys(dir.resolve("config.yml")));
        kv.putAll(parseConfigKeys(dir.resolve("database.yml")));
        String type = firstValue(kv, "database.type", "type", "backend");
        String mysqlEnabled = firstValue(kv, "mysql.enabled", "database.mysql.enabled");
        String table = sanitizeTable(firstValue(kv, "table", "tablename"), "ls_players");
        if (isMysqlBackend(type) || "true".equalsIgnoreCase(mysqlEnabled)) {
            HostPort hp = HostPort.parse(
                    firstValue(kv, "mysql.host", "database.host", "host"),
                    firstValue(kv, "mysql.port", "database.port", "port"),
                    3306);
            String dbName = defaultIfBlank(firstValue(kv, "mysql.database", "database.database", "database"), "loginsecurity");
            String user = defaultIfBlank(firstValue(kv, "mysql.username", "database.username", "username", "user"), "root");
            String pass = defaultIfNull(firstValue(kv, "mysql.password", "database.password", "password"), "");
            return DetectedSource.mysql(SourceType.LOGINSECURITY, hp.host(), hp.port(), dbName, user, pass, table, detectSslMode(kv, opts));
        }
        Path dbFile = findSqliteFile(dir, "LoginSecurity.db", "loginsecurity.db");
        return dbFile != null ? DetectedSource.sqlite(SourceType.LOGINSECURITY, dbFile, table) : null;
    }

    private static @Nullable DetectedSource detectNLogin(Path dir, ScanOptions opts) {
        Map<String, String> kv = parseConfigKeys(dir.resolve("config.yml"));
        String type = firstValue(kv, "database.type", "type", "backend");
        String table = sanitizeTable(firstValue(kv, "database.table", "table", "tablename"), "nlogin");
        if (isMysqlBackend(type)) {
            HostPort hp = HostPort.parse(
                    firstValue(kv, "database.hostname", "database.host", "hostname", "host"),
                    firstValue(kv, "database.port", "port"),
                    3306);
            String dbName = defaultIfBlank(firstValue(kv, "database.database", "database"), "nlogin");
            String user = defaultIfBlank(firstValue(kv, "database.username", "database.user", "username", "user"), "root");
            String pass = defaultIfNull(firstValue(kv, "database.password", "password"), "");
            return DetectedSource.mysql(SourceType.NLOGIN, hp.host(), hp.port(), dbName, user, pass, table, detectSslMode(kv, opts));
        }
        Path dbFile = findSqliteFile(dir, "nlogin.db", "database/accounts.db", "accounts.db", "database.db", "ai_accounts.db");
        return dbFile != null ? DetectedSource.sqlite(SourceType.NLOGIN, dbFile, table) : null;
    }

    private static @Nullable DetectedSource detectOpenLogin(Path dir, ScanOptions opts) {
        Path dbFile = findSqliteFile(dir, "accounts.db", "database/accounts.db", "openlogin.db", "database.db");
        return dbFile != null ? DetectedSource.sqlite(SourceType.OPENLOGIN, dbFile, "openlogin") : null;
    }

    private static @Nullable DetectedSource detectLimboAuth(Path dir, ScanOptions opts) {
        Map<String, String> kv = parseConfigKeys(dir.resolve("config.yml"));
        String storageType = firstValue(kv, "database.storage-type", "database.storage_type", "storage-type", "storage_type", "database.type");
        String table = sanitizeTable(firstValue(kv, "database.table", "table"), "AUTH");
        if (isMysqlBackend(storageType)) {
            HostPort hp = HostPort.parse(
                    firstValue(kv, "database.hostname", "database.host", "hostname", "host"),
                    firstValue(kv, "database.port", "port"),
                    3306);
            String dbName = defaultIfBlank(firstValue(kv, "database.database", "database"), "limboauth");
            String user = defaultIfBlank(firstValue(kv, "database.user", "database.username", "user", "username"), "root");
            String pass = defaultIfNull(firstValue(kv, "database.password", "password"), "");
            return DetectedSource.mysql(SourceType.LIMBOAUTH, hp.host(), hp.port(), dbName, user, pass, table, detectSslMode(kv, opts));
        }
        Path dbFile = findSqliteFile(dir, "limboauth.db", "database.db");
        return dbFile != null ? DetectedSource.sqlite(SourceType.LIMBOAUTH, dbFile, table) : null;
    }

    private static @Nullable DetectedSource detectAuthy(Path dir, ScanOptions opts) {
        Map<String, String> kv = parseConfigKeys(dir.resolve("config.yml"));
        String type = firstValue(kv, "database.type", "type");
        String table = sanitizeTable(firstValue(kv, "database.table", "table"), "players");
        if (isMysqlBackend(type)) {
            HostPort hp = HostPort.parse(
                    firstValue(kv, "database.credentials.host", "credentials.host", "host"),
                    firstValue(kv, "database.credentials.port", "credentials.port", "port"),
                    3306);
            String dbName = defaultIfBlank(firstValue(kv, "database.credentials.database", "credentials.database", "database"), "authy");
            String user = defaultIfBlank(firstValue(kv, "database.credentials.user", "credentials.user", "user"), "root");
            String pass = defaultIfNull(firstValue(kv, "database.credentials.password", "credentials.password", "password"), "");
            return DetectedSource.mysql(SourceType.AUTHY, hp.host(), hp.port(), dbName, user, pass, table, detectSslMode(kv, opts));
        }
        Path dbFile = findSqliteFile(dir, "data.db", "authy.db", "playerdata.db");
        return dbFile != null ? DetectedSource.sqlite(SourceType.AUTHY, dbFile, table) : null;
    }

    private record HostPort(String host, int port) {
        static HostPort parse(@Nullable String rawHost, @Nullable String rawPort, int defaultPort) {
            int port = parsePort(rawPort, defaultPort);
            if (rawHost == null || rawHost.isBlank()) {
                return new HostPort("127.0.0.1", port);
            }
            String h = rawHost.strip();
            int colon = h.lastIndexOf(':');
            if (colon > 0 && colon < h.length() - 1 && h.indexOf(':') == colon) {
                String hostPart = h.substring(0, colon).strip();
                int parsedPort = parsePort(h.substring(colon + 1), port);
                return new HostPort(hostPart.isEmpty() ? "127.0.0.1" : hostPart, parsedPort);
            }
            return new HostPort(h, port);
        }
    }

    private static @Nullable Path findSubdir(Path parent, String expectedName) {
        Path direct = parent.resolve(expectedName);
        if (Files.isDirectory(direct)) {
            return direct;
        }
        try (Stream<Path> children = Files.list(parent)) {
            return children
                    .filter(Files::isDirectory)
                    .filter(p -> p.getFileName().toString().equalsIgnoreCase(expectedName))
                    .findFirst()
                    .orElse(null);
        } catch (IOException e) {
            return null;
        }
    }

    private static @Nullable Path findSqliteFile(Path dir, String... candidates) {
        for (String name : candidates) {
            if (name == null || name.isBlank()) continue;
            String cleaned = name.replace("{pluginDir}/", "").replace("{pluginDir}\\", "").strip();
            Path candidate = dir.resolve(cleaned);
            if (Files.isRegularFile(candidate)) {
                return candidate;
            }
        }
        try (Stream<Path> children = Files.list(dir)) {
            List<Path> files = children.filter(Files::isRegularFile).toList();
            for (String name : candidates) {
                if (name == null || name.isBlank()) continue;
                for (Path p : files) {
                    if (p.getFileName().toString().equalsIgnoreCase(name)) {
                        return p;
                    }
                }
            }
        } catch (IOException ignored) {
            // ignore
        }
        return null;
    }

    /**
     * Lightweight pure-Java parser for simple YAML and HOCON config files.
     * Populates both flat lowercase keys and dot-separated section paths.
     */
    static Map<String, String> parseConfigKeys(Path configFile) {
        Map<String, String> out = new LinkedHashMap<>();
        if (configFile == null || !Files.isRegularFile(configFile)) {
            return out;
        }
        List<String> lines;
        try {
            lines = Files.readAllLines(configFile, StandardCharsets.UTF_8);
        } catch (IOException e) {
            return out;
        }

        List<SectionIndent> stack = new ArrayList<>();
        for (String rawLine : lines) {
            String strippedComment = stripComment(rawLine);
            String trimmed = strippedComment.strip();
            if (trimmed.isEmpty() || trimmed.equals("{") || trimmed.equals("}")) {
                if (trimmed.equals("}") && !stack.isEmpty()) {
                    stack.removeLast();
                }
                continue;
            }
            int indent = countLeadingSpaces(strippedComment);
            while (!stack.isEmpty() && !stack.getLast().braceScoped && indent <= stack.getLast().indent) {
                stack.removeLast();
            }

            if (trimmed.endsWith("{")) {
                String secName = trimmed.substring(0, trimmed.length() - 1).strip();
                if (secName.endsWith(":") || secName.endsWith("=")) {
                    secName = secName.substring(0, secName.length() - 1).strip();
                }
                secName = unquote(secName).toLowerCase(Locale.ROOT);
                if (!secName.isEmpty()) {
                    stack.add(new SectionIndent(secName, indent, true));
                }
                continue;
            }

            int sepIdx = findSeparator(trimmed);
            if (sepIdx <= 0) {
                continue;
            }
            String key = unquote(trimmed.substring(0, sepIdx).strip()).toLowerCase(Locale.ROOT);
            String valPart = trimmed.substring(sepIdx + 1).strip();
            if (valPart.isEmpty() || valPart.equals("{")) {
                stack.add(new SectionIndent(key, indent, valPart.equals("{")));
                continue;
            }
            String value = unquote(valPart);
            out.putIfAbsent(key, value);
            if (!stack.isEmpty()) {
                StringBuilder path = new StringBuilder();
                for (SectionIndent s : stack) {
                    path.append(s.name).append('.');
                }
                path.append(key);
                out.put(path.toString(), value);
                out.put(stack.getLast().name + "." + key, value);
            }
        }
        return out;
    }

    private record SectionIndent(String name, int indent, boolean braceScoped) {
    }

    private static int findSeparator(String s) {
        int colon = s.indexOf(':');
        int eq = s.indexOf('=');
        if (colon > 0 && eq > 0) return Math.min(colon, eq);
        return colon > 0 ? colon : eq;
    }

    private static int countLeadingSpaces(String s) {
        int count = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == ' ') count++;
            else if (c == '\t') count += 2;
            else break;
        }
        return count;
    }

    private static String stripComment(String line) {
        boolean inSingle = false;
        boolean inDouble = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '\'' && !inDouble) {
                inSingle = !inSingle;
            } else if (c == '"' && !inSingle) {
                inDouble = !inDouble;
            } else if (!inSingle && !inDouble) {
                if (c == '#') {
                    return line.substring(0, i);
                }
                if (c == '/' && i + 1 < line.length() && line.charAt(i + 1) == '/') {
                    return line.substring(0, i);
                }
            }
        }
        return line;
    }

    private static String unquote(String s) {
        String t = s.strip();
        if (t.length() >= 2) {
            if ((t.startsWith("'") && t.endsWith("'")) || (t.startsWith("\"") && t.endsWith("\""))) {
                return t.substring(1, t.length() - 1);
            }
        }
        return t;
    }

    private static @Nullable String firstValue(Map<String, String> kv, String... keys) {
        for (String k : keys) {
            String v = kv.get(k.toLowerCase(Locale.ROOT));
            if (v != null) return v;
        }
        return null;
    }

    private static boolean isMysqlBackend(@Nullable String raw) {
        if (raw == null || raw.isBlank()) return false;
        String lower = raw.toLowerCase(Locale.ROOT);
        return lower.contains("mysql") || lower.contains("mariadb");
    }

    private static String sanitizeTable(@Nullable String raw, String fallback) {
        if (raw == null || raw.isBlank()) return fallback;
        String trimmed = raw.strip();
        return trimmed.matches("^[a-zA-Z0-9_]{1,64}$") ? trimmed : fallback;
    }

    private static String defaultIfBlank(@Nullable String val, String fallback) {
        return (val == null || val.isBlank()) ? fallback : val.strip();
    }

    private static String defaultIfNull(@Nullable String val, String fallback) {
        return val == null ? fallback : val;
    }

    private static int parsePort(@Nullable String raw, int fallback) {
        if (raw == null || raw.isBlank()) return fallback;
        try {
            int p = Integer.parseInt(raw.strip());
            return (p >= 1 && p <= 65535) ? p : fallback;
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
