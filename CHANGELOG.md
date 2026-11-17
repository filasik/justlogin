# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.5] - 2026-11-17

### Added
- `/2fa setup` can show a locally generated authenticator QR code on a client-only map in the player's held slot (`totp.qr-map-enabled: true`, config version 8). The real inventory and world map storage are never modified; no external QR service is used.
- QR display is cleared on confirmation, cancellation, replacement, logout/disconnect, death, teleport, inventory interactions, slot changes, item drops/swaps/use, and after at most 120 seconds. The original slot is restored from the current server inventory; map pixels are overwritten with a blank image. Shutdown also blanks active maps and restores their captured slot display without accessing another Folia region's inventory.
- `/2fa cancel` discards pending setup. Manual secret/URI provisioning remains available when QR display is disabled or unavailable. A new setup or disconnect invalidates stale asynchronous setup callbacks.

### Security
- Pending TOTP secrets are consumed atomically; setup/cancellation cannot replace an in-flight confirmation. Diagnostic string representations redact the pending secret.
- A QR code contains the TOTP secret: screenshots and modified clients can retain it despite display cleanup. Setup still requires authentication and a valid first TOTP code before 2FA is enabled; pending setup expires after five minutes.

## [1.0.4] - 2026-11-17

### Changed
- `/jl editor [page]` now exports accounts ordered by most recent login first rather than registration order. Accounts with no recorded login sort last; equal login timestamps are ordered by descending account ID for deterministic pagination.

## [1.0.3] - 2026-11-17

### Fixed
- Editor links now include the configured relay URL, so the browser reads and writes against the same relay as the plugin instead of failing with HTTP 404 when its default differs. Encryption keys remain in the URL fragment.
- Web Editor uploads now use the JustLogin-hosted relay at `https://bytebin.justlogin.net` instead of `bytebin.lucko.me`, which rejected uploads with HTTP 403. Updated both the plugin and hosted/bundled editor defaults.
- Existing configs using the previous default relay (with or without a trailing slash) migrate automatically to the new address (`config-version: 7`). Custom relay URLs are preserved.

## [1.0.2] - 2026-11-17

### Fixed
- **Migration: MariaDB/MySQL TLS (`sslMode`)** — `/jl import` and the auto-scanner built a bare `jdbc:mariadb://host:port/db` URL, which failed on servers with self-signed certificates (`Self signed certificates. Either set sslMode=trust...`). The scanner now reads `sslMode` / `useSSL` from the legacy plugin config (`useSSL: false` -> `disable`, `true`/`REQUIRED` -> `trust`), falls back to JustLogin's `storage.mariadb.ssl-mode`, and manual `/jl import <source> mysql ... --ssl-mode=<trust|disable|verify-ca|verify-full>` can override it.
- **Migration: FastLogin `premiumUuid`** — the FastLogin import always rewrote `game_uuid` of premium accounts from the offline UUID to the Mojang UUID, which breaks OP, whitelist, `world/playerdata/` and permissions on servers that ran FastLogin with `premiumUuid: false`. The scanner now reads `premiumUuid` from `plugins/FastLogin/config.yml` (missing key = `true`, FastLogin's own default = rewrite). With `premiumUuid: false` only `premium = 1` and `premium_uuid` are set and `game_uuid` stays untouched; new FastLogin-only accounts get the offline UUID.

### Added
- `--keep-offline-uuid` (alias `--preserve-game-uuid`) and `--rewrite-uuid` flags for `/jl import fastlogin` to override the config detection.
- `--dry-run`, the start message, the final summary and the import report now state clearly whether FastLogin keeps the offline `game_uuid` or rewrites it to the Mojang UUID.
- New message keys `admin.import-bad-flag`, `admin.import-fastlogin-uuid-kept`, `admin.import-fastlogin-uuid-rewritten` (`en`, `cs`, `sk`).

## [1.0.1] - 2026-11-15

### Changed
- Polished wording of in-game messages, help pages and documentation across `en`, `cs` and `sk`.
- Minor Web Editor label tweaks.
- Config: one `skins:` option was renamed; existing configs are migrated automatically (`config-version: 6`).
- Internal cleanups and small stability improvements.

## [1.0.0] - 2026-11-13

### Added
- **Schema v2 & SMTP Email Recovery**: automatic SQLite/MariaDB migration `v1 -> v2` (`email`, `recovery_code_hash`, `recovery_expires_at`, indexed `email`), zero-dependency virtual-thread `SmtpMailer` (`STARTTLS`/`SSL`/`NONE`), and `/email <set|clear|recover>` commands with masked audit trails and anti-enumeration responses.
- **Admin Rename, Merge, GUI & Granular Permissions**: `/jl rename <old> <new>`, `/jl merge <source> <target>` (transactional merge preserving surviving `game_uuid`), `/jl gui [page]` chest browser enforcing strict Rule 8 click/drag cancellation, `justlogin.email`, and child permissions `justlogin.admin.<reload|status|audit|unregister|changepass|reset2fa|setpremium|forcepw|rename|merge|gui|import>`.
- **Captcha Challenge**: `/captcha <code>` anti-bot challenge (`captcha.enabled`, `captcha.require-on-register`, `captcha.trigger-after-failures`, `captcha.length`, `captcha.expire-seconds`).
- **Proxy Auth-Server Lockdown & Routing**: `proxy.auth-servers` lockdown on Velocity (`ServerPreConnectEvent`) and BungeeCord (`ServerConnectEvent`), driven by HMAC-signed `BACKEND_AUTH_OK` and `LOGOUT` plugin messages.
- **Single-Password Configuration Dialog & Config v3**: `login.dialog-single-password: true` default in `PaperDialogUi`, plus automatic `ConfigUpdater` `v2 -> v3` migration.
- **Floodgate Bedrock Cumulus Forms**: pure-reflection `BedrockFormUi` (`bedrock.cumulus-forms: true`) offering native Bedrock forms when Cumulus/Floodgate are installed, with command fallback otherwise.
- **Slovak Localization**: bundled `messages_sk.yml` (`locale: sk`) verified for key parity alongside `en` and `cs`.
- **Developer API**: `JustLoginAPI` registered in Bukkit `ServicesManager`, secret-free `AccountSnapshot`, and Bukkit events (`PlayerAuthenticatedEvent`, `PlayerRegisteredEvent`, `PlayerLoggedOutEvent`, `PlayerPremiumVerifiedEvent`).
- **Optional Local Loopback HTTP Editor**: `editor.local-http.enabled` starts a `127.0.0.1`-only embedded `HttpServer` serving the static Web Editor UI and `/post` relay with CSP headers as a self-contained alternative to external Bytebin instances.

- **Built-in Skin Management & Schema v3 (`Migrations` v3, Config v5)**:
  - `MojangSkinClient` fetches signed Mojang skin textures (`value` + `signature` via `sessionserver.mojang.com/...?unsigned=false`) with bounded TTL caching and fail-open timeouts so Mojang outages never block logins.
  - Persistent custom skin columns on `justlogin_accounts` (`skin_owner`, `skin_value`, `skin_signature`, `skin_updated_at`) preserved across `/jl merge` and `/jl rename`.
  - Configurable `skins:` section (`enabled`, `command-enabled`, `cooldown-seconds`, `cache-seconds`, plus a restore-by-username toggle) automatically restores matching Mojang skins by username for password-authenticated joins (strictly cosmetic; never grants `/premium`) across standalone Paper, Velocity (`GameProfileRequestEvent`), and Paper backends.
  - In-game `/skin <player|reset>` (alias `/skins`, `justlogin.skin`, cooldown bypass `justlogin.skin.bypasscooldown`) and admin `/jl skin <player> <target|reset>` (`justlogin.admin.skin`) updating live `PlayerProfile` on Paper/Folia entity threads with DB persistence and `CommandDoc`/`HelpRenderer` documentation in `en`, `cs`, and `sk`.
- **1-Click Legacy Auto-Migration Hardening**: expanded `MigrationScanner` + importers for AuthMe, FastLogin, LibreLogin (`librepremium_data`, split `BCrypt-2A`/`Argon-2ID`), LoginSecurity (`ls_players`), nLogin (`$SHA512$` reversed format + `mojang_id`), OpeNLogin (`openlogin`), LimboAuth (`AUTH`), and Authy (`players`), with `--dry-run` preview and audit reports.
- **Interactive `/jl help`**: paginated help and detailed command cards (`CommandDoc`, `HelpRenderer`, `HelpCommandCompletenessTest`) filtering by permission and active server features across `en`/`cs`/`sk`.
- **Landing page** (`docs/index.html`, served at `justlogin.net/`; the web editor lives at `justlogin.net/editor/`). Links to Modrinth, Hangar and GitHub, lists the private security contact `security@justlogin.net`, and forwards legacy `/?code=…#key` editor links to `/editor/`.

### Changed
- **Web Editor redesign** (`docs/editor/index.html`, mirrored in `editor/src/main/resources/web-editor/`): calmer light/dark theme, segmented login-mode control, switches, summary figures, pending-changes bar with Discard, copyable apply command, collapsible relay setting and responsive layout. Same encryption flow and strict CSP; adds a `?demo` preview with made-up data.

### Security
- Threat model regression suite (`ThreatModelMatrixTest`) covering bounded hashing DoS (`HASHING_BUSY`), TOTP step anti-replay & single-use backup codes, HMAC `BACKEND_AUTH_OK` replay rejection, pending `/premium` rollback, and SQLite v1->v2 migration integrity.
- Explicit documentation of vanilla Dialog plaintext password rendering (streamer warning), `secrets.key` host-compromise boundary, and Web Editor encrypted PII handling.

## [0.1.0] - 2026-11-13

### Added
- Multi-module architecture (`core`, `editor`, `paper`, `velocity`, `bungee`) targeting Java 21 bytecode (`--release 21`) with `-Xlint:all -Werror`.
- **Unified suite conventions (`justlogin.net`)**:
  - Async two-phase Paper startup (async secrets & storage migration -> first-tick `finishStartup`) with `ComponentLogger` MiniMessage box banner on Paper, Velocity, and BungeeCord.
  - Standardized config keys (`locale`, `update-check`, `metrics`, `storage`) with `ConfigUpdater` backup/migration/merge and backward-compatible fallbacks.
  - Stateful GitHub Releases `UpdateChecker` (12-hour interval) notifying `justlogin.admin` upon authentication.
  - bStats support (`metrics: true` toggle + `SimplePie` charts across Paper, Velocity, and BungeeCord).
  - Full `docs/assets/`, `docs/gallery/`, `.github/` workflows, and Modrinth/Spigot store copy.
- **Authentication & UI**:
  - Standalone Paper Mojang premium auto-login (`/premium` and its counterpart directly on standalone Paper servers without BungeeCord, Velocity, ProtocolLib, or PacketEvents) via Paper `ChannelInitializeListenerHolder` + RSA/AES challenge + Mojang `hasJoined` verification + signed `textures` skin restoration.
  - Native Paper 1.21.7+ Configuration-phase `Dialog` authentication (`AsyncPlayerConnectionConfigureEvent`) with `command` UI fallback for Bedrock (Floodgate) and `< 1.21.7` clients.
  - Argon2id password hashing (`password4j` 1.8.4) on bounded hashing workers, plus automatic transparent rehash for AuthMe SHA-256 / SHA-512, BCrypt, and PBKDF2 hashes.
  - RFC 6238 TOTP 2FA (`/2fa setup`, `/2fa confirm`, `/2fa disable`, `/2fa verify`) and 8 single-use hashed backup codes.
  - Self-contained AES-256-GCM Web Editor (`editor` module + Bytebin relay) via `/jl editor` and `/jl applyedits`.
  - AuthMe Reloaded & FastLogin SQLite/MariaDB importers and SQLite/MariaDB dual-dialect `Migrations` + DAOs.
  - English (`messages_en.yml`) and Czech (`messages_cs.yml`) MiniMessage localization bundles.

### Security
- `sessions.enabled: false` and `premium.auto-detect-mojang: false` safe defaults (with automatic `config-version` 1 -> 2 migration of `proxy.auto-detect-mojang` / `proxy.mojang-cache-seconds`).
- Fail-closed `ProxyStartupCheck` verifying Paper forwarding configuration (`velocity` / `bungee`) and non-placeholder `shared-secret` on startup.
- Log4j2 root filter redacting plaintext passwords from player auth commands across console and logs.
- HMAC-SHA256 + timestamp + replay-nonce verification on `justlogin:auth` plugin messaging channel.
- Immutable `game_uuid` assigned once on account creation and preserved on standalone Paper, Velocity, and BungeeCord across `/premium` toggles and Mojang renames.
- Per-(account, IP) and per-IP rate limiting + exponential backoff, duplicate-login pre-auth protection, and fail-closed pre-auth lockdown.
