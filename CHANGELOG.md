# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Built-in Skin Management & Schema v3 (`Migrations` v3, Config v5)**:
  - `MojangSkinClient` fetches signed Mojang skin textures (`value` + `signature` via `sessionserver.mojang.com/...?unsigned=false`) with bounded TTL caching and fail-open timeouts so Mojang outages never block logins.
  - Persistent custom skin columns on `justlogin_accounts` (`skin_owner`, `skin_value`, `skin_signature`, `skin_updated_at`) preserved across `/jl merge` and `/jl rename`.
  - Configurable `skins:` section (`enabled`, `restore-cracked-by-name`, `command-enabled`, `cooldown-seconds`, `cache-seconds`) automatically restores matching Mojang skins by username for offline/cracked joins (strictly cosmetic; never grants `/premium`) across standalone Paper, Velocity (`GameProfileRequestEvent`), and Paper backends.
  - In-game `/skin <player|reset>` (alias `/skins`, `justlogin.skin`, cooldown bypass `justlogin.skin.bypasscooldown`) and admin `/jl skin <player> <target|reset>` (`justlogin.admin.skin`) updating live `PlayerProfile` on Paper/Folia entity threads with DB persistence and `CommandDoc`/`HelpRenderer` documentation in `en`, `cs`, and `sk`.
- **1-Click Legacy Auto-Migration Hardening**: expanded `MigrationScanner` + importers for AuthMe, FastLogin, LibreLogin (`librepremium_data`, split `BCrypt-2A`/`Argon-2ID`), LoginSecurity (`ls_players`), nLogin (`$SHA512$` reversed format + `mojang_id`), OpeNLogin (`openlogin`), LimboAuth (`AUTH`), and Authy (`players`), with `--dry-run` preview and audit reports.
- **Interactive `/jl help`**: paginated help and detailed command cards (`CommandDoc`, `HelpRenderer`, `HelpCommandCompletenessTest`) filtering by permission and active server features across `en`/`cs`/`sk`.
- **Landing page** (`docs/index.html`, served at `justlogin.net/`; the web editor lives at `justlogin.net/editor/`). Links to Modrinth, Hangar and GitHub, lists the private security contact `security@justlogin.net`, and forwards legacy `/?code=…#key` editor links to `/editor/`.

### Changed
- **Web Editor redesign** (`docs/editor/index.html`, mirrored in `editor/src/main/resources/web-editor/`): calmer light/dark theme, segmented login-mode control, switches, summary figures, pending-changes bar with Discard, copyable apply command, collapsible relay setting and responsive layout. Same encryption flow and strict CSP; adds a `?demo` preview with made-up data.

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
  - Standalone Paper Mojang premium auto-login (`/premium` and `/cracked` directly on `online-mode=false` Paper servers without BungeeCord, Velocity, ProtocolLib, or PacketEvents) via Paper `ChannelInitializeListenerHolder` + RSA/AES challenge + Mojang `hasJoined` verification + signed `textures` skin restoration.
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
- Immutable `game_uuid` assigned once on account creation and preserved on standalone Paper, Velocity, and BungeeCord across `/premium`, `/cracked`, and Mojang renames.
- Per-(account, IP) and per-IP rate limiting + exponential backoff, duplicate-login pre-auth protection, and fail-closed pre-auth lockdown.
