# AGENTS.md — JustLogin

Guidance for AI agents and contributors working in this repository (`justlogin.net`, shared conventions with `justPolls` and `justAuction`).

## What this repo is

**JustLogin** is a multi-module cracked + premium Minecraft authentication suite (`me.skerik.justlogin`) across:
- `core/` — storage (`Database`, append-only `Migrations`, DAOs), crypto (`ServerSecrets`, `ProxyTokenSigner`, `TotpService`, Argon2id + legacy hashers), `AuthService`, importers (`AuthMeImporter`, `FastLoginImporter`), and pure unit/security tests. Zero Bukkit/Paper/Velocity/Bungee dependencies.
- `editor/` — self-contained AES-256-GCM encrypted Web Editor snapshot/diff engine & Bytebin client.
- `paper/` — Paper `1.21.7–26.x` / Folia plugin (`JustLogin`), Paper Configuration-phase Dialog UI, Brigadier `/register`/`/login`/`/2fa`/`/justlogin` commands, Log4j2 password redaction filter, `ConfigUpdater`, `Messages`, `Banner`, `Stats`, `UpdateChecker`.
- `velocity/` — Velocity `3.x` proxy companion enforcing `game_uuid` immutability, Mojang online/offline negotiation, and HMAC-signed `justlogin:auth` forwarding.
- `bungee/` — BungeeCord / Waterfall proxy companion matching Velocity's protocol and fail-closed validation.

## Commands

```bash
./gradlew build                  # compile all 5 modules (-Xlint:all -Werror) and run all unit tests
./gradlew :paper:shadowJar       # build shaded Paper JAR
./gradlew :velocity:shadowJar    # build shaded Velocity JAR
./gradlew :bungee:shadowJar      # build shaded BungeeCord JAR
./scripts/smoke-test.sh          # clean Paper boot via run-paper, check banner + schema + logs
./scripts/render-assets.sh       # export docs/assets/*.png and docs/gallery/*.png
```

Never initialize `.git` or push/tag unless explicitly instructed by the user. Do not commit secrets (`secrets.key`, `*.db`, real DB passwords).

## Conventions (`justlogin.net` / `Just*` suite)

- **Java & Compilation**: Toolchains can be JDK 21+, always compile `--release 21` with `-Xlint:all -Werror` (`-Xlint:-classfile` only on modules pulling Log4j2/Velocity compileOnly jars).
- **Folia / Threading**: Never use `Bukkit.getScheduler()`. Always use `Scheduler` (`GlobalRegionScheduler`, entity schedulers, async scheduler). Keep all DB/hashing/HTTP I/O async; `onEnable()` initializes listeners, commands, and plugin channels, then opens `secrets.key` + `Database` async before calling `finishStartup()`.
- **Banner, Stats, Updates**: Match the shared `justlogin.net` / `Just*` coloured `ComponentLogger` + `MiniMessage` box banner (`┌─ JustLogin ... └─ Ready in X ms · https://github.com/filasik/justLogin`), `metrics: true` bStats toggle (`bstats-id=${bstatsId}` in `build.properties`, `bstatsId=0` in repo), and GitHub Releases `UpdateChecker` (initial + 12h timer, notifying `justlogin.admin` on auth completion).
- **Configuration & Localization**: Config keys follow `locale`, `update-check`, `metrics`, `storage` (with `RENAMES` + fallbacks in `Settings`, `VelocityConfig`, `BungeeConfig`). When adding options to `config.yml`, increment `config-version`, document them inline, add entries to `ConfigUpdater.RENAMES` if renamed, and extend `ConfigUpdaterTest` + `SettingsTest`. Player messages live in `messages_en.yml`, `messages_cs.yml`, and `messages_sk.yml` (`MessagesFilesTest` enforces key parity).
- **Database Schema**: `Migrations.VERSIONS` is strictly **append-only**. Never modify existing SQL blocks; add a new entry for any schema change and test upgrade compatibility.
- **Visual Assets**: Keep `docs/assets/` (`icon.svg`/`png` 512×512, `banner.svg`/`png` 1200×300) and `docs/gallery/` (`*.html`/`*.png` 1280×720) in sync via `scripts/render-assets.sh`. Every gallery HTML/PNG must carry an explicit `"Illustration (mockup ...), not a screenshot"` label.

## Security invariants (never regress)

1. `sessions.enabled: false` and `premium.auto-detect-mojang: false` (`proxy.auto-detect-mojang: false` on proxy) by default.
2. Fail closed on pre-ready connections (`context == null` -> `error.not-ready`), proxy misconfiguration (`ProxyStartupCheck`), missing/placeholder proxy `shared-secret`, and pre-auth Paper lockdown (`PreAuthProtectionListener`).
3. Constant-time comparisons (`MessageDigest.isEqual`), nonce + timestamp checks on `justlogin:auth`, zero passwords in logs (`LogPasswordFilter`), and immutable `game_uuid` across `/premium`/`/cracked`/Mojang renames.
4. Keep unit/security tests in `core`, `editor`, `paper`, `velocity`, `bungee` passing without mocks hiding real security logic.

## Before releasing (`git tag vX.Y.Z`)

Check every item in [`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md) (`CHANGELOG.md`, `docs/modrinth.md`, `docs/spigot.bbcode.txt`, `README.md`, `./gradlew build`, `./scripts/smoke-test.sh`, `./scripts/render-assets.sh`).
