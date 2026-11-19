# Building and Contributing

## Repository layout

| Module | Purpose |
| :--- | :--- |
| `core/` | Storage (`Database`, append-only `Migrations`, DAOs), crypto (secrets, proxy token signer, TOTP, Argon2id + legacy hashers), `AuthService`, importers. No Bukkit / Paper / proxy dependencies |
| `editor/` | AES-256-GCM Web Editor snapshot / diff engine and relay client |
| `paper/` | Paper / Folia plugin: dialogs, Brigadier commands, listeners, config, messages |
| `velocity/` | Velocity companion plugin |
| `bungee/` | BungeeCord / Waterfall companion plugin |

## Build

Requires a JDK that can compile `--release 21`.

```bash
./gradlew build                 # compile all modules (-Xlint:all -Werror) and run all tests
./gradlew :paper:shadowJar      # shaded Paper jar
./gradlew :velocity:shadowJar   # shaded Velocity jar
./gradlew :bungee:shadowJar     # shaded BungeeCord jar
./scripts/smoke-test.sh         # clean Paper boot, checks banner, schema and logs
./scripts/render-assets.sh      # regenerate docs/assets and docs/gallery PNGs
```

Output jars: `paper/build/libs/JustLogin-<version>.jar`, `velocity/build/libs/JustLogin-Velocity-<version>.jar`, `bungee/build/libs/JustLogin-Bungee-<version>.jar`.

Run a dev server: `./gradlew :paper:runServer`.

## Conventions

- Java compiled with `-Xlint:all -Werror`.
- Never use `Bukkit.getScheduler()`; use the `Scheduler` abstraction. All database, hashing and HTTP I/O stays off the main thread.
- No hard-coded player text – add keys to `messages_en.yml`, `messages_cs.yml` and `messages_sk.yml` (a test enforces parity).
- New config options: bump `config-version`, comment them inline, add `ConfigUpdater.RENAMES` entries for renames, and extend `ConfigUpdaterTest` and `SettingsTest`.
- `Migrations.VERSIONS` is **append-only**; never edit an existing block, add a new one and test the upgrade.
- Keep the security defaults (sessions off, auto-detect off, fail-closed proxy checks, constant-time comparisons, no passwords in logs) and keep the security tests free of mocks that hide real logic.
- Don't commit secrets (`secrets.key`, `*.db`, real database passwords).

## Pull requests

1. Open an issue first for larger changes.
2. Keep PRs focused, update `CHANGELOG.md`, and make sure `./gradlew build` and `./scripts/smoke-test.sh` pass.
3. By contributing you agree your code is licensed under the project's MIT license.

## Releases

Maintainers tag `vX.Y.Z`; a GitHub Action builds, runs the smoke test, publishes a GitHub Release (the changelog is the release body) and publishes to Modrinth. Release checklist: `docs/RELEASE_CHECKLIST.md`.

## Links

[Source](https://github.com/filasik/justLogin) · [Issues](https://github.com/filasik/justLogin/issues) · [Security policy](Security-Model#reporting-a-vulnerability)
