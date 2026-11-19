# Installation (single Paper server)

This page covers a **standalone** Paper (or Folia) server without a proxy. For Velocity or BungeeCord see [Proxy Setup](Proxy-Setup).

## Requirements

| Requirement | Details |
| :--- | :--- |
| Server | Paper `1.21.7` – `26.x` (Folia supported) |
| Java | 21 or newer |
| Database | SQLite (bundled, default) or MariaDB |
| Optional | ViaVersion (older clients), Floodgate / Geyser (Bedrock) |

> The plugin downloads its database drivers and libraries on first start (`libraries.txt`), so the server needs outbound internet access once.

## Steps

1. Download `JustLogin-<version>.jar` from the [Releases page](https://github.com/filasik/justLogin/releases) (or Modrinth).
2. Put it into the server's `plugins/` folder.
3. Start the server.

On the first start JustLogin creates:

| Path | Purpose |
| :--- | :--- |
| `plugins/JustLogin/config.yml` | Main configuration, fully commented |
| `plugins/JustLogin/messages_en.yml`, `messages_cs.yml`, `messages_sk.yml` | Player-facing text (see [Messages and Localization](Messages-and-Localization)) |
| `plugins/JustLogin/secrets.key` | Server secrets (HMAC key, TOTP encryption key, proxy secret). **Back it up, never share it.** |
| `plugins/JustLogin/data/justlogin.db` | SQLite account database |

You should see the JustLogin banner in the console once startup finishes (`Ready in X ms`). If startup fails, JustLogin prints one clear error line and disables itself rather than running half-configured.

## First checks

1. Join the server with a Java `1.21.7+` client – you should get a **Register** dialog before the world loads.
2. Register, disconnect, reconnect – you should get a **Login** dialog.
3. Run `/jl status <yourname>` as an operator to inspect the account.
4. Run `/jl help` to see the in-game help.

## Standalone `/premium`

Standalone Mojang login (`premium.standalone-enabled: true`, the default) needs no extra plugins. JustLogin performs the Mojang encryption handshake on Paper's Netty pipeline itself. It stays idle when `server.properties` has `online-mode=true` or when `proxy.enabled=true`, because in those setups the server / proxy already verifies Mojang accounts. Details: [Premium Login](Premium-Login).

## Updating

1. Stop the server, replace the jar, start the server.
2. `ConfigUpdater` adds new options (with comments) to your `config.yml`, saves a backup as `config.yml.bak-v<n>` and **never changes values you set**.
3. Database changes run as append-only migrations automatically.

Read the [changelog](https://github.com/filasik/justLogin/blob/main/CHANGELOG.md) before major updates. Only the latest release receives security fixes.

## Uninstalling

Remove the jar. Account data stays in `plugins/JustLogin/data/` (or your MariaDB database) until you delete it. Passwords are hashed, so they cannot be moved to a plugin that expects a different format without the importer of that plugin.

## Folia

JustLogin never uses the Bukkit scheduler; it uses region, entity, global and async schedulers, so it runs on Folia. Nothing extra to configure.
