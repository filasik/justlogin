<div align="center">

<img src="https://raw.githubusercontent.com/filasik/justLogin/main/docs/assets/banner.png" alt="JustLogin" width="720">

# JustLogin Wiki

**Modern account authentication for Paper, Folia, Velocity and BungeeCord.**

</div>

JustLogin lets players register and log in through a native Minecraft **dialog shown before the world loads**, protects accounts with **Argon2id** hashing and optional **2FA**, supports **Mojang `/premium` auto-login** without changing a player's server UUID, and ships importers for the most common older authentication plugins.

| | |
| :--- | :--- |
| **Platforms** | Paper `1.21.7 – 26.x`, Folia, Velocity `3.x`, BungeeCord / Waterfall |
| **Java** | 21 or newer |
| **License** | MIT |
| **Website** | [justlogin.net](https://justlogin.net) |
| **Source / issues** | [github.com/filasik/justLogin](https://github.com/filasik/justLogin) |
| **Security reports** | [security@justlogin.net](mailto:security@justlogin.net) – see [Security Policy](Security-Model#reporting-a-vulnerability) |

## Where to start

| I want to... | Read |
| :--- | :--- |
| Install JustLogin on a single Paper server | [Installation](Installation) |
| Run it on a Velocity / BungeeCord network | [Proxy Setup](Proxy-Setup) |
| Understand what every option does | [Configuration](Configuration) |
| See every command and permission | [Commands and Permissions](Commands-and-Permissions) |
| Tell my players how to use it | [Player Guide](Player-Guide) |
| Let players keep their UUID with Mojang login | [Premium Login](Premium-Login) |
| Set up 2FA | [Two-Factor Authentication](Two-Factor-Authentication) |
| Move from AuthMe, LibreLogin, nLogin, ... | [Migration](Migration) |
| Manage accounts day to day | [Admin Guide](Admin-Guide) and [Web Editor](Web-Editor) |
| Understand the security design | [Security Model](Security-Model) |
| Use a MariaDB database | [Storage and Database](Storage-and-Database) |
| Translate or restyle messages | [Messages and Localization](Messages-and-Localization) |
| Integrate with my own plugin | [Developer API](Developer-API) |
| Fix a problem | [Troubleshooting](Troubleshooting) and [FAQ](FAQ) |
| Build the plugin or contribute | [Building and Contributing](Building-and-Contributing) |

## Feature overview

- **Authenticate before the world loads** – Java `1.21.7+` clients get a native Configuration-phase dialog. Older clients, Bedrock players and `login.ui: command` use a locked-down command flow.
- **Immutable `game_uuid`** – every account keeps one permanent server UUID, even when it is switched between password and Mojang login or when the Mojang name changes. Inventories, permissions, economy and claims stay attached.
- **Argon2id with legacy upgrade** – imported AuthMe / BCrypt / PBKDF2 hashes are re-hashed to Argon2id on the player's next successful login.
- **2FA, captcha, email recovery** – RFC 6238 TOTP with single-use backup codes, optional anti-bot captcha, optional SMTP password recovery.
- **Skins** – matching Mojang skin applied by username (cosmetic only) and `/skin` with cooldown and persistence.
- **Admin tooling** – paginated chest GUI, rename / merge, audit log, one-click importer, encrypted Web Editor.
- **Proxy-ready** – HMAC-signed `justlogin:auth` forwarding with timestamp and single-use nonce, fail-closed startup checks.
- **Safe defaults** – sessions and Mojang username auto-detect are **off** until you turn them on.

## Quick links

- [Releases / downloads](https://github.com/filasik/justLogin/releases)
- [Changelog](https://github.com/filasik/justLogin/blob/main/CHANGELOG.md)
- [Report a bug](https://github.com/filasik/justLogin/issues)
- [Support the project](https://www.paypal.com/donate/?hosted_button_id=94D2D46EHKU5S) (voluntary, never gives in-game perks)
