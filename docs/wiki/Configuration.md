# Configuration

All options live in `plugins/JustLogin/config.yml` and are commented in the file itself. Run **`/jl reload`** to apply most changes without a restart (storage settings need a restart).

`config-version` is managed by the plugin. When you update JustLogin, new options are merged into your file with their comments, a backup `config.yml.bak-v<n>` is written first, and **your values are never overwritten**. Renamed options are migrated automatically.

| `config-version` | Introduced in | Change |
| :--- | :--- | :--- |
| `6` | 1.0.1 | One `skins:` option renamed (migrated automatically) |
| `7` | 1.0.3 | `editor.relay-url` moved from `https://bytebin.lucko.me` to `https://bytebin.justlogin.net`. Only the old default value is migrated; a custom relay URL is kept |
| `8` | 1.0.5 | Added `totp.qr-map-enabled` |

> Tip: you can also edit accounts, not settings, with the [Web Editor](Web-Editor).

## General

| Key | Default | Description |
| :--- | :--- | :--- |
| `locale` | `en` | Language of player messages: `en`, `cs`, `sk` |
| `update-check` | `true` | Check GitHub Releases at startup and every 12 hours; players with `justlogin.admin` are notified when they authenticate |
| `metrics` | `true` | Anonymous bStats statistics (plugin ID 35316). The global switch is `plugins/bStats/config.yml` |

## `login`

| Key | Default | Description |
| :--- | :--- | :--- |
| `ui` | `dialog` | `dialog` = native Configuration-phase dialog (`1.21.7+`); `command` = classic `/register` and `/login` |
| `timeout-seconds` | `60` | Time a player has to finish authentication before being kicked |
| `kick-duplicate-online` | `true` | Reject a new connection if the same name is already online and authenticated |
| `fallback-for-legacy-clients` | `true` | Use the command flow for Bedrock and pre-`1.21.7` clients |
| `title-reminder` | `true` | Show a title prompt while waiting for credentials in command mode |
| `dialog-single-password` | `true` | One password field on the register dialog; `false` adds a confirm field |

## `bedrock`

| Key | Default | Description |
| :--- | :--- | :--- |
| `cumulus-forms` | `true` | Use Floodgate Cumulus forms for Bedrock players when Floodgate is installed; otherwise the chat commands are used |

## `captcha`

| Key | Default | Description |
| :--- | :--- | :--- |
| `enabled` | `true` | Enable the anti-bot captcha |
| `require-on-register` | `false` | Always require `/captcha <code>` before registration |
| `trigger-after-failures` | `3` | Challenge after N failed attempts (`0` disables the failure trigger) |
| `length` | `5` | Captcha length |
| `expire-seconds` | `120` | Captcha lifetime |

## `username` and `password`

| Key | Default | Description |
| :--- | :--- | :--- |
| `username.regex` | `^[a-zA-Z0-9_]{3,16}$` | Allowed usernames, validated before any database lookup |
| `password.min-length` / `max-length` | `8` / `128` | Password length bounds |
| `password.reject-username-as-password` | `true` | Block a password equal to the username |
| `password.reject-common-passwords` | `true` | Block very common passwords |
| `password.argon2.memory-kib` | `19456` | Argon2id memory (19 MiB) |
| `password.argon2.iterations` | `2` | Argon2id iterations |
| `password.argon2.parallelism` | `1` | Argon2id lanes |
| `password.hashing.max-concurrent` | `4` | Hash jobs running at once |
| `password.hashing.max-queued` | `64` | Queue size; when full players see *"The authentication queue is busy"* instead of the server lagging |

Raising Argon2 memory / iterations makes brute-force harder but costs CPU and RAM per login; hashing always runs on a bounded worker pool, never on the main thread.

## `rate-limit`, `registration`, `audit`

| Key | Default | Description |
| :--- | :--- | :--- |
| `rate-limit.max-attempts-per-account-ip` | `5` | Failed attempts per account + IP before lockout |
| `rate-limit.max-attempts-per-ip` | `20` | Failed attempts per IP (separate counter, so a shared IP does not lock out innocent accounts quickly) |
| `rate-limit.base-backoff-millis` | `1000` | Base delay for exponential backoff |
| `rate-limit.lockout-seconds` | `300` | Lockout duration |
| `registration.max-accounts-per-ip` | `5` | Accounts allowed per IP (`0` = unlimited) |
| `audit.retention-days` | `90` | Prune audit entries older than N days (`0` keeps everything) |

## `sessions`

| Key | Default | Description |
| :--- | :--- | :--- |
| `enabled` | `false` | Opt-in IP-bound HMAC auto-relogin. **Off by default** because anyone sharing the IP could resume the session |
| `duration-seconds` | `3600` | How long a session may be resumed |

`/logout` and `/changepassword` invalidate sessions.

## `totp`

| Key | Default | Description |
| :--- | :--- | :--- |
| `qr-map-enabled` | `true` | During `/2fa setup`, show the authenticator QR code on a temporary **client-only** map in the held slot (max. 120 s). No real item or saved map is ever created; the manual key is always shown too |
| `issuer` | `JustLogin` | Label shown in authenticator apps – set it to your server name |
| `window-steps` | `1` | Allowed clock drift (± 30 s per step) |

## `premium`

| Key | Default | Description |
| :--- | :--- | :--- |
| `standalone-enabled` | `true` | Mojang login handshake directly on Paper (no proxy needed) |
| `auto-detect-mojang` | `false` | Check Mojang for unseen usernames on first join. **Off by default** so a password-registered account can't be claimed by name |
| `mojang-cache-seconds` | `300` | Lookup cache |
| `prevent-proxy-connections` | `false` | Include the player's IP in the `hasJoined` check (keep `false` behind NAT or tunnels) |
| `fallback-to-password` | `false` | Allow premium-confirmed accounts that have a password to use it if the standalone hook is inactive |

See [Premium Login](Premium-Login).

## `skins`

| Key | Default | Description |
| :--- | :--- | :--- |
| `enabled` | `true` | Built-in skin management |
| `restore-by-name` | `true` | Apply the Mojang skin matching the username for password logins (cosmetic only, never grants `/premium`). |
| `command-enabled` | `true` | Allow `/skin` |
| `cooldown-seconds` | `60` | `/skin` cooldown (`0` disables); bypass with `justlogin.skin.bypasscooldown` |
| `cache-seconds` | `600` | Texture cache lifetime |

See [Skins](Skins).

## `proxy`

See [Proxy Setup](Proxy-Setup).

| Key | Default | Description |
| :--- | :--- | :--- |
| `enabled` | `false` | `true` only behind Velocity / BungeeCord running JustLogin |
| `mode` | `standalone` | `standalone`, `velocity`, `bungee` |
| `shared-secret` | empty | ≥ 16 characters, identical on proxy and Paper |
| `require-forwarding-config` | `true` | Verify `paper-global.yml` / `spigot.yml` at startup |

## `storage`

See [Storage and Database](Storage-and-Database).

| Key | Default | Description |
| :--- | :--- | :--- |
| `type` | `sqlite` | `sqlite` or `mariadb` (restart required) |
| `sqlite.file` | `data/justlogin.db` | Database file, relative to the plugin folder |
| `sqlite.pool-size` | `4` | Connection pool |
| `mariadb.host` / `port` / `database` / `user` / `password` | `localhost` / `3306` / `justlogin` / `root` / empty | Connection |
| `mariadb.pool-size` | `10` | Connection pool |
| `mariadb.ssl-mode` | empty | Empty, or `trust` for a self-signed certificate |

## `editor`

See [Web Editor](Web-Editor).

| Key | Default | Description |
| :--- | :--- | :--- |
| `web-url` | `https://justlogin.net` | Hosted editor URL |
| `relay-url` | `https://bytebin.justlogin.net` | JustLogin-hosted, Bytebin-compatible relay that stores the **encrypted** snapshot. You can point it at your own Bytebin instance |
| `page-size` | `500` | Accounts per exported page (most recent login first) |
| `ttl-seconds` | `1800` | Snapshot lifetime |
| `local-http.enabled` | `false` | Serve the editor on loopback instead of using the hosted one |
| `local-http.bind` / `port` | `127.0.0.1` / `8787` | Loopback address |

## `email`

| Key | Default | Description |
| :--- | :--- | :--- |
| `enabled` | `false` | Enable SMTP recovery (`/email`) |
| `code-ttl-seconds` | `600` | Confirmation / recovery code lifetime |
| `cooldown-seconds` | `120` | Delay between code requests |
| `server-name` | `Minecraft Server` | Name used in the email |
| `smtp.host` / `port` | `smtp.example.com` / `587` | SMTP server |
| `smtp.security` | `STARTTLS` | `STARTTLS` (587), `SSL` (465) or `NONE` |
| `smtp.username` / `password` | empty | SMTP credentials – do not commit this file |
| `smtp.from-address` / `from-name` | `noreply@example.com` / `JustLogin` | Sender |
| `smtp.connect-timeout-ms` / `read-timeout-ms` | `5000` / `10000` | Timeouts |

Use `NONE` only for a trusted local relay.

## Example: strict public server

```yaml
login:
  ui: dialog
  timeout-seconds: 45
captcha:
  enabled: true
  require-on-register: true
registration:
  max-accounts-per-ip: 3
rate-limit:
  lockout-seconds: 600
sessions:
  enabled: false
totp:
  issuer: "My Server"
```
