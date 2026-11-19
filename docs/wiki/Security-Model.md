# Security Model

## Defaults that protect you

| Setting | Default | Why |
| :--- | :--- | :--- |
| `sessions.enabled` | `false` | IP-bound auto-relogin is convenient but trusts the IP; opt in deliberately |
| `premium.auto-detect-mojang` / `proxy.auto-detect-mojang` | `false` | Prevents an unseen username from being treated as a Mojang-verified account just because of its name |
| Proxy `shared-secret` | must be set (≥ 16 chars) | Placeholder and blank values are rejected |
| `proxy.require-forwarding-config` | `true` | Startup verifies Paper's forwarding config |

## Principles

1. **Fail closed.** Connections arriving before JustLogin is ready are refused (`error.not-ready`). A bad proxy setup, a missing / placeholder shared secret or a failed forwarding check stops logins instead of letting players in unauthenticated.
2. **Nothing before authentication.** Until a player is authenticated: no movement, chat, inventory, block / entity interaction, item pickup / drop, damage or portals; only the command for their current step works (see [Commands and Permissions](Commands-and-Permissions#before-login)). With dialogs, the player is not even sent into the world.
3. **Passwords never leave the server and never reach logs.** `LogPasswordFilter` redacts command arguments in the Log4j2 output.
4. **Hashing off the main thread.** Argon2id (`19 MiB`, 2 iterations, 1 lane by default) runs on a bounded worker pool; when the queue is full players get a *busy* message instead of a lagging server (protects against hash-flood DoS).
5. **Constant-time comparisons** for secrets and signatures; **nonce + timestamp** checks on the `justlogin:auth` proxy channel.
6. **Immutable `game_uuid`.** Changing login method or Mojang name never changes the server UUID, so account takeover by name reuse cannot reach another account's data.

## Where secrets live

`plugins/JustLogin/secrets.key` holds the HMAC key, the TOTP encryption key and the proxy secret. It is deliberately **separate from the database** so SQL backups and dumps do not contain them. A host-level compromise still exposes local files, so keep file permissions tight and back the key up securely.

## Known limitations (be aware)

- **Dialog password fields are not masked.** Vanilla Minecraft dialogs show typed characters. The dialog header shows a warning icon. Servers that want masked input can use `login.ui: command` (the chat itself is not echoed to others).
- **BungeeCord legacy forwarding can be spoofed** if backend ports are reachable. Firewall them and use BungeeGuard.
- **Shared IPs** (schools, NAT): rate limits are tracked per account + IP and per IP separately so one attacker does not lock out a whole network immediately; tune `rate-limit.*` for your setup.
- **2FA QR map** shows the TOTP secret on screen during setup. Screenshots or a modified client can keep it. Disable with `totp.qr-map-enabled: false` if that worries you.
- **Web Editor relay** stores an encrypted snapshot with account names and UUIDs; use local mode if that is unacceptable ([Web Editor](Web-Editor)).

## External connections

JustLogin contacts only the following. Passwords are never sent anywhere.

| Service | Purpose | How to disable |
| :--- | :--- | :--- |
| Mojang `sessionserver.mojang.com` | Verify `/premium` sessions (`hasJoined`), fetch signed skin textures | `premium.standalone-enabled: false`, `skins.enabled: false` |
| GitHub Releases API | Update check (at startup and every 12 h) | `update-check: false` |
| [bStats](https://bstats.org) | Anonymous usage statistics, plugin ID 35316 | `metrics: false` or the global bStats opt-out |
| Web Editor (`justlogin.net`) and relay (`bytebin.justlogin.net`) | Receives only an AES-256-GCM encrypted snapshot | Don't use `/jl editor`, or `editor.local-http.enabled: true` |
| Your SMTP server | Account recovery emails | Leave `email.enabled: false` |

## Hardening checklist

- [ ] `secrets.key` backed up and not world-readable
- [ ] Backend ports reachable only from the proxy
- [ ] Long random `proxy.shared-secret`, identical everywhere
- [ ] `sessions.enabled` left `false` unless you accept the IP-trust trade-off
- [ ] Staff accounts use [2FA](Two-Factor-Authentication)
- [ ] `registration.max-accounts-per-ip` and `captcha` tuned for your player base
- [ ] Admin permissions granted individually, not `*`
- [ ] Database not exposed to the internet; MariaDB user limited to the JustLogin schema
- [ ] Plugin kept up to date (only the latest release receives security fixes)

## Reporting a vulnerability

Please **do not open a public issue.** Report privately:

- Email: **security@justlogin.net**
- or GitHub: *Security* tab → [Report a vulnerability](https://github.com/filasik/justLogin/security/advisories/new)

Include the version, steps to reproduce, and impact. Don't send real passwords, secrets or player data. Only the latest release receives security fixes.
