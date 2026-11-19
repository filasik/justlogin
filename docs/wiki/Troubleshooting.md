# Troubleshooting

Always start with the console: JustLogin prints **one clear line** for fatal problems and then disables itself instead of running half-configured. Include the first error lines and your version when you [open an issue](https://github.com/filasik/justLogin/issues).

## Startup

| Symptom | Cause / fix |
| :--- | :--- |
| Plugin disables itself right after start | Read the error line right above it: a bad `proxy.*` setting, a database that can't be opened, or missing libraries |
| `Cannot download libraries` / driver errors | First start needs internet to fetch `libraries.txt` dependencies. Allow outbound HTTPS or start once on a connected host and copy the downloaded libraries |
| Import fails with `Self signed certificates ... sslMode=trust` | Add `--ssl-mode=trust` to the import command or set `storage.mariadb.ssl-mode` (see [Migration](Migration)) |
| Database connection error with MariaDB | Check host / port / user / password / `ssl-mode`, that the schema exists and the user may connect from the server's IP |
| `proxy.enabled=true cannot use proxy.mode=standalone` | Set `proxy.mode: velocity` or `bungee` |
| `proxy.shared-secret ... at least 16 characters` | Set a long secret, identical on proxy and Paper |
| `proxies.velocity.enabled is false in config/paper-global.yml` | Enable Velocity forwarding in Paper (and set its secret) |
| `settings.bungeecord is false in spigot.yml` | Enable BungeeCord forwarding in `spigot.yml` |

## Players cannot log in

| Symptom | Cause / fix |
| :--- | :--- |
| *"An internal authentication error occurred"* / *not ready* | Connected before startup finished (or startup failed). Wait for the banner, check the console |
| *"Your username does not match the allowed server pattern"* | `username.regex` (default 3–16 letters, digits, `_`) |
| *"Incorrect password"* repeatedly, then *"Too many failed login attempts"* | Rate limit / lockout (`rate-limit.*`); the player has to wait for `rate-limit.lockout-seconds` |
| Captcha keeps appearing | Triggered after `captcha.trigger-after-failures` failures, or always with `require-on-register` |
| *"A player with this username is already connected and authenticated"* | `login.kick-duplicate-online: true`; the other session must end first |
| *"The authentication queue is busy"* | Hash queue full. Lower Argon2 cost or raise `password.hashing.max-queued` / `max-concurrent` if the CPU allows |
| *"Maximum number of registered accounts from your IP address has been reached"* | `registration.max-accounts-per-ip` |
| *"Authentication timed out"* | `login.timeout-seconds` |
| Player is held / can't move after logging in on a network | Proxy and Paper `shared-secret` differ, or the backend never got `BACKEND_AUTH_OK`; check both consoles |

## Dialog / client issues

| Symptom | Cause / fix |
| :--- | :--- |
| No dialog, only chat commands | Client is older than `1.21.7` (e.g. via ViaVersion), a Bedrock player, or `login.ui: command` |
| Bedrock player sees chat instead of a form | Floodgate missing or `bedrock.cumulus-forms: false` |
| Dialog shows the typed password | Vanilla behaviour; use `login.ui: command` if that is unacceptable |

## Mojang login (`/premium`)

| Symptom | Cause / fix |
| :--- | :--- |
| `/premium` armed but the next join asks for a password | The client could not present a verified Mojang session (not a Java account, session-server issue). JustLogin deliberately rolls back to password login – nobody is locked out |
| Standalone verification never runs | `premium.standalone-enabled: false`, `server.properties` `online-mode=true`, or `proxy.enabled=true` (see [Premium Login](Premium-Login#standalone-paper)) |
| Warning about Paper proxy forwarding while `proxy.enabled=false` | Paper forwarding is on but JustLogin is standalone; fix one of them |
| Verification fails behind NAT / tunnels | Keep `premium.prevent-proxy-connections: false` |
| *"This account requires Mojang verification through the network proxy"* | The account is marked premium and connected without proxy verification |

## 2FA

| Symptom | Cause / fix |
| :--- | :--- |
| Valid code rejected | Phone clock drift (enable automatic time); raise `totp.window-steps` to 2 if needed. A code can only be used once |
| *"Could not verify 2FA secret due to a server key error"* | `secrets.key` was changed or lost. `/jl reset2fa <player>` and have players set 2FA up again |
| Lost authenticator and backup codes | `/jl reset2fa <player>` |
| No QR map during `/2fa setup` | `totp.qr-map-enabled: false`, or the client could not show it. Use the secret key / URI from chat |
| QR map vanished before scanning | It hides on slot change, inventory use, teleport, etc. and after 120 s. Run `/2fa setup` again and keep still |

## Email recovery

| Symptom | Cause / fix |
| :--- | :--- |
| `/email` says it is disabled | `email.enabled: false` |
| No email arrives | Check SMTP host / port / `security` (`STARTTLS` on 587, `SSL` on 465), credentials, spam folder, `email.cooldown-seconds` |

## Web Editor

| Symptom | Cause / fix |
| :--- | :--- |
| Link expired | Snapshots live `editor.ttl-seconds` (default 1800 s); run `/jl editor` again |
| Can't reach the relay | Outbound HTTPS to `editor.relay-url` blocked, use `editor.local-http.enabled: true` |
| Upload fails with HTTP 403, or the editor shows HTTP 404 | You are on 1.0.2 or older with the old `bytebin.lucko.me` relay. Update to 1.0.3+; the default relay is migrated to `https://bytebin.justlogin.net` automatically |
| `applyedits` code rejected | Wrong / expired code, or the snapshot belongs to another page / server |

## Import

| Symptom | Cause / fix |
| :--- | :--- |
| `/jl import auto` finds nothing | The old plugin's folder must still be in `plugins/` (data only is enough) |
| Many skipped rows | Open `plugins/JustLogin/import-report-<timestamp>.txt` |

## Still stuck?

[Open an issue](https://github.com/filasik/justLogin/issues) with: JustLogin version, Paper / Velocity / Bungee version, Java version, the relevant console lines, and your (redacted!) `config.yml`. Security problems go to **security@justlogin.net**, never public issues.
