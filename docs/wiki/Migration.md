# Migration (importing from other plugins)

`/jl import` scans `plugins/` for supported authentication plugins and imports their accounts into JustLogin.

## Supported sources

| Source | Command argument |
| :--- | :--- |
| AuthMe | `authme` |
| FastLogin | `fastlogin` |
| LibreLogin / LibrePremium | `librelogin` |
| LoginSecurity | `loginsecurity` |
| nLogin | `nlogin` |
| OpeNLogin | `openlogin` |
| LimboAuth | `limboauth` |
| Authy | `authy` |

Each importer reads the source plugin's SQLite file or MySQL / MariaDB settings (from its own config) so database passwords do not have to be typed in the console.

## Recommended procedure

1. **Back up** the old plugin's data and the server world data.
2. Install JustLogin and start the server once, then keep the old plugin's folder in `plugins/` (data only; the old jar can be removed).
3. Preview:

   ```
   /jl import auto --dry-run
   ```

4. If the preview looks right:

   ```
   /jl import auto
   ```

   Or one source at a time: `/jl import authme`.
5. Read `plugins/JustLogin/import-report-<timestamp>.txt` (written when rows were skipped).
6. Test with an existing account, then remove the old plugin completely.

`auto` runs the password importers first and **FastLogin last**, so Mojang UUIDs and online flags pair up with already imported accounts.

## FastLogin and `premiumUuid` (important)

FastLogin has an option `premiumUuid` in `plugins/FastLogin/config.yml` that decides which UUID premium players play under. JustLogin follows it:

| FastLogin `premiumUuid` | What the import does with `game_uuid` |
| :--- | :--- |
| `true` (FastLogin's default, also used when the key is missing) | Premium accounts that still have an offline UUID get their `game_uuid` **rewritten to the Mojang UUID**. |
| `false` | `game_uuid` is **left untouched** (offline UUID kept). Only `premium = 1` and `premium_uuid` are set. Players that exist only in FastLogin get the offline UUID as `game_uuid`. |

**Why it matters:** OP, whitelist, permissions and `world/playerdata/` are tied to the UUID. If your server ran with `premiumUuid: false`, rewriting UUIDs would make premium players lose their inventory, OP and permissions. The import detects this from the FastLogin config automatically.

Override it manually for `/jl import fastlogin` (or `auto`):

| Flag | Effect |
| :--- | :--- |
| `--keep-offline-uuid` (alias `--preserve-game-uuid`) | Never touch `game_uuid`, regardless of the FastLogin config. |
| `--rewrite-uuid` | Always rewrite offline `game_uuid` to the Mojang UUID, even if FastLogin has `premiumUuid: false`. |

Always run `/jl import auto --dry-run` first: the output states `game_uuid=keep-offline` or `game_uuid=rewrite-to-mojang` for FastLogin, and the final summary and import report repeat it. The decision cannot be undone by re-running the import, so restore your backup if it was wrong.

## MySQL / MariaDB and TLS (`sslMode`)

If the old plugin's database uses a self-signed certificate, the import can fail with `Self signed certificates. Either set sslMode=trust...`. JustLogin picks the TLS mode in this order:

1. `--ssl-mode=<trust|disable|verify-ca|verify-full>` on the command
2. `sslMode` / `useSSL` from the old plugin's config (`useSSL: false` becomes `disable`, `true` / `REQUIRED` becomes `trust`)
3. `storage.mariadb.ssl-mode` from JustLogin's `config.yml`
4. the driver default

Manual example:

```
/jl import authme mysql 127.0.0.1 3306 authme root <password> authme --ssl-mode=trust --dry-run
```

`trust` encrypts the connection without verifying the certificate, which is fine for a one-off import from your own database.

## What is imported

- Usernames and password hashes
- Permanent UUIDs where the source has them (the `game_uuid` is preserved across AuthMe + FastLogin imports; see the FastLogin `premiumUuid` note above)
- Email addresses and TOTP secrets where the source stores them
- Mojang / premium flags (FastLogin)

Legacy hashes (AuthMe `SHA-256` / `SHA-512`, `BCrypt`, `PBKDF2`, split `BCrypt-2A` / `Argon-2ID` formats) are normalised. They stay valid, and **every account is upgraded to Argon2id automatically on its next successful login** – players notice nothing.

Rows that cannot be imported are skipped and listed in the import report, so check it after every run.

## After migrating

- Run `/jl status <name>` on a few accounts to check hash algorithm and UUID.
- Tell players nothing changes except the login window; their passwords still work.
- Keep the old database backup for a while.

## Moving between JustLogin servers

Use `storage.type: mariadb` on all servers (see [Storage and Database](Storage-and-Database)) or copy the SQLite database plus `secrets.key` together.
