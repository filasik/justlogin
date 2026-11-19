# Storage and Database

JustLogin uses **HikariCP** with either **SQLite** (default) or **MariaDB**. Drivers are downloaded on first start (`libraries.txt`), not bundled in the jar.

All database work (queries, hashing, HTTP) runs **asynchronously**; the main thread never waits on I/O.

## SQLite (default)

```yaml
storage:
  type: sqlite
  sqlite:
    file: "data/justlogin.db"
    pool-size: 4
```

Good for a single server. Back up `data/justlogin.db` while the server is stopped or use SQLite's online backup.

## MariaDB

Required when several servers (proxy + backends) share accounts.

```yaml
storage:
  type: mariadb
  mariadb:
    host: "db.internal"
    port: 3306
    database: "justlogin"
    user: "justlogin"
    password: "<strong password>"
    pool-size: 10
    ssl-mode: ""        # "trust" for self-signed certificates
```

1. Create the schema and a dedicated user:

   ```sql
   CREATE DATABASE justlogin CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   CREATE USER 'justlogin'@'%' IDENTIFIED BY '<strong password>';
   GRANT ALL PRIVILEGES ON justlogin.* TO 'justlogin'@'%';
   ```

2. Use **identical** `storage` settings on the proxy and every Paper backend.
3. Restart. Tables are created and migrated automatically.

The storage type cannot be switched at runtime; changing it requires a restart. Moving existing accounts from SQLite to MariaDB is not automated – plan it before you go live (export / import the tables yourself, together with `secrets.key`).

## Schema

Tables (shared prefix handled internally):

| Table | Content |
| :--- | :--- |
| `accounts` | Name, immutable `game_uuid`, optional `premium_uuid`, password hash + algorithm, premium flags, TOTP secret (encrypted) and last used step, force-change flag, email + recovery code hash, saved skin texture, timestamps, hashed last IP |
| `backup_codes` | Hashed single-use 2FA backup codes |
| `sessions` | Hashed IP + expiry for opt-in sessions |
| `audit_log` | Time, actor, action, target, details |

No plain-text passwords or plain IP addresses are stored.

## Migrations

Schema changes ship as **append-only migrations** (`v1` core tables, `v2` email recovery, `v3` skins). They run automatically when the plugin starts and are never edited afterwards, so upgrading is safe. Downgrading to an older plugin version is not supported – restore a backup if you must.

## Backups

Back up the database **and** `secrets.key` together. See the [Admin Guide](Admin-Guide#backups).
