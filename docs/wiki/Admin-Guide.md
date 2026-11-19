# Admin Guide

Day-to-day account management. All commands need the permissions listed in [Commands and Permissions](Commands-and-Permissions).

## Inspecting accounts

```
/jl status <player>     # UUIDs, hash algorithm, premium, 2FA, session state
/jl audit [limit]       # recent security and admin actions
```

`/jl status` is read-only and never prints hashes or secrets. The audit log records who did what (actor, action, target, details) and is pruned after `audit.retention-days` (default 90).

## The account GUI

`/jl gui [page]` opens a 54-slot chest browser of all accounts (click and drag are strictly locked):

| Click | Action |
| :--- | :--- |
| Left | Toggle *force password change* |
| Shift + Left | Reset 2FA |
| Right | Inspect the account in chat |
| Shift + Right | Unregister the account |

## Common tasks

| Situation | What to do |
| :--- | :--- |
| Player forgot their password and has no email | `/jl changepass <player> <temporary password>`, then `/jl forcepw <player> true` – the player must choose their own password at next login |
| Player lost their authenticator | `/jl reset2fa <player>` |
| Player changed their Minecraft name | `/jl rename <old> <new>` – the `game_uuid` (inventory, permissions...) is preserved |
| Player created a duplicate account | `/jl merge <duplicate> <real>` – keeps the target's `game_uuid`, carries over premium UUID / email if the target lacks them, deletes the source |
| Account is stuck in Mojang mode | `/jl setpremium <player> false` |
| Remove an account | `/jl unregister <player>` |
| Edit many accounts at once | [Web Editor](Web-Editor) |

Avoid setting someone's password from the console if your console history is accessible; `/jl forcepw` is safer because only the player ever knows the new password.

## Reloading

`/jl reload` reloads `config.yml` and `messages_<locale>.yml`. Changing `storage.*` needs a restart.

## Backups

Back up together, regularly:

- the database (`plugins/JustLogin/data/justlogin.db` or your MariaDB schema), and
- `plugins/JustLogin/secrets.key`.

The key is intentionally *not* in the database. Without it, 2FA secrets, signed sessions and proxy signing keys cannot be recovered (players can still log in with their password; 2FA must be reset with `/jl reset2fa`).

## Update notifications

Admins with `justlogin.admin` get a chat notice when they authenticate and a newer release exists. Disable with `update-check: false`.

## Monitoring

- The console banner on startup reports readiness time and any fatal configuration error.
- Warnings about proxy / forwarding mismatches are printed at startup (see [Proxy Setup](Proxy-Setup)).
- `HASHING_BUSY` messages to players mean your hash queue is full – raise `password.hashing.max-queued` or `max-concurrent` only if your CPU can take it, or lower Argon2 cost.
