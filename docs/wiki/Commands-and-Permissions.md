# Commands and Permissions

All commands are Brigadier commands with full tab completion (including stored account names). In-game, `/jl help [page|topic|command]` shows interactive help and detail cards for every command below.

## Player commands

| Command | Aliases | Permission | Description |
| :--- | :--- | :--- | :--- |
| `/register <password> <confirm>` | `/reg` | `justlogin.use` | Register a new account |
| `/login <password>` | `/l` | `justlogin.use` | Log in |
| `/logout` | – | `justlogin.use` | End your authenticated session |
| `/changepassword <old> <new>` | `/changepass`, `/cp` | `justlogin.use` | Change your password (invalidates sessions) |
| `/unregister <password>` | – | `justlogin.use` | Permanently delete your own account |
| `/captcha <code>` | – | `justlogin.use` | Solve the anti-bot captcha |
| `/2fa setup` | – | `justlogin.2fa` | Create a TOTP secret, `otpauth://` link and (optionally) a temporary QR map |
| `/2fa cancel` | – | `justlogin.2fa` | Discard a pending setup and hide the QR map |
| `/2fa confirm <code>` | – | `justlogin.2fa` | Activate 2FA and receive 8 backup codes |
| `/2fa verify <code>` | – | `justlogin.2fa` | Complete login with a TOTP or backup code |
| `/2fa disable <code>` | – | `justlogin.2fa` | Turn 2FA off (needs a valid code) |
| `/email set <address> <password>` | – | `justlogin.email` | Request binding a recovery email |
| `/email confirm <code>` | – | `justlogin.email` | Confirm the email with the emailed code |
| `/email clear` | – | `justlogin.email` | Remove the recovery email |
| `/email recover <player> [code] [newPassword]` | – | `justlogin.email` | Request a reset code, then finish with `<code> <newPassword>` |
| `/premium` | – | `justlogin.premium` | Arm Mojang auto-login for the next join |
| `/unpremium [password]` | – | `justlogin.premium` | Switch back to password login (`[password]` only if the account has none yet) |
| `/skin <player\|reset>` | `/skins` | `justlogin.skin` | Change or reset your skin |
| `/jl help [page\|topic\|cmd]` | `/justlogin help`, `/jl ?` | `justlogin.use` | Help |

Features that are disabled in the config (email, captcha, premium, skins) are marked `[... disabled]` in the help.

## Admin commands

`/jl`, `/justlogin` and `/auth` are the same command.

| Command | Permission | Description |
| :--- | :--- | :--- |
| `/jl reload` | `justlogin.admin.reload` | Reload `config.yml` and messages |
| `/jl status <player>` | `justlogin.admin.status` | UUIDs, hash algorithm, premium, 2FA, session state (never hashes or secrets) |
| `/jl audit [limit]` | `justlogin.admin.audit` | Recent security / admin audit entries |
| `/jl unregister <player>` | `justlogin.admin.unregister` | Delete an account (kicks the player if online) |
| `/jl changepassword <player> <password>` (alias `changepass`) | `justlogin.admin.changepass` | Set a password for a player |
| `/jl forcechangepassword <player> <true\|false>` (alias `forcepw`) | `justlogin.admin.forcepw` | Require a new password on next login (preferred over setting one yourself) |
| `/jl reset2fa <player>` | `justlogin.admin.reset2fa` | Clear 2FA secret and backup codes |
| `/jl setpremium <player> <true\|false>` | `justlogin.admin.setpremium` | Override the Mojang-login flag (UUID is preserved) |
| `/jl rename <old> <new>` | `justlogin.admin.rename` | Rename an account, keeping its `game_uuid` |
| `/jl merge <source> <target>` | `justlogin.admin.merge` | Merge source into target, keeping the target's `game_uuid`; deletes the source record |
| `/jl gui [page]` | `justlogin.admin.gui` | Chest-GUI account browser |
| `/jl import [auto\|authme\|fastlogin\|librelogin\|loginsecurity\|nlogin\|openlogin\|limboauth\|authy] [--dry-run] [--ssl-mode=<mode>] [--keep-offline-uuid]` | `justlogin.admin.import` | Migrate from other plugins – see [Migration](Migration) |
| `/jl skin <player> <target\|reset>` | `justlogin.admin.skin` | Set / reset another player's skin |
| `/jl editor [page]` | `justlogin.editor` | Export an encrypted [Web Editor](Web-Editor) session (accounts ordered by most recent login) |
| `/jl applyedits <code\|confirm>` | `justlogin.editor` | Preview, then apply Web Editor changes |

## Permissions

| Permission | Default | Description |
| :--- | :--- | :--- |
| `justlogin.use` | everyone | Basic authentication commands |
| `justlogin.2fa` | everyone | `/2fa` |
| `justlogin.premium` | everyone | `/premium`, `/unpremium` |
| `justlogin.email` | everyone | `/email` |
| `justlogin.skin` | everyone | `/skin` |
| `justlogin.skin.bypasscooldown` | op | Skip the `/skin` cooldown |
| `justlogin.editor` | op | Web Editor commands |
| `justlogin.admin` | op | Parent of every admin sub-permission below, plus `justlogin.editor` |
| `justlogin.admin.reload` / `.status` / `.audit` / `.unregister` / `.changepass` / `.forcepw` / `.reset2fa` / `.setpremium` / `.rename` / `.merge` / `.gui` / `.import` / `.skin` | op | Individual admin commands |

Grant a single sub-permission (for example `justlogin.admin.status` to moderators) instead of full `justlogin.admin` where you can. Only players with `justlogin.admin` receive update notifications.

## Before login

Unauthenticated players are in a strict default-deny lockdown: only the command that matches their current step is allowed (`/register`, `/login`, `/captcha`, `/email recover ...`, `/2fa verify ...`, `/changepassword` for forced changes, and `/jl help`). Other plugins' namespaced commands (`otherplugin:cmd`) are rejected, and the tab-completion list is trimmed to match.

## Password logging

`LogPasswordFilter` removes the arguments of `login`, `register`, `changepassword`, `unregister`, `unpremium`, `2fa`, `email set/confirm/recover` and `jl changepassword` from the console and `logs/latest.log`. Other plugins' command loggers may still record them – prefer the dialog login.
