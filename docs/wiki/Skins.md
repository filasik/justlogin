# Skins

JustLogin includes a small skin manager so you do not need a separate skin plugin. It works standalone and behind Velocity.

## What it does

- **Name-matched skin (cosmetic)** – for password logins, the plugin can apply the Mojang skin that belongs to the same username (`skins.restore-by-name`). This is purely visual and never grants `/premium` or bypasses authentication.
- **`/skin <player|reset>`** – a player can wear another Mojang player's skin or reset to the default. Applied instantly, saved in the database, survives relogins.
- **`/jl skin <player> <target|reset>`** – an admin can set or reset someone else's skin.
- **Cooldown** – `skins.cooldown-seconds` (default 60), bypass with `justlogin.skin.bypasscooldown`.
- **Cache** – fetched textures are cached for `skins.cache-seconds` (default 600).

## Configuration

```yaml
skins:
  enabled: true
  restore-by-name: true
  command-enabled: true
  cooldown-seconds: 60
  cache-seconds: 600
```

On Velocity the equivalent `skins.enabled`, `skins.restore-by-name` and `skins.cache-seconds` are in the proxy `config.yml`.

## Permissions

| Permission | Default |
| :--- | :--- |
| `justlogin.skin` | everyone |
| `justlogin.skin.bypasscooldown` | op |
| `justlogin.admin.skin` | op |

## Notes

- Skin textures are fetched (signed) from Mojang's servers.
- Set `skins.enabled: false` to disable everything and stop contacting Mojang for skins.
