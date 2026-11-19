# Messages and Localization

Every player-facing text comes from `plugins/JustLogin/messages_<locale>.yml`; there is no hard-coded text. Messages use [MiniMessage](https://docs.advntr.dev/minimessage/format.html), so colors, gradients, hover and click events all work.

## Languages

Bundled: `en` (English), `cs` (Czech), `sk` (Slovak). Select with `locale:` in `config.yml`, then `/jl reload`.

Lookup order for each key: **your edited file → bundled file of the selected language → bundled English**. Missing keys fall back to the built-in English text, so you only need to keep the keys you actually changed.

## Editing

```yaml
prefix: "<dark_gray>[<gradient:#38bdf8:#34d399><bold>JustLogin</bold></gradient><dark_gray>] "
auth:
  login-success: "<green>Welcome back, <white>{player}</white>!</green>"
```

- `{placeholders}` such as `{player}`, `{seconds}`, `{min}`, `{max}`, `{version}` are replaced with escaped values, so a player name can never inject MiniMessage tags.
- Keep the placeholders present in the original text.
- The help texts (`help.cmd.<id>.syntax/desc/example/note`) are in the same file.

## Adding a language

1. Copy `messages_en.yml` to `messages_<code>.yml` (for example `messages_de.yml`).
2. Translate the values only, never the keys.
3. Set `locale: de` and run `/jl reload`.

If you want it included in the plugin, send a pull request: bundled languages must contain exactly the same keys as English (a unit test enforces key parity for `en`, `cs`, `sk`). See [Building and Contributing](Building-and-Contributing).

## Proxy messages

The few kick messages shown by Velocity / BungeeCord live under `messages:` in the proxy `config.yml` (see [Proxy Setup](Proxy-Setup)).
