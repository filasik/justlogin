# FAQ

### Which versions are supported?
Paper `1.21.7 – 26.x` and Folia, Velocity `3.x`, BungeeCord / Waterfall. Java 21+. Older Minecraft versions are not supported.

### Does it work on Folia?
Yes. It never uses the Bukkit scheduler and relies on region / entity / global / async schedulers.

### Do players get the dialog on every client?
Java `1.21.7+` gets the native dialog. Older clients (through ViaVersion), Bedrock without forms, and `login.ui: command` use the command flow. Bedrock players via Floodgate can use native forms.

### Can I use it without a proxy?
Yes – a single Paper server is the default setup, including `/premium` ([Installation](Installation)).

### Do I need ProtocolLib / PacketEvents / FastLogin?
No. Standalone `/premium` is built in.

### What happens to my existing AuthMe / LibreLogin / nLogin accounts?
Run `/jl import auto` ([Migration](Migration)). Existing passwords keep working and are upgraded to Argon2id on the player's next login.

### What is the `game_uuid`?
A permanent UUID that JustLogin assigns on first join. It stays the same whatever login method is used and across Mojang renames, so inventories, permissions, economy and claims don't get lost ([Premium Login](Premium-Login#the-immutable-game_uuid)).

### Does `/premium` let someone take over another player's account?
No. Only the account owner can arm it while authenticated, and the next join must pass a cryptographic Mojang session check. If verification fails, the account falls back to password login. Mojang name auto-detection, which trades safety for convenience, is **off by default**.

### Are passwords stored securely?
Hashed with Argon2id (memory-hard) and a bounded worker pool; legacy hashes are upgraded. Passwords are redacted from console / `latest.log`. The dialog input field itself is not masked on screen – see [Security Model](Security-Model#known-limitations-be-aware).

### What leaves my server?
Mojang session / skin lookups, GitHub update checks, bStats, the (encrypted) Web Editor relay if you use it, and your own SMTP server. All can be disabled; no passwords ever leave ([Security Model](Security-Model#external-connections)).

### How do I turn off telemetry?
`metrics: false` (and `update-check: false` if you also want no GitHub request).

### Can I change the messages / language?
Yes – edit `messages_<locale>.yml`; see [Messages and Localization](Messages-and-Localization). Bundled: English, Czech, Slovak.

### Does the 2FA QR code use an online QR service?
No. The QR code is generated on the server and drawn on a client-only map; nothing is sent anywhere and no item is added to the inventory. See [Two-Factor Authentication](Two-Factor-Authentication#the-qr-map).

### Can I have 2FA mandatory?
2FA is optional for players; you can reset it for anyone (`/jl reset2fa`). Requiring it for staff is a policy decision on your side.

### How do I run it on a network?
Install the proxy jar and the Paper jar everywhere, share one secret and one MariaDB: [Proxy Setup](Proxy-Setup).

### Is there a plugin API?
Yes: `JustLoginAPI` via Bukkit's `ServicesManager` and four lifecycle events ([Developer API](Developer-API)).

### Is it free?
Yes, MIT licensed. Donations are optional and never give in-game perks.

### Where do I report a bug or a vulnerability?
Bugs: [GitHub Issues](https://github.com/filasik/justLogin/issues). Vulnerabilities: **security@justlogin.net** (private).
