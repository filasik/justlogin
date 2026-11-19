# Developer API

Other plugins can read authentication state and react to lifecycle events. The API contains **no secrets**: `AccountSnapshot` never exposes password hashes, TOTP secrets, IP hashes, email addresses or recovery tokens.

## Depend on JustLogin

Add JustLogin as a compile-only dependency (use the jar from the [Releases page](https://github.com/filasik/justLogin/releases)) and declare it as a dependency in your `paper-plugin.yml`:

```yaml
dependencies:
  server:
    JustLogin:
      load: BEFORE
      required: false
```

## Service

```java
JustLoginAPI api = Bukkit.getServicesManager().load(JustLoginAPI.class);
if (api == null) return; // JustLogin not present or not ready yet

if (api.isAuthenticated(player)) {
    api.findAccount(player.getUniqueId()).thenAccept(opt -> opt.ifPresent(account -> {
        UUID permanentUuid = account.gameUuid();
        boolean premium = account.premiumConfirmed();
    }));
}
```

| Method | Description |
| :--- | :--- |
| `boolean isAuthenticated(UUID)` / `isAuthenticated(Player)` | Is the player fully logged in |
| `CompletableFuture<Optional<AccountSnapshot>> findAccount(String username)` | Look up by name (async) |
| `CompletableFuture<Optional<AccountSnapshot>> findAccount(UUID gameUuid)` | Look up by permanent UUID (async) |
| `void forceLogout(Player)` | Log the player out |

Futures complete off the main thread; hop back to the right region / entity scheduler before touching the world (Folia).

## `AccountSnapshot`

| Field | Type |
| :--- | :--- |
| `id` | `long` |
| `username` | `String` |
| `gameUuid` | `UUID` – permanent server UUID |
| `premiumUuid` | `@Nullable UUID` |
| `premiumConfirmed` | `boolean` |
| `hasTotp` | `boolean` |
| `forcePasswordChange` | `boolean` |
| `hasEmail` | `boolean` |
| `registeredAt`, `lastLoginAt` | `long` (epoch millis) |

## Events (`me.skerik.justlogin.api.event`)

| Event | Fired when | Getters |
| :--- | :--- | :--- |
| `PlayerAuthenticatedEvent` | Authentication completes | `getPlayer()`, `getAccount()`, `getMethod()` – `PASSWORD`, `PASSWORD_2FA`, `SESSION`, `PROXY_PREMIUM`, `STANDALONE_PREMIUM`, `EMAIL_RECOVERY` |
| `PlayerRegisteredEvent` | A new account is registered and logged in | `getPlayer()`, `getAccount()` |
| `PlayerLoggedOutEvent` | `/logout`, a proxy request or the API logs a player out | `getPlayer()`, `getAccount()` |
| `PlayerPremiumVerifiedEvent` | A `/premium` verification succeeds with Mojang proof | `getPlayer()`, `getPremiumUuid()`, `getAccount()` |

All events are synchronous-style Bukkit events (`isAsync() == false`).

```java
@EventHandler
public void onAuth(PlayerAuthenticatedEvent e) {
    getLogger().info(e.getPlayer().getName() + " authenticated via " + e.getMethod());
}
```

## Tips

- Key your own data by **`gameUuid`** (it is what the server sees as the player's UUID and never changes).
- Do not do anything sensitive for a player before `isAuthenticated` is true – JustLogin already blocks most Bukkit interactions until then, but your plugin's own logic should respect it.
