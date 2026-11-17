# 02 – Audit (ROZPRACOVÁNO)

> Stav: revize byla přerušena limitem. **Přečteno celé:** `core` (kromě `importer/*` a `MojangSkinClient`), `editor` (kromě `EditorCrypto` a webového `index.html`), z `paper` hlavní třída, `Context`, listenery, `auth/*`, `premium/*`, `AuthCommands`, `ProxyStartupCheck`, `LogPasswordFilter`, `config.yml`, `paper-plugin.yml`, build a CI.
> **Nepřečteno:** `velocity/*`, `bungee/*`, `AdminCommands`, `EmailCommands`, `SkinCommands`, `AdminGui`, `Settings`, `ConfigUpdater`, `Messages`, importery, testy (jen spuštěny). Nálezy níže jsou fakta z kódu, pokud není uvedeno „domněnka" nebo „otevřená otázka".
> Build ověřen: `./gradlew build` prošel, 78 testů (core 39, editor 3, paper 29, velocity 3, bungee 4), 0 selhání.

## Kritické
Žádný nález této úrovně v přečtené části.

## Vysoké

### V1 – Backend věří `accountId` z proxy tokenu bez kontroly jména
- Kde: `paper/src/main/java/me/skerik/justlogin/paper/listener/ProxyMessageListener.java:53-64`
- Popis: po ověření HMAC a shody jména/UUID se účet načte přes `findById(verified.accountId())` a rovnou se na něj přihlásí. Neověřuje se, že `acc.nameLower()` odpovídá hráči.
- Dopad: pokud proxy a backend nesdílí jednu databázi (obě strany mají výchozí SQLite), ID se neshodují. Hráč pak dostane cizí `Account` do session a `recordSuccessfulSession` přepíše cizímu účtu `last_name` a `last_ip_hash` (`AccountStore.java:199-213`).
- Otevřená otázka: zda dokumentace sdílenou MariaDB vynucuje (proxy moduly jsem nestihl přečíst).
- Oprava: hledat účet podle `nameLower`, ověřit `id` i `gameUuid` proti tokenu, při neshodě odmítnout a zalogovat. Pracnost: S.

### V2 – Zablokování cizího jména drženým dialogem
- Kde: `paper/.../listener/ConfigureAuthListener.java:73-77`, `paper/.../listener/PlayerLifecycleListener.java:76-81`
- Popis: dokud má jméno rozpracovaný dialog v konfigurační fázi, každé další připojení pod tím jménem je odmítnuto. Útočník se připojí pod jménem oběti, nechá dialog otevřený (`login.timeout-seconds`, výchozí 60) a opakuje.
- Dopad: cílený DoS konkrétního hráče bez znalosti hesla.
- Oprava: limit souběžných nevyřízených dialogů na IP, a povolit nahrazení čekajícího spojení, pokud nové přichází z IP shodné s `last_ip_hash` účtu. Pracnost: M.

### V3 – Fail-closed na Mojang API jde zneužít k odstavení nových hráčů
- Kde: `core/.../service/ProxyAuthService.java:206-237`, `core/.../service/MojangApiClient.java:97-108`
- Popis: jakmile existuje jediný premium účet, každé neznámé jméno vyvolá dotaz na Mojang (i při `auto-detect-mojang: false`). `RATE_LIMITED`/`ERROR` znamená odmítnutí. Chyby se necachují a cache se při 4096 položkách celá maže.
- Dopad: boti s náhodnými jmény vyčerpají limit Mojang API a nikdo neregistrovaný se nepřipojí.
- Oprava: limit dotazů na IP před voláním Mojangu, LRU místo `clear()`, krátký circuit breaker; zvážit, zda má větev P0-7 při výpadku opravdu odmítat (rozhodnutí člověka). Pracnost: M.

## Střední

### S1 – Rate limit a limit účtů na IP nepočítají s IPv6 prefixem
- Kde: `core/.../crypto/IpHmac.java:32-40`, `core/.../security/LoginRateLimiter.java:51-79`, `core/.../storage/AccountStore.java:327-336`
- Dopad: útočník s /64 střídá adresy a obejde `max-attempts-per-ip`, `max-attempts-per-account-ip` i `max-accounts-per-ip`. Globální limit na účet záměrně není.
- Oprava: pro limity hashovat IPv6 zkrácené na /64 (session ponechat na plné adrese). Pracnost: S.

### S2 – Selhání startu nechá plugin zapnutý bez jasné hlášky
- Kde: `paper/.../JustLogin.java:97-103` (chytá se jen `IOException`; `new Database(...)` je mimo `try`), `core/.../crypto/ServerSecrets.java:95-98`
- Dopad: nedostupná MariaDB nebo poškozený `secrets.key` skončí nezachycenou výjimkou v async úloze. Plugin zůstane enabled, `context == null`, hráči vidí „not ready" navždy. Je to fail-closed, ale v rozporu se vzorem „jeden jasný řádek a `disablePlugin`".
- Oprava: obalit obě místa `catch (RuntimeException)` se stejnou větví jako u migrací. Pracnost: S.

### S3 – Session podle IP + legacy BungeeCord forwarding
- Kde: `paper/.../util/ProxyStartupCheck.java:61-72` (jen varování), `core/.../service/AuthService.java:180-187`
- Dopad: při `sessions.enabled: true`, režimu `bungee` a dostupném portu backendu lze podvrhnout IP oběti a session obnovit bez hesla. Výchozí nastavení (sessions vypnuté) zranitelné není.
- Oprava: v režimu `bungee` session odmítnout, nebo vyžadovat explicitní potvrzovací volbu. Pracnost: S.

### S4 – Chybějící indexy
- Kde: `core/.../storage/Migrations.java:22-88`; dotazy `AccountStore.java:316-324` (`premium = 1`) a `327-336` (`last_ip_hash`)
- Dopad: full scan tabulky při každé registraci a při každém připojení neznámého jména.
- Oprava: nová položka v4 v `Migrations.VERSIONS` s indexy na `last_ip_hash` a `premium`. Pracnost: S.

### S5 – Souběžný start více uzlů nad jednou MariaDB shodí migraci
- Kde: `core/.../storage/Migrations.java:104-113`
- Popis: DDL je idempotentní, ale `INSERT INTO justlogin_schema` u druhého uzlu narazí na primární klíč a start selže.
- Oprava: duplicitní klíč u vložení verze brát jako hotovo, případně `GET_LOCK`. Pracnost: S.

### S6 – Standalone hook: spolknutá chyba instalace
- Kde: `paper/.../premium/StandalonePremiumManager.java:139-156`
- Dopad: když `registerChannelListener` selže, `isActiveRuntime()` dál vrací true, banner hlásí „hook active" a premium účty jsou trvale odmítány (`PlayerLifecycleListener.java:144-147`). Smoke test to nepozná, kontroluje jen text banneru (`scripts/smoke-test.sh:86`).
- Oprava: uložit výsledek instalace a zahrnout ho do `isActiveRuntime()`, chybu zalogovat. Pracnost: S.

### S7 – Neomezená fronta DB a dotaz na každý Login Start
- Kde: `core/.../storage/Database.java:49`, `paper/.../premium/StandalonePremiumManager.java:257-259`
- Dopad: záplava spojení plní neomezenou frontu ještě před jakýmkoli limitem.
- Oprava: omezená fronta s odmítnutím, limit spojení na IP v handleru. Pracnost: M.

### S8 – Obnova hesla: kód se spotřebuje před hashováním
- Kde: `core/.../service/EmailRecoveryService.java:377-407`
- Dopad: při `HASHING_BUSY` je kód pryč a heslo se nezměnilo; hráč čeká na cooldown.
- Oprava: nejdřív hash, pak spotřeba kódu a zápis hesla v jedné transakci. Pracnost: S.

### S9 – Editor: blokující aplikace změn
- Kde: `editor/.../EditorService.java:154-194`, `221-278`
- Popis: `supplyAsync` na společném ForkJoin poolu s `.join()` na DB, jeden dotaz na každou změnu, bez transakce.
- Oprava: jedna `db.supply` s transakcí pro celý plán. Pracnost: M.

### S10 – Skin podle jména zdržuje přihlášení
- Kde: `paper/.../listener/PlayerLifecycleListener.java:161-172`, `config.yml:113`
- Dopad: výchozí zapnuto; každé připojení bez textur čeká až 2,5 s na Mojang a odesílá mu jména všech hráčů.
- Oprava: aplikovat skin až po přihlášení asynchronně, nebo zkrátit timeout a doplnit do dokumentace. Pracnost: M.

### S11 – CI a release
- `scripts/e2e.sh` a E2E boti jsou mimo repo (`.gitignore:32`), takže reflexní NMS hook (`StandaloneLoginBridge.java:102-180`) v CI nikdo reálně neprověří.
- `com.modrinth.minotaur` má dynamickou verzi `2.+` (`build.gradle.kts:5`); akce jsou připnuté tagem, ne SHA.
- `release.yml` neověřuje, že tag odpovídá `pluginVersion`.
- Repozitář Sonatype snapshots je zapnutý pro všechny moduly (`build.gradle.kts:29`).
- Pracnost: S–M.

## Nízké
- Dvojí `releaseInFlight` při výjimce v `login` (`AuthService.java:343-355`).
- `consumePreAuthGrant` grant nejdřív odebere, pak validuje; cizí spojení tak donutí oběť zadat heslo znovu (`AuthSessionManager.java:292-305`).
- Vynucená změna hesla se audituje jako `ADMIN_CHANGE_PASSWORD` (`AuthService.java:490`).
- Captcha kód se posílá klientovi v čitelné podobě, bota nezastaví (`PlayerLifecycleListener.java:285-287`).
- E-maily jsou natvrdo anglicky a předmět není kódován dle RFC 2047 (`EmailRecoveryService.java:202-208`, `316-322`; `SmtpMailer.java:93`), v rozporu s pravidlem „žádný hardcoded text".
- Lokální editor nemá session token, který plán uvádí; `POST /post` bez hlavičky `Origin` projde (`LocalHttpEditorServer.java:147-155`). Bloby jsou šifrované, dopad je jen paměť.
- `MojangApiClient.java:75` skládá URL bez enkódování jména (bezpečné jen s výchozím regexem).
- Seznam běžných hesel má 53 položek a heslo se kopíruje do `String` (`PasswordPolicy.java:19-34`).
- Zpětně kompatibilní konstruktory v `CoreSettings.java:34-137` a `Account.java:36-85` jsou balast.
- `CONTRIBUTING.md:4` říká Java 21+, toolchain vyžaduje 25 (`build.gradle.kts:33`).
- `AGENTS.md` je nesledovaná kopie `CLAUDE.md`; `CLAUDE.md` je v `.gitignore:27`.
- TOTP šifrování nemá AAD s ID účtu (`AesGcmCrypto.java:23-35`).

## Otevřené otázky
1. Chybí sekce „MOJE FEATURES"; zadání ji zmiňuje, ale žádné features neobsahuje.
2. Musí proxy a backend sdílet jednu databázi? (rozhoduje o závažnosti V1)
3. Je použití veřejného `https://bytebin.lucko.me` jako výchozího relay (`config.yml:151`) dohodnuté s provozovatelem?
4. Má větev P0-7 při výpadku Mojangu odmítat (bezpečnost), nebo pustit offline (dostupnost)?
5. Volá Paper `PlayerConnectionCloseEvent` i pro spojení odmítnutá v pre-loginu? Na tom stojí počítadla `rejectedDuplicatesByName` (`AuthSessionManager.java:191-206`); neověřeno.

## Co je v projektu dobře
- `core` bez závislosti na platformě, vše přes `CompletableFuture`, žádné I/O na hlavním vlákně.
- Argon2id s omezeným poolem a limitem na IP (`HashingExecutor`), rezervace pokusu před hashováním (`LoginRateLimiter.tryAcquire`).
- Důsledné porovnání v konstantním čase, nonce a časové razítko u proxy zpráv, typ zprávy je součástí HMAC.
- Atomické spotřebování TOTP kroku, záložních kódů a recovery kódu podmíněným `UPDATE`.
- Tajemství mimo DB, atomický zápis `secrets.key` s 0600, odmítnutí zástupného `shared-secret`.
- Bezpečné výchozí hodnoty (sessions a auto-detect vypnuté) a fail-closed při `context == null` a chybné proxy konfiguraci.
- Neměnné `game_uuid` řešené na jednom místě (`ProxyAuthService.resolveJoinProfile`).
- Editor: klíč jen ve fragmentu URL, změny autentizované AES-GCM, optimistický zámek přes `updated_at`, potvrzení ve hře.
- Přísný allowlist příkazů před přihlášením jako čistá testovatelná funkce.
- `-Xlint:all -Werror`, append-only migrace, smoke test v CI.
