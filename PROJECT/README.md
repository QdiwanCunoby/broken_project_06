# LipariBank — Project Work Giorno 6 (Auth: JWT, cookie sicuri, change-password)

## Avvio

```bash
# Postgres del G0 (bootcamp/node): container liparibank-db su localhost:5432
cd ../../node && docker compose up -d
cd -
cp .env.example .env            # DATABASE_URL punta al Postgres del G0
npm install
npx prisma migrate dev          # applica prisma/migrations/*_init
npx prisma db seed              # idempotente: 2 clienti, 3 conti
npm run dev
```

Richieste di prova: [requests/liparibank.http](requests/liparibank.http) (estensione REST Client).

## Cosa c'è

| Esercizio | Dove |
|-----------|------|
| 1-3 Schema + migrazione | `prisma/schema.prisma`, `prisma/migrations/*_init/migration.sql` |
| 4 Repository Prisma | `PrismaAccountRepository`, `PrismaCustomerRepository` (stesse interfacce degli InMemory) |
| 4 Composition root | `src/app.ts`: un solo `PrismaClient`, cambiano solo le righe dei repository |
| 5 Transfer | `src/modules/transfer/` — `$transaction` interattiva, `Prisma.Decimal` |
| 6 Seed | `prisma/seed.ts` (upsert), `"prisma": { "seed": "tsx prisma/seed.ts" }` |
| 7 Test | `requests/liparibank.http` (T1-T6) |

## Scelte

- **Decimal**: `balance` e `amount` sono `Decimal(15,2)`; nel codice sono `Prisma.Decimal`, nelle risposte JSON stringhe (`"1000.00"`). Mai `number`.
- **409 per fondi insufficienti** (non 422): la richiesta è valida, è lo stato del conto a impedirla. 422 resta per i dati malformati.
- **Addebito condizionato**: `updateMany({ where: { balance: { gte: amount } } })` rende controllo e scrittura un'unica operazione atomica, quindi due bonifici concorrenti non portano il saldo sotto zero.
- **Rollback**: qualsiasi errore dentro la `$transaction` annulla addebito, accredito e record Transfer.
- **onDelete: Restrict** su tutte le FK: non si cancellano clienti o conti con storico (si chiudono).
- **Interfacce invariate**: `Account.balance` è `string` nel dominio (era `number` in memoria) — l'unica modifica ai tipi, necessaria per non far passare i soldi dai float.


---

# Giorno 6 — The Broken Project

Base: copia di `G5/PROJECT` (G6 era vuota e il broken project non era disponibile), con il modulo auth costruito **già corretto** per i 3 bug + feature opzionale.

## Avvio

```bash
cp .env.example .env
# Generare con: openssl rand -base64 64   (due valori DIVERSI per JWT_SECRET e JWT_REFRESH_SECRET)
npm install
npx prisma migrate dev          # applica anche 20261012100000_add_users
npm run dev
npm test                        # vitest + supertest, usa un repository in memoria: non serve il DB
```

## Bug 1 — JWT secret hardcoded
- Secret letti da `JWT_SECRET` / `JWT_REFRESH_SECRET` in `src/config/env.ts`; nessun default.
- **Fail fast**: se mancano, sono < 32 caratteri o sono uguali, `env.ts` lancia e l'app non parte (testato).
- `.env.example` ha i placeholder vuoti + `# Generare con: openssl rand -base64 64`; `.env` è già in `.gitignore`.
- **Rotazione**: i secret vanno ruotati in *tutti* gli ambienti perché lo storico Git conserva `secret123`. Un secret per ambiente, mai condiviso.
- **Produzione LipariBank**: Azure Key Vault (o Kubernetes Secret montato come env var/file), mai un `.env` in chiaro sul server.

## Bug 2 — Cookie sicuri (`src/modules/auth/auth.cookies.ts`)
Entrambi i cookie: `httpOnly: true`, `secure: NODE_ENV === "production"`, `sameSite: "lax"`, `maxAge`, `path`. Il `refresh_token` ha `path=/api/auth/refresh`.

- **Strict**: il cookie non viaggia mai cross-site, nemmeno seguendo un link esterno.
- **Lax**: parte solo nelle navigazioni top-level GET cross-site, non in POST/fetch/iframe → blocca il CSRF senza rompere i link in ingresso.
- **None**: parte sempre (richiede Secure), serve solo per embed/SSO cross-site ed espone al CSRF.
- LipariBank usa **Lax**: protegge bonifici e cambio password dal CSRF restando usabile dai link in email.

Verifica manuale: dopo il login `document.cookie` in console torna `""`; i cookie restano visibili in DevTools → Application → Cookies.

## Bug 3 — `bcrypt.compare` con argomenti invertiti
`bcrypt.compare(input.password, user.passwordHash)` (plain, hash). TypeScript non l'aveva segnalato perché **entrambi i parametri sono `string`**: la type safety non salva dagli errori semantici. Lo prende il test di integrazione register + login in `tests/auth.test.ts`.

Variante: `authenticate` va registrato **prima** delle route (`app.use("/api/customers", authenticate, customerRoutes)`); Express applica i middleware in ordine di registrazione. Un test verifica che le route protette rispondano 401 senza cookie.

## Feature — `POST /api/auth/change-password`
- Body validato da `changePasswordSchema` (policy password + nuova ≠ attuale → 422); password attuale errata → **401**.
- `bcrypt.hash(…, 12)`; rate limit **3 tentativi / 15 min** per `IP + userId` → 429.
- Risposta 204 e cookie della richiesta cancellati: il frontend rifà login.

### Strategia di invalidazione: `tokenVersion`
Scelta tra le tre opzioni:

| Opzione | Valutazione |
|---|---|
| Cambiare `JWT_SECRET` | Butta fuori **tutti** gli utenti: inaccettabile in produzione |
| Blacklist `jti` su Redis | Chirurgica, ma richiede infrastruttura Redis che oggi non c'è |
| **`tokenVersion`** ✅ | Invalida solo l'utente interessato, nessuna infrastruttura nuova |

Come funziona: `users.token_version` (default 0) finisce nel claim `tv` di access e refresh token. `updatePassword` salva il nuovo hash e fa `token_version + 1` nella **stessa** UPDATE. `authenticate` e `/refresh` caricano l'utente e rifiutano (401) i token con `tv` diversa.

**Perché non fare nulla è inaccettabile**: i JWT sono stateless, quindi senza invalidazione un token rubato resterebbe valido 15 min (access) / 7 giorni (refresh) anche dopo il cambio password: l'utente che reagisce a un furto di sessione non avrebbe alcuna certezza che il ladro sia fuori. Con `tokenVersion` l'accesso del ladro cessa alla richiesta successiva (testato: access, refresh e nuovo change-password con i cookie vecchi → 401).

**Costo accettato**: una query al DB (per PK) a ogni richiesta autenticata. Se diventasse un collo di bottiglia: cache breve della `tokenVersion` o passaggio alla blacklist `jti` su Redis.