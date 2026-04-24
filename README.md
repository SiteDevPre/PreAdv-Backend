# PRE ADV Backend — Railway + PostgreSQL

Backend completo per:

- autenticazione admin
- autenticazione clienti
- area clienti
- dashboard admin
- tracking visite/click/IP
- lead dal sito
- richieste cliente
- progetti
- chat cliente/admin
- consegne foto/video
- download autorizzato
- storage S3/R2 opzionale per file grandi

## 1. Deploy su GitHub + Railway

1. Crea una repo GitHub, per esempio `pre-adv-backend`.
2. Carica tutti questi file nella repo.
3. Su Railway:
   - New Project
   - Deploy from GitHub repo
   - seleziona `pre-adv-backend`
4. Aggiungi PostgreSQL:
   - Add service
   - Database
   - PostgreSQL
5. Railway imposta `DATABASE_URL` automaticamente.

## 2. Variabili Railway obbligatorie

Nel servizio backend, aggiungi:

```env
JWT_SECRET=metti-una-stringa-lunghissima-random
ADMIN_PASSWORD=progettoadv1
ADMIN_EMAIL=owner@preadv.it
FRONTEND_ORIGIN=https://www.preadv.it,https://preadv.it
PUBLIC_BACKEND_URL=https://TUO-BACKEND.up.railway.app
NODE_ENV=production
```

`ADMIN_EMAIL` è l'email con cui entrerai nel pannello admin quando lo collegheremo. La password sarà `progettoadv1`.

## 3. Comando Railway

Il file `railway.toml` imposta già:

```bash
npm run start:railway
```

che esegue:

```bash
npx prisma db push && node src/server.js
```

Quindi il database viene inizializzato automaticamente.

## 4. Test rapido

Apri:

```txt
https://TUO-BACKEND.up.railway.app/api/health
```

Deve rispondere:

```json
{ "ok": true, "service": "PRE ADV Backend" }
```

## 5. Collegamento al frontend Aruba

Su Aruba devi aggiungere i file dentro `/www/`:

```txt
/www/preadv-api-client.js
/www/preadv-api-tracker.js
```

Poi nella `index.html`, prima di `</body>`:

```html
<script>
  window.PREADV_API_BASE = "https://TUO-BACKEND.up.railway.app";
</script>
<script src="/preadv-api-tracker.js"></script>
<script src="/preadv-api-client.js"></script>
```

## 6. Login cliente

La pagina `login.html` dovrà chiamare:

```js
await PREADV_API.clientRegister({ name, email, password, company, phone });
await PREADV_API.clientLogin(email, password);
```

Dopo login, manda il cliente a:

```txt
area-clienti.html
```

## 7. Area clienti

La futura `area-clienti.html` chiamerà:

```js
const dashboard = await PREADV_API.clientDashboard();
```

E riceverà:

```json
{
  "user": {},
  "projects": [],
  "requests": [],
  "deliveries": [],
  "messages": []
}
```

## 8. Admin panel

Il pannello `/gestione` dovrà fare login con:

```js
await PREADV_API.adminLogin("owner@preadv.it", "progettoadv1");
```

Poi potrà chiamare:

```js
await PREADV_API.adminDashboard();
await PREADV_API.adminClients();
```

## 9. File grandi

Per file 4K/foto massima qualità, usa Cloudflare R2 o storage S3.

Variabili opzionali:

```env
S3_ENDPOINT=
S3_REGION=auto
S3_BUCKET=
S3_ACCESS_KEY_ID=
S3_SECRET_ACCESS_KEY=
S3_PUBLIC_BASE_URL=
```

Endpoint upload firmato:

```txt
POST /api/admin/storage/presign-upload
```

Endpoint download cliente:

```txt
GET /api/client/download/:deliveryId
```

## 10. API principali

### Auth
- `POST /api/auth/client/register`
- `POST /api/auth/client/login`
- `POST /api/auth/admin/login`
- `POST /api/auth/logout`
- `GET /api/me`

### Tracking
- `POST /api/track/visit`
- `POST /api/track/click`

### Client
- `GET /api/client/dashboard`
- `POST /api/client/requests`
- `GET /api/client/messages`
- `POST /api/client/messages`
- `GET /api/client/deliveries`
- `GET /api/client/download/:deliveryId`

### Admin
- `GET /api/admin/dashboard`
- `GET /api/admin/clients`
- `POST /api/admin/clients`
- `GET /api/admin/visits`
- `GET /api/admin/clicks`
- `GET /api/admin/leads`
- `GET /api/admin/requests`
- `PATCH /api/admin/requests/:id`
- `GET /api/admin/projects`
- `POST /api/admin/projects`
- `GET /api/admin/deliveries`
- `POST /api/admin/deliveries`
- `GET /api/admin/messages/:clientId`
- `POST /api/admin/messages`

## 11. Importante

Il backend è pronto. Il prossimo step è collegare:
- `login.html`
- `area-clienti.html`
- `/gestione/index.html`

alle API reali tramite `preadv-api-client.js`.
