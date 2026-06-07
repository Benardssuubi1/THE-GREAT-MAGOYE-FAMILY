# Magoye API — Updated Endpoints

## New Features & Endpoints

### 1. Authentication (`/api/auth/`)
- **POST `/api/auth/register`** — User registration
  - Required: `email`, `password`
  - Optional: `fullName`, `branch`
  - Response: `{success, id}`

- **POST `/api/auth/login`** — User login
  - Required: `email`, `password`
  - Response: `{success, id, email, full_name, branch}`

### 2. Media Library (`/api/media/`)
- **GET `/api/media/library`** — Fetch all media (public)
  - Query params: `limit` (default: 50, max: 200)
  - Response: Array of media objects `{id, type, title, description, date, thumbnail, src, created_at}`

- **POST `/api/media/library`** — Add new media (requires API key)
  - Required: `title`, `src` (URL)
  - Optional: `type`, `description`, `date`, `thumbnail`
  - Response: `{success, id}`

- **DELETE `/api/media/<mid>`** — Delete media (requires API key)
  - Response: `{success}`

### 3. Legacy Fund (`/api/legacy-fund/`)
- **GET `/api/legacy-fund/summary`** — Fetch fund progress (public)
  - Response: `{target_amount, target_currency, amount_raised, currency, supporters, percentage}`

- **GET `/api/legacy-fund/contributions`** — Fetch recent contributions (public)
  - Query params: `limit` (default: 6, max: 50)
  - Response: Array of contributions `{id, donor_name, amount, currency, is_anonymous, created_at}`

- **POST `/api/legacy-fund/contributions`** — Add contribution (public, no auth needed)
  - Required: `amount`
  - Optional: `donor_name`, `currency`, `is_anonymous`
  - Response: Contribution object with timestamp

### 4. Updated Stats Endpoint
- **GET `/api/stats`** (requires API key) now includes:
  - `updates`, `members`, `gallery`, `chat`, `users`, `media`, `contributions`, `total_raised`

## Database Schema

### New Tables
- **users** — `id, email, password, full_name, branch, created_at`
- **media** — `id, type, title, description, date, thumbnail, src, created_at`
- **contributions** — `id, donor_name, amount, currency, is_anonymous, created_at`

## Frontend Integration
- Auth endpoints support login/register flows in `login.html`
- Media endpoints power `media.html` (display) and `admin.html` (manage)
- Legacy fund endpoints enable `legacy-fund.html` features
- API wrapper in `javascript/api.js` includes Bearer token + X-API-KEY headers

## Security Notes
- Auth endpoints **do not require API key** (public registration/login)
- Media POST and delete **require API key** (admin only)
- Contributions POST **does not require API key** (public donations)
- All endpoints have rate limiting (10-60 requests/minute)
- Input sanitization applied to all text fields

## Deployment
When deploying, ensure:
1. `DATABASE_URL` environment variable is set
2. `API_SECRET_KEY` environment variable is configured (or uses default `magoye-secret-2025`)
3. PostgreSQL tables are initialized via `init_db()`
4. CORS headers allow frontend domain

Example deployment:
```bash
export DATABASE_URL="postgresql://user:pass@host:5432/magoye"
export API_SECRET_KEY="your-secure-key-here"
python "Magoye API.py"
```
