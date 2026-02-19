# LucidDevTutorial

A personal learning sandbox for exploring [Lucid's developer platform](https://developer.lucid.co) — OAuth 2.0, REST API endpoints, and SCIM provisioning. Built hands-on while getting familiar with the APIs. This is a reference and experimentation space, not a production tool.

---

## What's here

### `oauth/`
Scripts for working through Lucid's OAuth 2.0 authorization flows and SAML-based SSO.

| File | Purpose |
|---|---|
| `oauth.py` | OAuth 2.0 authorization code flow — exchanging codes for tokens, refreshing access tokens |
| `saml.py` | SAML 2.0 SSO integration experiments |

### `rest_api/`
Scripts for calling Lucid's REST API endpoints directly.

| File | Purpose |
|---|---|
| `lucid_api.py` | General REST API calls — documents, users, and other Lucid resources |

### `scim/`
Scripts for SCIM 2.0 provisioning — managing users and groups programmatically via Lucid's SCIM endpoint.

| File | Purpose |
|---|---|
| `scim.py` | SCIM user/group provisioning, deprovisioning, and attribute mapping |

### `fixtures/`
Sample JSON payloads and test data used across scripts — example request bodies, mock API responses, and test user records. Keeps the scripts clean by separating data from logic.

---

## Setup

### Prerequisites

- Python 3.11+
- A [Lucid developer account](https://developer.lucid.co) with an application registered
- Your app's **Client ID** and **Client Secret** from the Lucid developer portal

### 1. Clone the repo

```bash
git clone https://github.com/richardudell/LucidDevTutorial.git
cd LucidDevTutorial
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate      # macOS / Linux
# venv\Scripts\activate       # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

Key packages:
| Package | Why |
|---|---|
| `requests` | HTTP calls to Lucid's REST and SCIM APIs |
| `Flask` | Lightweight server for handling OAuth redirect callbacks |
| `Flask-OAuthlib` | OAuth client helpers for the authorization code flow |
| `python-dotenv` | Loads credentials from a `.env` file so they stay out of code |
| `SQLAlchemy` + `alembic` | Optional — for persisting tokens or SCIM sync state locally |

### 4. Configure credentials

Create a `.env` file in the project root (it's gitignored — never commit this):

```bash
cp .env.example .env   # if an example exists, otherwise create from scratch
```

Populate it with your Lucid app credentials:

```env
# Lucid OAuth App Credentials
LUCID_CLIENT_ID=your_client_id_here
LUCID_CLIENT_SECRET=your_client_secret_here
LUCID_REDIRECT_URI=http://localhost:5000/callback

# Lucid API Base URLs
LUCID_AUTH_URL=https://lucid.app/oauth2/authorize
LUCID_TOKEN_URL=https://lucid.app/oauth2/token
LUCID_API_BASE_URL=https://api.lucid.co
LUCID_SCIM_BASE_URL=https://scim.lucid.co/v2

# SCIM Bearer Token (separate from OAuth — provisioned in Lucid admin settings)
LUCID_SCIM_TOKEN=your_scim_bearer_token_here
```

> **Where to find these:** Log into [lucid.app](https://lucid.app), go to **Admin > Developer Portal**, and find your registered application. The SCIM token is provisioned separately under **Admin > Account Settings > SCIM**.

### 5. Run a script

Scripts are standalone — run them individually from the project root with the virtual environment active:

```bash
python oauth/oauth.py
python rest_api/lucid_api.py
python scim/scim.py
```

If a script starts a local Flask server (OAuth callback), it will print the local URL to visit in your browser to kick off the authorization flow.

---

## Lucid API reference

- [Developer docs](https://developer.lucid.co)
- [OAuth 2.0 guide](https://developer.lucid.co/guides/#oauth-20)
- [REST API reference](https://developer.lucid.co/api/v1/)
- [SCIM provisioning guide](https://help.lucid.co/hc/en-us/articles/360059437171)

---

## Notes

- This repo has no CI, no tests, and no deployment pipeline — it's a scratch pad.
- Scripts may be incomplete or experimental. Treat them as starting points, not working implementations.
- `fixtures/` data is fake. Don't put real user data or credentials in this repo.
