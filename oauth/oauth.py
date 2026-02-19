"""
oauth.py — Lucid OAuth 2.0 Reference Script
============================================

PURPOSE
-------
This file is a learning reference for the Lucid OAuth 2.0 Authorization Code Flow.
It is designed to be read section-by-section (or run in a Python REPL) as a
troubleshooting guide and onboarding resource — not a production application.

AUTHORIZATION CODE FLOW OVERVIEW
---------------------------------
1. Your app redirects the user to Lucid's authorization URL.
2. The user logs in and grants (or denies) your requested scopes.
3. Lucid redirects back to your redirect_uri with a short-lived ?code=<code>.
4. Your app POSTs that code to the token endpoint to exchange it for tokens.
5. Your app uses the access_token to call Lucid APIs on the user's behalf.
6. When the access_token expires (1 hour), use the refresh_token to get a new one.

USER TOKEN vs. ACCOUNT TOKEN
------------------------------
Lucid has two distinct token types — they are NOT interchangeable:

  User token    — Acts on behalf of a single user.
                  Required for: user.profile, folder, document scopes.
                  Authorization URL: https://lucid.app/oauth2/authorize

  Account token — Acts on behalf of the entire organization.
                  Required for: account.user, account.user:readonly.
                  Authorization URL: https://lucid.app/oauth2/authorizeAccount

  Key rule: You cannot mix user-only and account-only scopes in the same request.
  Doing so will return an `invalid_scopes` error.

LEARNING NOTE
-------------
Paste real values where you see "YOUR_..." or read them from a .env file.
Each section below maps to one phase of the flow above.
"""

import json
import os
import time
import urllib.parse

import requests
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Setup — load credentials from .env
# ---------------------------------------------------------------------------

load_dotenv()

CLIENT_ID     = os.getenv("LUCID_CLIENT_ID")
CLIENT_SECRET = os.getenv("LUCID_CLIENT_SECRET")
REDIRECT_URI  = os.getenv("LUCID_REDIRECT_URI", "http://localhost:5000/callback")

# Authorization endpoints
USER_AUTH_URL    = os.getenv("LUCID_USER_AUTH_URL",    "https://lucid.app/oauth2/authorize")
ACCOUNT_AUTH_URL = os.getenv("LUCID_ACCOUNT_AUTH_URL", "https://lucid.app/oauth2/authorizeAccount")

# Token endpoint — same URL for both create and refresh
TOKEN_URL = os.getenv("LUCID_TOKEN_URL", "https://api.lucid.co/oauth2/token")

# API base URL
API_BASE = os.getenv("LUCID_API_BASE_URL", "https://api.lucid.co")

# File used to persist tokens between runs (mirrors the pattern in Lucid's sample scripts)
TOKEN_FILE = "lucid_tokens.json"


# ===========================================================================
# SECTION 1 — Build the Authorization URL
# ===========================================================================
# The user must visit this URL in their browser to grant your app access.
# Lucid will show a consent screen listing the scopes you requested, then
# redirect back to your redirect_uri with a short-lived authorization code.
# ===========================================================================

def section1_build_auth_urls():
    # -----------------------------------------------------------------------
    # USER TOKEN authorization URL
    # Use this when you need to act on behalf of a specific user
    # (e.g., read their profile, manage their documents).
    # -----------------------------------------------------------------------
    user_params = {
        # client_id: your app's unique identifier from the Lucid Developer Portal
        "client_id": CLIENT_ID,

        # response_type: always "code" for the Authorization Code Flow
        "response_type": "code",

        # redirect_uri: where Lucid sends the user after they authorize.
        # Must exactly match what you registered in the Developer Portal.
        "redirect_uri": REDIRECT_URI,

        # scope: space-separated list of permissions you're requesting.
        # user.profile — read basic info about the authorizing user
        # offline_access — enables refresh tokens (required to get a refresh_token back)
        # lucidchart.document.content:readonly — view/download documents
        # NOTE: Do NOT mix account.user scopes here — those require an Account token.
        "scope": "user.profile offline_access lucidchart.document.content:readonly",

        # state: an opaque value you generate and verify on return.
        # Critical for CSRF protection — reject any callback where state doesn't match.
        "state": "REPLACE_WITH_A_RANDOM_CSRF_TOKEN",
    }

    user_auth_url = USER_AUTH_URL + "?" + urllib.parse.urlencode(user_params)
    print("=== SECTION 1: Authorization URLs ===\n")
    print("USER TOKEN — paste this URL into your browser:")
    print(user_auth_url)
    print()

    # -----------------------------------------------------------------------
    # ACCOUNT TOKEN authorization URL
    # Use this when you need org-level actions (list all users, manage licenses).
    # The consent screen here is shown to an account admin, not an end user.
    # The token represents the organization, not an individual.
    # -----------------------------------------------------------------------
    account_params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,

        # account.user:readonly — list users in the org (Account token only)
        # account.user — create/edit/delete users (Account token only)
        # offline_access — still required here to get a refresh_token
        "scope": "account.user:readonly offline_access",

        "state": "REPLACE_WITH_A_RANDOM_CSRF_TOKEN",
    }

    account_auth_url = ACCOUNT_AUTH_URL + "?" + urllib.parse.urlencode(account_params)
    print("ACCOUNT TOKEN — paste this URL into your browser (must be authorized by an admin):")
    print(account_auth_url)
    print()
    print("After visiting either URL, copy the 'code' query param from the redirect URL.")
    print("You have ~5 minutes before the code expires.\n")


# ===========================================================================
# SECTION 2 — Exchange the Authorization Code for Tokens
# ===========================================================================
# After the user authorizes, Lucid redirects to your redirect_uri with:
#   ?code=<short-lived-code>&state=<your-state-value>
#
# Verify the state matches what you sent, then immediately POST the code
# to the token endpoint. The code expires in ~5 minutes — don't delay.
# ===========================================================================

def section2_exchange_code(authorization_code: str):
    print("=== SECTION 2: Exchange Code for Tokens ===\n")

    response = requests.post(
        TOKEN_URL,
        data={
            # grant_type: tells Lucid this is a code exchange (not a refresh)
            "grant_type": "authorization_code",

            # code: the short-lived code from the redirect URL's ?code= param
            "code": authorization_code,

            # redirect_uri: must match exactly what was used in Section 1
            "redirect_uri": REDIRECT_URI,

            # client_id / client_secret: your app's credentials
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        headers={
            # The token endpoint accepts application/x-www-form-urlencoded
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )

    if response.status_code != 200:
        print(f"ERROR {response.status_code}: {response.text}")
        # Common errors:
        #   invalid_client — your client_id/secret is wrong, OR the admin
        #                     disabled the OAuth client in the Lucid Admin Panel
        #   invalid_grant  — the code already expired or was already used
        return None

    tokens = response.json()

    # -----------------------------------------------------------------------
    # Token response fields:
    #
    #   access_token  — the bearer token you use in API calls (lasts 1 hour)
    #   refresh_token — long-lived token used to get new access_tokens
    #                   (present only if you requested offline_access scope)
    #   token_type    — always "Bearer"
    #   expires_in    — seconds until access_token expires (3600 = 1 hour)
    #   expires       — Unix timestamp when access_token expires
    #   user_id       — the Lucid user ID of the authorizing user (User tokens only)
    #   scopes        — the scopes that were actually granted
    # -----------------------------------------------------------------------
    print("Token response:")
    print(json.dumps(tokens, indent=2))
    print()

    # Save tokens to a file so Section 3 can pick them up
    _save_tokens(tokens)
    print(f"Tokens saved to {TOKEN_FILE}\n")

    return tokens


# ===========================================================================
# SECTION 3 — Refresh an Expired Access Token
# ===========================================================================
# Access tokens expire after 3600 seconds (1 hour).
# Use the refresh_token to get a new access_token without re-authorizing.
#
# IMPORTANT: Refreshing invalidates BOTH the old access_token and the old
# refresh_token. Always save the NEW tokens returned in the response.
#
# Refresh tokens themselves expire after 180 days of non-use.
# The offline_access scope must have been included in Section 1.
# ===========================================================================

def section3_refresh_token():
    print("=== SECTION 3: Refresh an Expired Access Token ===\n")

    tokens = _load_tokens()
    if not tokens:
        print(f"No tokens found in {TOKEN_FILE}. Run section2 first.\n")
        return None

    # Check if the access_token is still valid (with a 60-second buffer)
    expires = tokens.get("expires", 0)
    if time.time() < expires - 60:
        remaining = int(expires - time.time())
        print(f"Access token is still valid for {remaining} seconds. No refresh needed.\n")
        return tokens

    print("Access token expired — refreshing...\n")

    response = requests.post(
        TOKEN_URL,
        data={
            # grant_type: tells Lucid this is a token refresh
            "grant_type": "refresh_token",

            # refresh_token: the long-lived token from the original exchange
            "refresh_token": tokens["refresh_token"],

            # client credentials are still required
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )

    if response.status_code != 200:
        print(f"ERROR {response.status_code}: {response.text}")
        # invalid_grant here usually means the refresh token expired (180 days
        # of non-use) or was already used. Re-authorize from Section 1.
        return None

    new_tokens = response.json()
    print("New tokens received:")
    print(f"  access_token:  {new_tokens.get('access_token', '')[:40]}...")
    print(f"  refresh_token: {new_tokens.get('refresh_token', '')[:40]}...")
    print()

    # CRITICAL: save the new tokens — the old ones are now invalid
    _save_tokens(new_tokens)
    print(f"New tokens saved to {TOKEN_FILE}\n")

    return new_tokens


# ===========================================================================
# SECTION 4 — Make an Authenticated API Call
# ===========================================================================
# Every Lucid API call requires TWO headers:
#   Authorization: Bearer <access_token>
#   Lucid-Api-Version: 1
#
# Missing either header will result in a 401 or 400 error.
# "Missing Lucid-Api-Version" is the most common mistake for new integrations.
# ===========================================================================

def section4_api_calls():
    print("=== SECTION 4: Authenticated API Calls ===\n")

    tokens = _load_tokens()
    if not tokens:
        print(f"No tokens found in {TOKEN_FILE}. Run section2 first.\n")
        return

    access_token = tokens["access_token"]

    # Required headers for ALL Lucid API calls
    headers = {
        # Authorization: the bearer token from Section 2 or 3
        "Authorization": f"Bearer {access_token}",

        # Lucid-Api-Version: must be present on every request — no exceptions
        # Lucid uses this for API versioning and rejects calls that omit it
        "Lucid-Api-Version": "1",
    }

    # -----------------------------------------------------------------------
    # Example A: Get the current user's profile
    # Requires: User token with user.profile scope
    # This will NOT work with an Account token.
    # -----------------------------------------------------------------------
    print("GET /users/me/profile  (User token + user.profile scope)")
    response = requests.get(f"{API_BASE}/users/me/profile", headers=headers)
    print(f"  Status: {response.status_code}")
    if response.ok:
        print(f"  Response: {json.dumps(response.json(), indent=4)}")
    else:
        print(f"  Error: {response.text}")
    print()

    # -----------------------------------------------------------------------
    # Example B: Get a specific user by ID
    # Requires: Account token with account.user:readonly scope
    # This will NOT work with a User token — returns 403.
    # Replace USER_ID with a real Lucid user ID.
    # -----------------------------------------------------------------------
    user_id = "REPLACE_WITH_A_REAL_USER_ID"
    print(f"GET /users/{user_id}  (Account token + account.user:readonly scope)")
    response = requests.get(f"{API_BASE}/users/{user_id}", headers=headers)
    print(f"  Status: {response.status_code}")
    if response.ok:
        print(f"  Response: {json.dumps(response.json(), indent=4)}")
    else:
        print(f"  Error: {response.text}")
    print()

    # -----------------------------------------------------------------------
    # Example C: List all users in the account
    # Requires: Account token with account.user:readonly scope
    # -----------------------------------------------------------------------
    print("GET /users  (Account token + account.user:readonly scope)")
    response = requests.get(f"{API_BASE}/users", headers=headers)
    print(f"  Status: {response.status_code}")
    if response.ok:
        print(f"  Response: {json.dumps(response.json(), indent=4)}")
    else:
        print(f"  Error: {response.text}")
    print()


# ===========================================================================
# SECTION 5 — Token Introspection and Revocation
# ===========================================================================
# These endpoints let you inspect or invalidate tokens without making a
# full API call. Both use application/x-www-form-urlencoded POST bodies.
# ===========================================================================

def section5_introspect_and_revoke():
    print("=== SECTION 5: Token Introspection and Revocation ===\n")

    tokens = _load_tokens()
    if not tokens:
        print(f"No tokens found in {TOKEN_FILE}. Run section2 first.\n")
        return

    access_token = tokens["access_token"]

    # -----------------------------------------------------------------------
    # Introspect a token
    # Use this to check if a token is still active, what scopes it has, and
    # when it expires — without making a full business API call.
    # Helpful for debugging "why is this call returning 401?"
    # -----------------------------------------------------------------------
    print("POST /oauth2/token/introspect")
    introspect_response = requests.post(
        f"{API_BASE}/oauth2/token/introspect",
        data={
            # token: the access_token or refresh_token you want to inspect
            "token": access_token,

            # client credentials required for introspection
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    print(f"  Status: {introspect_response.status_code}")
    print(f"  Response: {json.dumps(introspect_response.json(), indent=4)}")
    print()

    # -----------------------------------------------------------------------
    # Revoke a token
    # Revoking either the access_token OR the refresh_token invalidates the
    # ENTIRE grant — both tokens become invalid immediately.
    # Use this on user logout or when rotating credentials.
    # -----------------------------------------------------------------------
    print("POST /oauth2/token/revoke")
    revoke_response = requests.post(
        f"{API_BASE}/oauth2/token/revoke",
        data={
            "token": access_token,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    print(f"  Status: {revoke_response.status_code}")
    # A 200 response with an empty body means success
    print(f"  Token revoked successfully: {revoke_response.status_code == 200}")
    print()


# ===========================================================================
# Helper utilities
# ===========================================================================

def _save_tokens(tokens: dict):
    """Persist token dict to a local JSON file (mirrors Lucid's sample script pattern)."""
    with open(TOKEN_FILE, "w") as f:
        json.dump(tokens, f, indent=2)


def _load_tokens() -> dict | None:
    """Load tokens from the local JSON file, or return None if not found."""
    if not os.path.exists(TOKEN_FILE):
        return None
    with open(TOKEN_FILE) as f:
        return json.load(f)


# ===========================================================================
# MAIN — runs all sections in order for demonstration
# ===========================================================================

if __name__ == "__main__":
    print("Lucid OAuth 2.0 Reference Script")
    print("=" * 50)
    print()

    # SECTION 1: Print both authorization URLs
    section1_build_auth_urls()

    # SECTION 2: Uncomment and paste a real code to exchange it for tokens
    # authorization_code = "PASTE_CODE_FROM_REDIRECT_URL_HERE"
    # section2_exchange_code(authorization_code)

    # SECTION 3: Refresh the token if it's expired
    # section3_refresh_token()

    # SECTION 4: Make authenticated API calls
    # section4_api_calls()

    # SECTION 5: Introspect or revoke a token
    # section5_introspect_and_revoke()


# ===========================================================================
# FULL FLOW SUMMARY (plain English)
# ===========================================================================
#
#  1. Register your app in the Lucid Developer Portal to get client_id + secret.
#  2. Decide if you need a User token or Account token (they are different flows).
#  3. Build the authorization URL (Section 1) and send the user there.
#  4. The user grants access; Lucid redirects to your redirect_uri with ?code=...
#  5. Verify the state param matches (CSRF check), then exchange the code (Section 2).
#  6. Store access_token + refresh_token somewhere safe (never in the browser).
#  7. Include Authorization: Bearer <token> + Lucid-Api-Version: 1 on every call.
#  8. When the access_token expires (1 hour), refresh it (Section 3).
#  9. Save the NEW tokens — the old ones are invalidated after refresh.
# 10. On logout, revoke the token (Section 5) to invalidate the entire grant.
#
# ===========================================================================
# COMMON MISTAKES
# ===========================================================================
#
#  - invalid_scopes error: mixing user-only scopes (user.profile) with
#    account-only scopes (account.user) in the same authorization request.
#
#  - 401 on API calls: forgetting the Lucid-Api-Version: 1 header.
#    Both Authorization and Lucid-Api-Version are required on EVERY call.
#
#  - invalid_grant on code exchange: the authorization code expired (5 minutes)
#    or was already used. Restart from Section 1.
#
#  - Stale tokens after refresh: not saving the new access_token + refresh_token.
#    The old tokens are immediately invalid — always overwrite your stored tokens.
#
#  - invalid_client: the admin may have disabled the OAuth client in the
#    Lucid Admin Panel. Check with your Lucid account administrator.
#
# ===========================================================================
