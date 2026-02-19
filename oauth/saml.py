# =============================================================================
# saml.py — Lucid SAML 2.0 Service Provider Reference
# =============================================================================
#
# WHAT IS SAML?
# -------------
# SAML (Security Assertion Markup Language) is an XML-based standard for
# exchanging authentication and authorization data between two parties:
#
#   Identity Provider (IdP) — the system that authenticates the user
#                              (e.g., Okta, Azure AD, Google Workspace, Ping)
#   Service Provider (SP)   — the application the user is trying to access
#                              (in this file: your app; Lucid is the SP in prod)
#
# WHEN DOES LUCID USE SAML?
# --------------------------
# SAML is used for enterprise Single Sign-On (SSO). When a Lucid account admin
# configures SAML in the Admin Panel, users are redirected to their company's IdP
# to authenticate instead of logging in directly with Lucid credentials.
#
# You as a developer do NOT need to build Lucid's SAML integration — Lucid handles
# that internally. This file is useful if you are building your OWN app that accepts
# SAML assertions, or if you want to understand the flow for troubleshooting.
#
# =============================================================================
# SAML vs OAuth COMPARISON
# =============================================================================
#
#  Feature          | SAML 2.0                          | OAuth 2.0
#  -----------------|-----------------------------------|-------------------------
#  Protocol         | XML-based assertions              | JSON-based tokens (JWT)
#  Token format     | Signed XML Assertion              | Bearer token (opaque or JWT)
#  Flow direction   | IdP POSTs identity to your app    | Your app pulls tokens via API
#  Initiated by     | User (SP-init) or IdP (IdP-init)  | Always app-initiated
#  Use case         | Enterprise SSO via IT admin setup | Developer-controlled app auth
#  Setup process    | IdP/SP metadata XML exchange      | client_id + client_secret
#  User experience  | Transparent redirect to corp IdP  | Consent screen per app
#  Refresh          | Session-based (IdP session)        | refresh_token
#
# When to use SAML with Lucid:
#   - Your company uses an IdP (Okta, Azure AD, etc.) and wants users to SSO
#     into Lucid without a separate Lucid password.
#   - Your IT admin configures this in the Lucid Admin Panel — no code needed.
#
# When to use OAuth with Lucid:
#   - You are a developer building an integration/app that accesses Lucid APIs.
#   - You need programmatic access to Lucid documents, users, etc.
#   - See oauth.py for the full OAuth 2.0 flow.
#
# =============================================================================
# GLOSSARY
# =============================================================================
#
#  IdP (Identity Provider)  — authenticates the user and issues the SAML assertion
#                              (e.g., Okta, Azure AD, Google Workspace)
#
#  SP (Service Provider)    — your app; consumes the SAML assertion and creates
#                              a local session
#
#  Assertion                — the XML document the IdP sends to the SP after
#                              successful authentication; contains NameID +
#                              attributes + a digital signature
#
#  ACS URL                  — Assertion Consumer Service URL; the SP endpoint
#                             (POST /saml/acs in this file) where the IdP sends
#                             the SAML response. Must be registered with the IdP.
#
#  SSO URL                  — the IdP's endpoint that initiates the login flow;
#                             your app redirects users here
#
#  SLO (Single Logout)      — a protocol that allows the IdP and SP to coordinate
#                             logout so the user is logged out everywhere at once
#
#  NameID                   — the identifier for the user in the SAML assertion;
#                             typically an email address (emailAddress format)
#
#  Metadata                 — an XML document describing an IdP or SP:
#                             entity ID, certificates, supported bindings, ACS URL.
#                             IdP and SP exchange metadata to establish trust.
#
#  Attributes               — additional user info the IdP includes in the assertion
#                             (e.g., firstName, lastName, groups, department)
#
# =============================================================================

import os
from urllib.parse import urlparse

from dotenv import load_dotenv
from flask import Flask, redirect, render_template_string, request, session
from onelogin.saml2.auth import OneLogin_Saml2_Auth

load_dotenv()

app = Flask(__name__)

# Flask session secret — in production, load this from a secure secret store
app.secret_key = os.urandom(24)


# =============================================================================
# SAML SETTINGS
# =============================================================================
# python3-saml reads configuration from a dict (or from a settings.json file).
# Every key is annotated below.
#
# In a real deployment, load sensitive values (certs, URLs) from environment
# variables or a secrets manager — never hardcode them.
# =============================================================================

def get_saml_settings() -> dict:
    """
    Build the python3-saml settings dictionary from environment variables.
    See .env.example for the full list of required variables.
    """
    return {
        # ----------------------------------------------------------------
        # "strict": True means python3-saml enforces all SAML security checks:
        #   - Response must not be expired (respects NotBefore / NotOnOrAfter)
        #   - Signature must be valid
        #   - Destination must match ACS URL
        # Set to False only for local development/testing — NEVER in production.
        # ----------------------------------------------------------------
        "strict": True,

        # ----------------------------------------------------------------
        # "debug": True logs detailed SAML processing info.
        # Useful for diagnosing signature/cert errors during setup.
        # ----------------------------------------------------------------
        "debug": os.getenv("FLASK_ENV") == "development",

        # ----------------------------------------------------------------
        # "sp" block — describes YOUR application (the Service Provider)
        # ----------------------------------------------------------------
        "sp": {
            # entityId: a unique URI that identifies your app to the IdP.
            # Typically the URL of your metadata endpoint.
            # Must match exactly what you give the IdP admin.
            "entityId": os.getenv("SAML_SP_ENTITY_ID", "http://localhost:5000/saml/metadata"),

            "assertionConsumerService": {
                # url: the ACS URL where the IdP will POST the SAML response.
                # Register this exact URL with your IdP admin.
                "url": os.getenv("SAML_SP_ACS_URL", "http://localhost:5000/saml/acs"),

                # binding: almost always HTTP-POST for ACS
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },

            "singleLogoutService": {
                # url: where the IdP sends logout requests/responses
                "url": "http://localhost:5000/saml/slo",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },

            # NameIDFormat: the format you expect for the user identifier.
            # emailAddress is the most common — the NameID will be the user's email.
            # Other options:
            #   urn:oasis:names:tc:SAML:2.0:nameid-format:persistent  (opaque, stable ID)
            #   urn:oasis:names:tc:SAML:2.0:nameid-format:transient   (temporary ID per session)
            # Mismatch between SP and IdP NameIDFormat is a common setup error.
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",

            # x509cert / privateKey: SP's signing certificate and private key.
            # Used if you want to sign AuthnRequests or encrypt assertions.
            # Leave empty for basic SP-initiated flows without signing.
            "x509cert": "",
            "privateKey": "",
        },

        # ----------------------------------------------------------------
        # "idp" block — describes the Identity Provider (given to you by the IdP admin)
        # ----------------------------------------------------------------
        "idp": {
            # entityId: the IdP's unique identifier (from their metadata XML)
            "entityId": os.getenv("SAML_IDP_ENTITY_ID", "https://your-idp.example.com/saml"),

            "singleSignOnService": {
                # url: the IdP's SSO endpoint — your app redirects users here
                "url": os.getenv("SAML_IDP_SSO_URL", "https://your-idp.example.com/saml/sso"),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },

            "singleLogoutService": {
                # url: the IdP's SLO endpoint — used during coordinated logout
                "url": os.getenv("SAML_IDP_SLO_URL", "https://your-idp.example.com/saml/slo"),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },

            # x509cert: the IdP's public signing certificate (PEM format, no headers).
            # python3-saml uses this to verify the signature on every SAML response.
            # Get this from the IdP admin or their metadata XML (<ds:X509Certificate>).
            # IMPORTANT: PEM format — no "-----BEGIN CERTIFICATE-----" headers here,
            # just the raw base64 content as a single string (no line breaks).
            "x509cert": os.getenv("SAML_IDP_CERT", ""),
        },
    }


def _build_saml_auth(req) -> OneLogin_Saml2_Auth:
    """
    Construct the python3-saml Auth object from a Flask request.
    python3-saml needs the raw request details to validate signatures and
    construct proper redirect URLs.
    """
    url_data = urlparse(request.url)
    saml_request = {
        "https":        "on" if request.scheme == "https" else "off",
        "http_host":    request.host,
        "server_port":  url_data.port,
        "script_name":  request.path,
        "get_data":     request.args.copy(),
        "post_data":    request.form.copy(),
        "query_string": request.query_string,
    }
    return OneLogin_Saml2_Auth(saml_request, get_saml_settings())


# =============================================================================
# ROUTE: GET /saml/metadata
# =============================================================================
# PURPOSE: Generate and serve your SP's metadata XML.
#
# WHO NEEDS THIS: Your IdP admin. Give them this URL (or download the XML)
# so they can register your app in their IdP and establish trust.
#
# WHAT THE XML CONTAINS:
#   - entityId (who you are)
#   - ACS URL (where to send assertions)
#   - NameIDFormat preference
#   - SP signing certificate (if you use one)
#
# SETUP STEP: This is the FIRST thing to share with the IdP admin.
# =============================================================================

@app.route("/saml/metadata")
def saml_metadata():
    auth = _build_saml_auth(request)
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()

    # Validate the metadata before serving it
    errors = settings.validate_metadata(metadata)
    if errors:
        return f"Metadata validation errors: {', '.join(errors)}", 500

    return metadata, 200, {"Content-Type": "text/xml"}


# =============================================================================
# ROUTE: GET /saml/login  (SP-Initiated SSO)
# =============================================================================
# PURPOSE: Start the SAML login flow from your app's side.
#
# SP-INITIATED vs IdP-INITIATED:
#
#   SP-initiated (this route):
#     1. User clicks "Login with SSO" in YOUR app
#     2. Your app builds a SAML AuthnRequest and redirects the user to the IdP
#     3. The IdP authenticates the user, then POSTs a SAML Response to your ACS URL
#
#   IdP-initiated:
#     1. User clicks your app's icon in the Okta/Azure dashboard (the IdP)
#     2. The IdP POSTs a SAML Response directly to your ACS URL — no AuthnRequest
#     3. Your ACS route (/saml/acs) must handle both cases
#
# Most enterprise setups support both. SP-initiated is preferred because it
# lets you set a RelayState (return URL) and validate request integrity.
# =============================================================================

@app.route("/saml/login")
def saml_login():
    auth = _build_saml_auth(request)

    # login() builds the SAML AuthnRequest and returns the IdP redirect URL
    # return_to: where to send the user AFTER successful authentication
    # (passed as RelayState through the IdP and back to your ACS)
    sso_url = auth.login(return_to=request.args.get("next", "/dashboard"))

    # Redirect the user's browser to the IdP's SSO URL
    return redirect(sso_url)


# =============================================================================
# ROUTE: POST /saml/acs  (Assertion Consumer Service)
# =============================================================================
# PURPOSE: Receive and validate the SAML Response from the IdP.
#
# THIS IS THE CORE OF SAML:
#   1. User authenticates at the IdP
#   2. IdP POSTs a base64-encoded, signed XML document to this URL
#   3. python3-saml decodes + validates the XML signature
#   4. You extract the NameID (user identifier) and any attributes
#   5. You create a local session for the user
#
# SECURITY NOTE:
#   - The signature validation in step 3 is critical — it proves the assertion
#     came from your trusted IdP and was not tampered with
#   - python3-saml handles this automatically using the IdP's x509cert
#   - NEVER skip signature validation in production
#
# COMMON ERRORS AT THIS STEP:
#   - Clock skew: your server's clock differs from the IdP's by >5 minutes
#     (assertions have a short validity window — fix with NTP sync)
#   - Certificate mismatch: the cert in your settings doesn't match the IdP's
#   - NameID format mismatch: SP expects emailAddress, IdP sends persistent
#   - Destination mismatch: ACS URL in settings doesn't match what IdP has registered
# =============================================================================

@app.route("/saml/acs", methods=["POST"])
def saml_acs():
    auth = _build_saml_auth(request)

    # process_response() decodes and validates the SAML Response XML.
    # This is where signature verification happens automatically.
    auth.process_response()

    # Check for validation errors before trusting anything
    errors = auth.get_errors()
    if errors:
        # get_last_error_reason() gives a human-readable explanation
        # Common reasons: "Signature validation failed", "Response has expired",
        # "The assertion was not issued at this URL"
        reason = auth.get_last_error_reason()
        return f"SAML error: {errors}. Reason: {reason}", 400

    # is_authenticated() confirms the assertion was valid and the user authenticated
    if not auth.is_authenticated():
        return "Authentication failed — assertion was not valid", 401

    # -------------------------------------------------------------------------
    # Extract user identity from the validated assertion
    # -------------------------------------------------------------------------

    # NameID: the primary user identifier (usually email in emailAddress format)
    # This is what you use to look up or create the user in your system
    name_id = auth.get_nameid()

    # Attributes: additional user info the IdP includes in the assertion.
    # Which attributes are available depends on what the IdP is configured to send.
    # Common attribute names (vary by IdP — ask your IdP admin for the attribute map):
    #   Okta:     "firstName", "lastName", "email", "groups"
    #   Azure AD: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
    #   ADFS:     "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
    attributes = auth.get_attributes()

    # Helper to safely extract the first value from a multi-value attribute list
    def attr(key):
        return (attributes.get(key) or [None])[0]

    first_name = attr("firstName") or attr("givenName")
    last_name  = attr("lastName")  or attr("sn")
    email      = attr("email")     or name_id  # fall back to NameID if no email attribute

    # Store user info in the Flask session
    session["saml_authenticated"] = True
    session["user"] = {
        "name_id":    name_id,
        "email":      email,
        "first_name": first_name,
        "last_name":  last_name,
        "attributes": attributes,
    }

    # RelayState: the return URL set in Section 2 of the SP-initiated flow
    # (the "next" param from /saml/login). Redirect back there on success.
    relay_state = request.form.get("RelayState", "/dashboard")
    return redirect(relay_state)


# =============================================================================
# ROUTE: GET /saml/slo  (Single Logout)
# =============================================================================
# PURPOSE: Handle logout coordinated between the SP and IdP.
#
# SLO ENDING BOTH SESSIONS:
#   SLO ensures that when a user logs out, they are logged out of BOTH your app
#   AND the IdP (and potentially all other SP apps in the same SSO session).
#
# TWO DIRECTIONS:
#   1. SP-initiated SLO: user clicks "Logout" in your app → your app sends
#      a LogoutRequest to the IdP → IdP logs them out → IdP sends a
#      LogoutResponse back to this endpoint
#
#   2. IdP-initiated SLO: user logs out from another app or the IdP directly →
#      IdP sends a LogoutRequest to this endpoint → your app clears the session
#      and sends a LogoutResponse back to the IdP
#
# COMMON ISSUE: Many IdPs send the logout request to this endpoint. Your app
# must be able to process both LogoutRequests (incoming) and LogoutResponses.
# python3-saml's process_slo() handles both automatically.
# =============================================================================

@app.route("/saml/slo")
def saml_slo():
    auth = _build_saml_auth(request)

    # process_slo() handles both incoming LogoutRequests and LogoutResponses.
    # delete_session_cb: called when the IdP confirms logout — use it to clear
    # your local session data.
    def clear_session():
        session.clear()

    redirect_url = auth.process_slo(
        delete_session_cb=clear_session,
        keep_local_session=False,
    )

    errors = auth.get_errors()
    if errors:
        return f"SLO error: {errors}", 400

    # After SP-initiated SLO: redirect_url is the IdP's SLO endpoint
    # After IdP-initiated SLO: redirect_url is None (IdP handles the redirect)
    if redirect_url:
        return redirect(redirect_url)

    return redirect("/")


# =============================================================================
# SIMPLE DASHBOARD (just to show post-login state)
# =============================================================================

@app.route("/dashboard")
def dashboard():
    if not session.get("saml_authenticated"):
        return redirect("/saml/login")

    user = session["user"]
    return render_template_string(
        "<h1>Logged in via SAML</h1>"
        "<p>NameID: {{ user.name_id }}</p>"
        "<p>Email: {{ user.email }}</p>"
        "<p>Name: {{ user.first_name }} {{ user.last_name }}</p>"
        "<p><a href='/saml/slo'>Logout (SLO)</a></p>",
        user=user,
    )


# =============================================================================
# TROUBLESHOOTING REFERENCE
# =============================================================================
#
# PROBLEM: "Response has expired" or "Timing issues"
# SYMPTOM: auth.get_errors() returns ["invalid_response"]
# CAUSE:   Clock skew — your server's time differs from the IdP's by more
#          than the assertion's validity window (~5 minutes in most IdPs)
# FIX:     Sync your server's clock with NTP.
#          In python3-saml settings you can also add:
#            "security": {"clockSkew": 180}  # allow 3-minute skew
#
# PROBLEM: "Signature validation failed"
# SYMPTOM: auth.get_errors() = ["invalid_response"], reason = "Signature..."
# CAUSE:   The x509cert in your settings doesn't match the IdP's signing cert,
#          OR the cert has line breaks/whitespace in it (must be a flat string)
# FIX:     1. Re-download the IdP cert from their metadata XML
#          2. Strip the "-----BEGIN CERTIFICATE-----" headers
#          3. Join all lines into a single string (no \n in the cert value)
#          4. Paste it into SAML_IDP_CERT in your .env
#
# PROBLEM: "NameID format mismatch"
# SYMPTOM: Authentication fails or NameID is wrong format
# CAUSE:   Your SP expects emailAddress but IdP sends persistent (or vice versa)
# FIX:     1. Check what NameIDFormat the IdP is configured to send
#          2. Match the "NameIDFormat" in your SP settings to what the IdP sends
#          Common formats:
#            urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress   (email)
#            urn:oasis:names:tc:SAML:2.0:nameid-format:persistent     (opaque stable ID)
#            urn:oasis:names:tc:SAML:2.0:nameid-format:transient      (session-only ID)
#
# PROBLEM: Missing or wrong user attributes
# SYMPTOM: attributes dict is empty or doesn't have expected keys
# CAUSE:   The IdP is not configured to send those attributes, or the
#          attribute names differ between IdPs
# FIX:     1. Enable "debug": True in SAML settings
#          2. Log auth.get_attributes() after process_response()
#          3. Share the full attribute list with your IdP admin and ask them
#             to map the correct attributes in their IdP app config
#
# PROBLEM: "The assertion was not issued at this URL"
# SYMPTOM: Destination mismatch error
# CAUSE:   The ACS URL registered with the IdP doesn't match SAML_SP_ACS_URL
# FIX:     Make sure the URL in your IdP app config matches exactly:
#            http://localhost:5000/saml/acs  (no trailing slash)
#          Protocol (http vs https) and port must also match.
#
# =============================================================================

if __name__ == "__main__":
    # Run Flask in debug mode for local testing
    # Visit http://localhost:5000/saml/metadata to verify your SP metadata
    app.run(debug=True, port=5000)
