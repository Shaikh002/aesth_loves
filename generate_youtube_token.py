#!/usr/bin/env python3
# generate_youtube_token_v2.py
import json, base64, sys, os
from pathlib import Path
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

CLIENT_SECRETS = Path("client_secrets.json")
TOKEN_FILE = Path("token.json")
SCOPES = [
    "https://www.googleapis.com/auth/youtube.upload",
    "https://www.googleapis.com/auth/youtube.force-ssl"
]

REVOKE_HELP_URL = "https://myaccount.google.com/permissions"  # where to remove old app access

def fail(msg):
    print(f"❌ {msg}")
    print(f"➡️  If you keep getting no refresh_token: revoke old access here: {REVOKE_HELP_URL}")
    print("   (Find your OAuth app under 'Third-party apps with account access', remove it, then re-run.)")
    sys.exit(1)

def ensure_client_secrets():
    if not CLIENT_SECRETS.exists():
        fail("client_secrets.json not found. Create a **Desktop App** OAuth client and save it here.")

def interactive_consent_new_creds():
    # Force a brand-new consent so Google returns a refresh_token
    flow = InstalledAppFlow.from_client_secrets_file(
        str(CLIENT_SECRETS), SCOPES
    )
    # access_type=offline + prompt=consent are the keys
    return flow.run_local_server(
        port=0,
        access_type="offline",
        prompt="consent",            # Force showing the consent screen
        authorization_prompt_message="Opening Google sign-in to create a fresh token (with refresh_token)...",
        success_message="✅ Authorization complete. You can close this tab."
    )

def verify_refresh_works(creds: Credentials):
    """
    Ensure we actually can refresh: force a refresh call and check access token changes/exists.
    """
    if not getattr(creds, "refresh_token", None):
        fail("Google did not return a refresh_token in the response.")

    try:
        # Force a refresh to prove CI will work headlessly
        creds.refresh(Request())
    except Exception as e:
        fail(f"Refresh attempt failed: {e}")

def test_youtube(creds: Credentials):
    yt = build("youtube", "v3", credentials=creds)
    me = yt.channels().list(part="id,snippet", mine=True).execute()
    ch = me["items"][0]
    print(f"🔗 Auth OK for channel: {ch['snippet']['title']} (id={ch['id']})")

def save_token(creds: Credentials):
    TOKEN_FILE.write_text(creds.to_json(), encoding="utf-8")
    print(f"💾 token.json saved → {TOKEN_FILE.resolve()}")

def print_base64_token():
    b64 = base64.b64encode(TOKEN_FILE.read_bytes()).decode("utf-8")
    print("\n──────── COPY BELOW INTO YT_TOKEN_JSON_B64 ────────")
    print(b64)
    print("──────── END ────────\n")

def main():
    ensure_client_secrets()

    # Optional safety: start clean so Google shows consent again
    if TOKEN_FILE.exists():
        print("🧹 Removing old token.json to force a fresh consent…")
        try:
            TOKEN_FILE.unlink()
        except Exception:
            pass

    print("🔑 Opening browser for Google OAuth (Desktop App)…")
    creds = interactive_consent_new_creds()

    # Must have refresh_token for CI
    verify_refresh_works(creds)

    # Save and test a simple YouTube call
    save_token(creds)
    test_youtube(creds)

    # Print base64 for GitHub Actions secret
    print_base64_token()
    print("✅ Done. Use this base64 as YT_TOKEN_JSON_B64 in GitHub Secrets.")

if __name__ == "__main__":
    main()
