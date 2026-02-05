"""
Simple Flask site using an existing OAuth2 ID provider.
- OAuth2 authorization code flow with PKCE (S256), implemented without Authlib.
- One REST API: GET /api/access-token returns the current access token.
- Minimal HTML page with login link.
"""
import base64
import hashlib
import logging
import os
import secrets
from urllib.parse import urlencode

from dotenv import load_dotenv

load_dotenv()

import requests
from flask import Flask, redirect, render_template, request, session, jsonify, url_for

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-in-production")

OAUTH2_CLIENT_ID = os.environ["OAUTH2_CLIENT_ID"]
OAUTH2_CLIENT_SECRET = os.environ["OAUTH2_CLIENT_SECRET"]
OAUTH2_AUTH_URL = os.environ["OAUTH2_AUTH_URL"]
OAUTH2_TOKEN_URL = os.environ["OAUTH2_TOKEN_URL"]
OAUTH2_SCOPE = os.environ["OAUTH2_SCOPE"]

SESSION_KEY_STATE = "oauth2_state"
SESSION_KEY_CODE_VERIFIER = "oauth2_code_verifier"


def pkce_s256_challenge(code_verifier: str) -> str:
    """Compute code_challenge from code_verifier using S256 (RFC 7636)."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


@app.route("/")
def index():
    return render_template("index.html", logged_in="access_token" in session)


@app.route("/login")
def login():
    redirect_uri = url_for("callback", _external=True)
    state = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(32)
    code_challenge = pkce_s256_challenge(code_verifier)

    session[SESSION_KEY_STATE] = state
    session[SESSION_KEY_CODE_VERIFIER] = code_verifier

    params = {
        "response_type": "code",
        "client_id": OAUTH2_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": OAUTH2_SCOPE,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    auth_url = OAUTH2_AUTH_URL + ("&" if "?" in OAUTH2_AUTH_URL else "?") + urlencode(params)
    return redirect(auth_url)


@app.route("/callback")
def callback():
    redirect_uri = url_for("callback", _external=True)
    state_in = request.args.get("state")
    code = request.args.get("code")
    error = request.args.get("error")

    if error:
        description = request.args.get("error_description", error)
        logger.warning("OAuth2 error from provider: %s - %s", error, description)
        return jsonify({"error": error, "error_description": description}), 400

    saved_state = session.pop(SESSION_KEY_STATE, None)
    code_verifier = session.pop(SESSION_KEY_CODE_VERIFIER, None)

    if not state_in or state_in != saved_state:
        logger.warning("State mismatch or missing state")
        return jsonify({"error": "invalid_request", "detail": "State mismatch or missing"}), 400

    if not code:
        return jsonify({"error": "invalid_request", "detail": "Missing authorization code"}), 400

    if not code_verifier:
        return jsonify({"error": "invalid_request", "detail": "Missing code_verifier (session expired?)"}), 400

    # Exchange code for token
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": OAUTH2_CLIENT_ID,
        "client_secret": OAUTH2_CLIENT_SECRET,
        "code_verifier": code_verifier,
    }

    try:
        resp = requests.post(
            OAUTH2_TOKEN_URL,
            data=token_data,
            headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )
        resp.raise_for_status()
        token = resp.json()
    except requests.RequestException as e:
        logger.exception("Token request failed")
        detail = str(e)
        if hasattr(e, "response") and e.response is not None and e.response.text:
            detail = e.response.text
        return jsonify({"error": "Token request failed", "detail": detail}), 400

    session["access_token"] = token.get("access_token")
    session["id_token"] = token.get("id_token")
    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.pop("access_token", None)
    session.pop("id_token", None)
    return redirect(url_for("index"))


@app.route("/api/access-token", methods=["GET"])
def api_access_token():
    """REST API: returns the current access token if the user is logged in."""
    if "access_token" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    return jsonify({"access_token": session["access_token"]})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
