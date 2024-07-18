import base64
import logging
import os

import ckan.model as model
import ckan.plugins.toolkit as toolkit
import ckanext.keycloak_auth.db.jwt_token as db
import requests
from ckan.common import config, request
from flask import Blueprint
from six.moves.urllib.parse import urlparse

log = logging.getLogger(__name__)
keycloak_auth = Blueprint("keycloak_auth", __name__)

def generate_secure_session_id():
    return base64.urlsafe_b64encode(os.urandom(32)).decode()

def auth():
    """The location where auth redirect sent with a HTTP POST."""
    auth_code = request.form["code"]

    access_token, refresh_token = exchange_auth_code_for_token(auth_code)

    ckan_url = config.get("ckanext.keycloak.ckan_url")
    resp = toolkit.redirect_to(ckan_url)
    
    # Store the tokens in the database
    new_session_id = generate_secure_session_id()
    new_user_session = db.UserSession(session_id=new_session_id)
    model.Session.add(new_user_session)
    model.Session.commit()
    
    new_tokens = db.JWTToken(access_token=access_token, refresh_token=refresh_token, user_session=new_user_session)
    model.Session.add(new_tokens)
    model.Session.commit()
    
    resp.set_cookie('session_id', new_session_id, httponly=True, secure=False)

    return resp


def keycloak_login():
    """Redirects the user to keycloak identity provider for authentication"""
    server_url = config.get("ckanext.keycloak.server_url")
    realm = config.get("ckanext.keycloak.realm")
    frontend_client_id = config.get("ckanext.keycloak.frontend_client_id")
    ckan_url = config.get("ckanext.keycloak.ckan_url")

    redirect_url = (
        server_url
        + "/realms/"
        + realm
        + "/protocol/openid-connect"
        + "/auth?client_id="
        + frontend_client_id
        + "&redirect_uri="
        + ckan_url
        + "authenticate&response_mode=form_post&response_type=code&scope=openid&nonce=0d45c2fe-591b-4d34-8725-444d1218cb0c"
    )
    

    return toolkit.redirect_to(redirect_url)


def exchange_auth_code_for_token(auth_code):
    server_url = config.get("ckanext.keycloak.server_url")
    realm = config.get("ckanext.keycloak.realm")
    ckan_url = config.get("ckanext.keycloak.ckan_url")
    frontend_client_id = config.get("ckanext.keycloak.frontend_client_id")

    """Exchange authorization code for access token"""
    token_endpoint = f"{server_url}/realms/{realm}/protocol/openid-connect/token"
    payload = {
        "grant_type": "authorization_code",
        "client_id": frontend_client_id,
        "code": auth_code,
        "redirect_uri": ckan_url + "authenticate",
    }

    response = requests.post(token_endpoint, data=payload)
    response_data = response.json()
    return response_data["access_token"], response_data.get("refresh_token")


def keycloak_change_password():
    """Redirects the user to keycloak identity provider for password change"""
    server_url = config.get("ckanext.keycloak.server_url")
    realm = config.get("ckanext.keycloak.realm")
    frontend_client_id = config.get("ckanext.keycloak.frontend_client_id")

    redirect_url = (
        server_url
        + "/realms/"
        + realm
        + "/login-actions/reset-credentials"
        + "?client_id="
        + frontend_client_id
    )

    return toolkit.redirect_to(redirect_url)


def jupyterhub_login():
    """Redirects the user to jupyterhub"""
    ckan_url = config.get("ckanext.keycloak.ckan_url")
    parsed_url = urlparse(ckan_url)
    host = parsed_url.netloc.split(":")[0]
    jupyterhub_host = "jupyterhub." + host

    redirect_url = "https://" + jupyterhub_host + "/"

    return toolkit.redirect_to(redirect_url)


auth_endpoint = config.get("ckanext.keycloak_auth.auth_endpoint", "/authenticate")
keycloak_auth.add_url_rule(auth_endpoint, view_func=auth, methods=["GET", "POST"])
keycloak_auth.add_url_rule("/user/keycloak_login", view_func=keycloak_login)
keycloak_auth.add_url_rule("/user/jupyterhub_login", view_func=jupyterhub_login)
keycloak_auth.add_url_rule(
    "/user/keycloak_change_password", view_func=keycloak_change_password
)
