import logging
import secrets
import string
import urllib.parse

import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
import requests
from ckan import model
from ckan.common import config, g
from ckan.lib import base
from ckanext.keycloak_auth.db.jwt_token import Base, UserSession
from ckanext.keycloak_auth.keycloak import KeycloakConnect
from ckanext.keycloak_auth.views.keycloak_auth import keycloak_auth
from ckanext.keycloak_auth.views.user import user
from sqlalchemy import engine_from_config
from flask import request
from functools import lru_cache
import aiohttp
from sqlalchemy.orm import joinedload

import asyncio


from .keycloak import KeycloakConnect

PUBLIC_KEYS_CACHE = {}
session_cache = {}

log = logging.getLogger(__name__)


def _get_user_by_email(email):
    user_obj = model.User.by_email(email)
    if user_obj:
        user_obj = user_obj[0]

    if user_obj and user_obj.is_deleted():
        user_obj.activate()
        user_obj.commit()
        log.info(f"User {user_obj.name} reactivated")
    return user_obj if user_obj else None

def process_user(email, full_name, username, roles):
    """
    Check if a user exists for the current login, if not register one
    Returns the user name
    """
    user_dict = _get_user_by_email(email)

    if user_dict:
        log.info(user_dict)

        # Track if any change was made
        changes_made = False

        # Initialize plugin_extras and keycloak_plugin with defaults if missing
        if user_dict.plugin_extras is None:
            user_dict.plugin_extras = {}
            changes_made = True
        
        if 'keycloak_plugin' not in user_dict.plugin_extras:
            user_dict.plugin_extras['keycloak_plugin'] = {}
            changes_made = True

        # Check if roles_extra needs to be updated
        if user_dict.plugin_extras['keycloak_plugin'].get('roles_extra') != roles:
            user_dict.plugin_extras['keycloak_plugin']['roles_extra'] = roles
            changes_made = True

        if user_dict.fullname != full_name:
            user_dict.fullname = full_name
            changes_made = True
        
        if user_dict.email != email:
            user_dict.email = email
            changes_made = True

        # Save and commit only if any changes were made
        if changes_made:
            user_dict.save()
            user_dict.commit()

        return user_dict.name

    
    password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(10))
    
    # This is the first time this user has logged in, register a user
    user_dict = {
        "name": username,
        "fullname": full_name,
        "email": email,
        "password": password,
        "plugin_extras": {
            "keycloak_plugin": {
                "roles_extra": roles,
            }
        },
    }

    context = {
        "ignore_auth": True,
        "user": username,
    }

    try:
        user_dict = toolkit.get_action("user_create")(context, user_dict)
    except toolkit.ValidationError as e:
        error_message = e.error_summary or e.message or e.error_dict
        base.abort(400, error_message)

    return user_dict["name"]

class KeycloakAuthPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurable)
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IAuthenticator, inherit=True)
    plugins.implements(plugins.IActions)

    keycloak_client_server = None

    # IActions
    def get_actions(self):
        return {
            "get_user_session": get_user_session_action,
        }

    # IConfigurer
    def configure(self, config):
        missing_param = "{0} is not configured. Please update your .ini file."

        server_url = config.get("ckanext.keycloak.server_url")
        if not server_url:
            raise RuntimeError(missing_param.format("ckanext.keycloak.server_url"))

        realm = config.get("ckanext.keycloak.realm")
        if not realm:
            raise RuntimeError(missing_param.format("ckanext.keycloak.realm"))

        client_id = config.get("ckanext.keycloak.client_id")
        if not client_id:
            raise RuntimeError(missing_param.format("ckanext.keycloak.client_id"))

        frontend_client_id = config.get("ckanext.keycloak.frontend_client_id")
        if not frontend_client_id:
            raise RuntimeError(
                missing_param.format("ckanext.keycloak.frontend_client_id")
            )

        admin_group = config.get("ckanext.keycloak.admin_group")
        if not admin_group:
            raise RuntimeError(missing_param.format("ckanext.keycloak.admin_group"))

        client_secret_key = config.get("ckanext.keycloak.client_secret_key")
        if not client_secret_key:
            raise RuntimeError(
                missing_param.format("ckanext.keycloak.client_secret_key")
            )

        ckan_url = config.get("ckanext.keycloak.ckan_url")
        if not ckan_url:
            raise RuntimeError(missing_param.format("ckanext.keycloak.ckan_url"))

        self.keycloak_client_server = KeycloakConnect(
            server_url=server_url,
            realm_name=realm,
            client_id=client_id,
            client_secret_key=client_secret_key,
        )

        self.keycloak_client_server.userslist()

    # IConfigurer
    def update_config(self, config_):
        toolkit.add_template_directory(config_, "templates")
        toolkit.add_public_directory(config_, "public")
        toolkit.add_resource("fanstatic", "keycloak_auth")

        engine = engine_from_config(config_, "sqlalchemy.")
        Base.metadata.create_all(engine)

    # IBlueprint
    def get_blueprint(self):
        return [keycloak_auth, user]

    # IAuthenticator
    def identify(self):
        if request.path.startswith("/webassets/") or request.path.startswith("/base/"):
            return None

        session_id = toolkit.request.cookies.get("session_id")
        if not session_id:
            return None

        # Use cached session if available
        user_session = session_cache.get(session_id) or get_user_session(session_id)
        if not user_session:
            return None

        # Cache the session
        session_cache[session_id] = user_session
        
        # Reattach the detached instance to the active session
        user_session = reattach_session(user_session)

        if user_session and user_session.jwttokens:
            access_token = user_session.jwttokens.access_token
            refresh_token = user_session.jwttokens.refresh_token

        if not access_token or not refresh_token:
            return delete_session(user_session)

        try:
            access_token_payload = decode_jwt(access_token)
        except ExpiredSignatureError as e:
            log.info("Signature expired:" + str(e))

            access_token, refresh_token = self.refresh_auth_tokens(
                refresh_token, user_session
            )

            if not access_token or not refresh_token:
                return delete_session(user_session)

            try:
                access_token_payload = decode_jwt(access_token)
            except InvalidTokenError as e:
                log.error("Failed to decode JWT token: " + str(e))
                return delete_session(user_session)
        except InvalidTokenError as e:
            log.error("Failed to decode JWT token: " + str(e))
            return delete_session(user_session)

        g.user = process_user(
            access_token_payload["email"],
            access_token_payload["name"],
            access_token_payload["preferred_username"],
            access_token_payload["realm_access"]["roles"],
        )

        g.userobj = model.User.by_name(g.user)

        return None

    def refresh_auth_tokens(self, refresh_token, user_session):
        new_access_token, new_refresh_token = get_jwt_tokens(refresh_token)
        if new_access_token and new_refresh_token:
            user_session.jwttokens.access_token = new_access_token
            user_session.jwttokens.refresh_token = new_refresh_token
            try:
                model.Session.add(user_session)
                model.Session.commit()
                return new_access_token, new_refresh_token
            except Exception as e:
                log.error(f"Refresh auth tokens error: {e}")

                model.Session.delete(user_session)
                model.Session.commit()
                return None, None

        return None, None

    def logout(self):
        server_url = config.get("ckanext.keycloak.server_url")
        realm = config.get("ckanext.keycloak.realm")
        ckan_url = toolkit.config.get("ckanext.keycloak.ckan_url")

        keycloak_logout_url = (
            f"{server_url}/realms/{realm}/protocol/openid-connect/logout"
        )
        redirect_uri = f"{ckan_url}"

        params = {"redirect_uri": redirect_uri}

        logout_url = f"{keycloak_logout_url}?{urllib.parse.urlencode(params)}"
        resp = toolkit.redirect_to(logout_url)
        resp.delete_cookie("session_id")

        return resp

def get_jwt_tokens(refresh_token):
    server_url = config.get("ckanext.keycloak.server_url")
    realm = config.get("ckanext.keycloak.realm")

    token_url = f"{server_url}/realms/{realm}/protocol/openid-connect/token"
    client_id = config.get("ckanext.keycloak.frontend_client_id")

    data = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh_token,
    }

    response = requests.post(token_url, data=data, timeout=10)

    if response.status_code == 200:
        tokens = response.json()
        new_access_token = tokens["access_token"]
        new_refresh_token = tokens["refresh_token"]

        return new_access_token, new_refresh_token
    else:
        print(
            f"Failed to refresh access token: {response.status_code} - {response.text}"
        )
        return None, None

async def fetch_public_key(kid):
    server_url = config.get("ckanext.keycloak.server_url")
    realm = config.get("ckanext.keycloak.realm")

    jwks_url = f"{server_url}/realms/{realm}/protocol/openid-connect/certs"
    async with aiohttp.ClientSession() as session:
        try:
            # Fetch the JWKS
            async with session.get(jwks_url) as response:
                response.raise_for_status()
                jwks = await response.json()

                # Search for the public key by 'kid'
                for key in jwks.get("keys", []):
                    if key["kid"] == kid:
                        # Cache this key for future validations
                        PUBLIC_KEYS_CACHE[kid] = key
                        return key
        except aiohttp.ClientError as e:
            log.error(f"Error fetching public keys: {e}")
    return None

def decode_jwt(token):
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get("kid")

    if not kid:
        raise InvalidTokenError("KID not found in JWT")

    # Attempt to retrieve the public key from cache
    public_key = PUBLIC_KEYS_CACHE.get(kid)

    # If the key is not in the cache, fetch it asynchronously
    if not public_key:
        try:
            # Try to get the current event loop
            loop = asyncio.get_event_loop()
        except RuntimeError:  # If there is no event loop in the current thread
            loop = asyncio.new_event_loop()  # Create a new event loop
            asyncio.set_event_loop(loop)

        if loop.is_running():
            # If the event loop is already running, schedule the task
            public_key = asyncio.ensure_future(fetch_public_key(kid))
        else:
            # Otherwise, run the event loop
            public_key = loop.run_until_complete(fetch_public_key(kid))

        if not public_key:
            raise InvalidTokenError("Public key for KID not found")

    # Construct the RSA public key
    rsa_public_key = jwt.algorithms.RSAAlgorithm.from_jwk(public_key)

    decoded = jwt.decode(
        token, rsa_public_key, algorithms=["RS256"], audience="account"
    )
    return decoded

def reattach_session(user_session):
    # Reattach the session to the current SQLAlchemy session
    current_session = model.Session.object_session(user_session)
    if not current_session:
        user_session = model.Session.merge(user_session)
    return user_session


def delete_session(user_session):
    response = toolkit.redirect_to("home.index")
    response.delete_cookie("session_id")

    # Remove from cache
    session_cache.pop(user_session.session_id, None)

    model.Session.delete(user_session)
    model.Session.commit()

    return response

@lru_cache(maxsize=100)
def get_user_session(session_id):
    try:
        return (
            model.Session.query(UserSession)
            .options(joinedload(UserSession.jwttokens))
            .filter_by(session_id=session_id)
            .first()
        )
    except Exception as e:
        log.error(f"Get user session error: {e}")
        return None

def get_user_session_action(context, data_dict):
    session = get_user_session(data_dict["session_id"])
    return {"user_session": session}