import logging
import copy
import string
import secrets

from flask import Blueprint
from six import text_type
from six.moves.urllib.parse import urlparse

import ckan.plugins.toolkit as toolkit
import ckan.model as model
import ckan.authz as authz
from ckan.lib import base
from ckan.views.user import set_repoze_user
from ckan.common import config, g, request

from ckanext.keycloak_auth.keycloak import KeycloakConnect

log = logging.getLogger(__name__)
keycloak_auth = Blueprint(u'keycloak_auth', __name__)


def _get_user_by_email(email):

    user_obj = model.User.by_email(email)
    if user_obj:
        user_obj = user_obj[0]

    if user_obj and user_obj.is_deleted():
        user_obj.activate()
        user_obj.commit()
        log.info(u'User {} reactivated'.format(user_obj.name))

    return user_obj if user_obj else None


def process_user(email, full_name, username):
    u'''
    Check if a user exists for the current login, if not register one
    Returns the user name
    '''
    user_dict = _get_user_by_email(email)
    alphabet = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(alphabet) for i in range(10))

    if user_dict:
        log.info(user_dict)
        
        user_dict.password = password

        return user_dict.name

    # This is the first time this user has logged in, register a user

    user_dict = {
        u'name': username,
        u'fullname': full_name,
        u'email': email,
        u'password': password,
    }

    context = {u'ignore_auth': True,}

    try:
        user_dict = toolkit.get_action(u'user_create')(context, user_dict)
    except toolkit.ValidationError as e:
        error_message = (e.error_summary or e.message or e.error_dict)
        base.abort(400, error_message)

    return user_dict[u'name']


def auth():
    u'''The location where auth redirect sent with a HTTP POST.
    '''
    token = request.form['access_token']

    g.user = None
    g.userobj = None

    server_url = config.get('ckanext.keycloak.server_url')
    realm = config.get('ckanext.keycloak.realm')
    client_id = config.get('ckanext.keycloak.client_id')
    client_secret_key = config.get('ckanext.keycloak.client_secret_key')

    keycloak = KeycloakConnect(server_url=server_url,
                                realm_name=realm,
                                client_id=client_id,
                                client_secret_key=client_secret_key)

    userinfo = keycloak.userinfo(token)

    g.user = process_user(userinfo['email'], userinfo['name'], userinfo['preferred_username'])

    user_id = ''

    for user in keycloak.userslist():
        if user['username'] == userinfo['preferred_username']:
            user_id = user['id']

    admin_group = config.get('ckanext.keycloak.admin_group')
    user_groups = keycloak.usergroupslist(user_id)
    in_admin_group = False

    for group in user_groups:
        if group['name'] == admin_group:
            in_admin_group = True

    is_sysadmin = authz.is_sysadmin(userinfo['preferred_username'])
    g.userobj = model.User.by_name(g.user)

    if is_sysadmin and not in_admin_group:
        g.userobj.sysadmin = False
        model.Session.add(g.userobj)
        model.Session.commit()
    elif not is_sysadmin and in_admin_group:
        g.userobj.sysadmin = True
        model.Session.add(g.userobj)
        model.Session.commit()

    relay_state = request.form.get('RelayState')
    redirect_target = toolkit.url_for(relay_state, _external=True) if relay_state else 'home.index'

    ckan_url = config.get('ckanext.keycloak.ckan_url')
    resp = toolkit.redirect_to(ckan_url)

    set_repoze_user(g.user, resp)

    return resp


def keycloak_login():
    u'''Redirects the user to keycloak identity provider for authentication
    '''
    server_url = config.get('ckanext.keycloak.server_url')
    realm = config.get('ckanext.keycloak.realm')
    frontend_client_id = config.get('ckanext.keycloak.frontend_client_id')
    ckan_url = config.get('ckanext.keycloak.ckan_url')

    redirect_url = (
        server_url
        + "/realms/"
        + realm
        + "/protocol/openid-connect"
        + "/auth?client_id="
        + frontend_client_id
        + "&redirect_uri="
        + ckan_url
        + "authenticate&response_mode=form_post&response_type=token&scope=openid&nonce=0d45c2fe-591b-4d34-8725-444d1218cb0c"
    )

    return toolkit.redirect_to(redirect_url)


def keycloak_change_password():
    u'''Redirects the user to keycloak identity provider for password change
    '''
    server_url = config.get('ckanext.keycloak.server_url')
    realm = config.get('ckanext.keycloak.realm')
    frontend_client_id = config.get('ckanext.keycloak.frontend_client_id')

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
    u'''Redirects the user to jupyterhub
    '''
    ckan_url = config.get('ckanext.keycloak.ckan_url')
    parsed_url = urlparse(ckan_url)
    host = parsed_url.netloc.split(':')[0]
    jupyterhub_host = 'jupyterhub.' + host[(len(host.split('.')[0]) + 1):]

    redirect_url = (
        "https://"
        + jupyterhub_host
        + "/"
    )

    return toolkit.redirect_to(redirect_url)

auth_endpoint = config.get('ckanext.keycloak_auth.auth_endpoint', '/authenticate')
keycloak_auth.add_url_rule(auth_endpoint, view_func=auth, methods=[u'GET', u'POST'])
keycloak_auth.add_url_rule(u'/user/keycloak_login', view_func=keycloak_login)
keycloak_auth.add_url_rule(u'/user/jupyterhub_login', view_func=jupyterhub_login)
keycloak_auth.add_url_rule(u'/user/keycloak_change_password', view_func=keycloak_change_password)