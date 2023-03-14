import logging
from flask import redirect
from six.moves.urllib.parse import urlparse

import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit

from .keycloak import KeycloakConnect
from ckanext.keycloak_auth.views.keycloak_auth import keycloak_auth
from ckanext.keycloak_auth.views.user import user

log = logging.getLogger(__name__)

class KeycloakAuthPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurable)
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IAuthenticator, inherit=True)


    # IConfigurable

    def configure(self, config):
        # Certain config options must exists for the plugin to work. Raise an
        # exception if they're missing.
        missing_param = "{0} is not configured. Please update your .ini file."

        server_url = config.get('ckanext.keycloak.server_url')
        if not server_url:
            raise RuntimeError(missing_param.format('ckanext.keycloak.server_url'))

        realm = config.get('ckanext.keycloak.realm')
        if not realm:
            raise RuntimeError(missing_param.format('ckanext.keycloak.realm'))

        client_id = config.get('ckanext.keycloak.client_id')
        if not client_id:
            raise RuntimeError(missing_param.format('ckanext.keycloak.client_id'))

        frontend_client_id = config.get('ckanext.keycloak.frontend_client_id')
        if not frontend_client_id:
            raise RuntimeError(missing_param.format('ckanext.keycloak.frontend_client_id'))

        admin_group = config.get('ckanext.keycloak.admin_group')
        if not admin_group:
            raise RuntimeError(missing_param.format('ckanext.keycloak.admin_group'))

        client_secret_key = config.get('ckanext.keycloak.client_secret_key')
        if not client_secret_key:
            raise RuntimeError(missing_param.format('ckanext.keycloak.client_secret_key'))

        ckan_url = config.get('ckanext.keycloak.ckan_url')
        if not ckan_url:
            raise RuntimeError(missing_param.format('ckanext.keycloak.ckan_url'))

        # Create Keycloak instance
        keycloak = KeycloakConnect(server_url=server_url,
                                    realm_name=realm,
                                    client_id=client_id,
                                    client_secret_key=client_secret_key)

        keycloak.userslist()


    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('fanstatic', 'keycloak_auth')


    # IBlueprint

    def get_blueprint(self):
        return [keycloak_auth, user]


    # IAuthenticator

    def logout(self):
        server_url = toolkit.config.get('ckanext.keycloak.server_url')
        realm = toolkit.config.get('ckanext.keycloak.realm')
        ckan_url = toolkit.config.get('ckanext.keycloak.ckan_url')

        redirect_url = (
            server_url
            + "/realms/"
            + realm
            + "/protocol/openid-connect"
            + "/logout?"
            + "redirect_uri="
            + ckan_url
        )

        response = redirect(redirect_url, code=302)
        if response:
            parsed_url = urlparse(ckan_url)
            host = parsed_url.netloc.split(':')[0]

            response.delete_cookie('auth_tkt', domain='.' + host)
            response.delete_cookie('auth_tkt')
            response.delete_cookie('ckan')

        return response