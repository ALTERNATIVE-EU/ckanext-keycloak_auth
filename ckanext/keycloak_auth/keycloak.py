import requests
import logging
import json

LOGGER = logging.getLogger(__name__)


class KeycloakConnect:
    def __init__(self, server_url, realm_name, client_id, client_secret_key=None):
        """Create Keycloak Instance.
        Args:
            server_url (str): 
                URI auth server
            realm_name (str): 
                Realm name
            client_id (str): 
                Client ID
            client_secret_key (str): 
                Client secret credencials.
                For each 'access type':
                    - confidencial -> Mandatory
        
        Returns:
            object: Keycloak object
        """

        self.server_url = server_url
        self.realm_name = realm_name
        self.client_id = client_id
        self.client_secret_key = client_secret_key

        # Keycloak useful Urls
        self.well_known_endpoint = (
            self.server_url
            + "/realms/"
            + self.realm_name
            + "/.well-known/openid-configuration"
        )
        self.token_introspection_endpoint = (
            self.server_url
            + "/realms/"
            + self.realm_name
            + "/protocol/openid-connect/token/introspect"
        )
        self.userinfo_endpoint = (
            self.server_url
            + "/realms/"
            + self.realm_name
            + "/protocol/openid-connect/userinfo"
        )
        self.groups_endpoint = (
            self.server_url
            + "/admin"
            + "/realms/"
            + self.realm_name
            + "/groups"
        )
        self.users_endpoint = (
            self.server_url
            + "/admin"
            + "/realms/"
            + self.realm_name
            + "/users"
        )
        self.client_token_endpoint = (
            self.server_url
            + "/realms/"
            + self.realm_name
            + "/protocol/openid-connect"
            + "/token"
        )

    def well_known(self):
        """Lists endpoints and other configuration options 
        relevant to the OpenID Connect implementation in Keycloak.
        Returns:
            [type]: [list of keycloak endpoints]
        """
        response = requests.request("GET", self.well_known_endpoint)
        error = response.raise_for_status()
        if error:
            LOGGER.error(
                "Error obtaining list of endpoints from endpoint: "
                f"{self.well_known_endpoint}, response error {error}"
            )
            return {}
        return response.json()

    def introspect(self, token, token_type_hint=None):
        """
        Introspection Request token
        Implementation: https://tools.ietf.org/html/rfc7662#section-2.1
        Args:
            token (string): 
                REQUIRED. The string value of the token.  For access tokens, this
                is the "access_token" value returned from the token endpoint
                defined in OAuth 2.0 [RFC6749], Section 5.1.  For refresh tokens,
                this is the "refresh_token" value returned from the token endpoint
                as defined in OAuth 2.0 [RFC6749], Section 5.1.  Other token types
                are outside the scope of this specification.
            token_type_hint ([string], optional): 
                OPTIONAL.  A hint about the type of the token submitted for
                introspection.  The protected resource MAY pass this parameter to
                help the authorization server optimize the token lookup.  If the
                server is unable to locate the token using the given hint, it MUST
                extend its search across all of its supported token types.  An
                authorization server MAY ignore this parameter, particularly if it
                is able to detect the token type automatically.  Values for this
                field are defined in the "OAuth Token Type Hints" registry defined
                in OAuth Token Revocation [RFC7009].
        Returns:
            json: The introspect token
        """
        payload = {
            "token": token,
            "client_id": self.client_id,
            "client_secret": self.client_secret_key,
        }
        headers = {
            "content-type": "application/x-www-form-urlencoded",
            "authorization": "Bearer " + token,
        }
        response = requests.request(
            "POST", self.token_introspection_endpoint, data=payload, headers=headers
        )
        error = response.raise_for_status()
        if error:
            LOGGER.error(
                "Error obtaining introspect token from endpoint: "
                f"{self.token_introspection_endpoint}, data {payload}, "
                f" headers {headers}, response error {error}"
            )
            return {}
        return response.json()

    def is_token_active(self, token):
        """Verify if introspect token is active.
        Args:
            token (str): The string value of the token. 
        Returns:
            bollean: Token valid (True) or invalid (False)
        """
        introspect_token = self.introspect(token)
        is_active = introspect_token.get("active", None)
        return True if is_active else False

    def roles_from_token(self, token):
        """
        Get roles from token
        Args:
            token (string): The string value of the token.
        Returns:
            list: List of roles.
        """
        token_decoded = self.introspect(token)

        realm_access = token_decoded.get("realm_access", None)
        resource_access = token_decoded.get("resource_access", None)
        client_access = (
            resource_access.get(self.client_id, None)
            if resource_access is not None
            else None
        )

        client_roles = (
            client_access.get("roles", None) if client_access is not None else None
        )
        realm_roles = (
            realm_access.get("roles", None) if realm_access is not None else None
        )

        if client_roles is None:
            return realm_roles
        if realm_roles is None:
            return client_roles
        return client_roles + realm_roles

    def userinfo(self, token):
        """Get userinfo (sub attribute from JWT) from authenticated token
        Args:
            token (str): The string value of the token.
        Returns:
            json: user info data
        """
        headers = {"authorization": "Bearer " + token}
        response = requests.request("GET", self.userinfo_endpoint, headers=headers)
        error = response.raise_for_status()
        if error:
            LOGGER.error(
                "Error obtaining userinfo token from endpoint: "
                f"{self.userinfo_endpoint}, headers {headers}, "
                f"response error {response.raise_for_status()}"
            )
            return {}
        return response.json()

    def userslist(self):
        """Get list of users from keycloak server
        Returns:
            json: user list
        """

        payload = {
            'client_id': self.client_id,
            'client_secret': self.client_secret_key,
            'grant_type': 'client_credentials'
        }
        headers = {
            "content-type": "application/x-www-form-urlencoded",
        }
        response = requests.request(
            "POST", self.client_token_endpoint, data=payload, headers=headers
        )

        error = response.raise_for_status()
        if error:
            LOGGER.error(
                "Error obtaining introspect token from endpoint: "
                f"{self.token_introspection_endpoint}, data {payload}, "
                f" headers {headers}, response error {error}"
            )
            return {}

        headers = {"authorization": "Bearer " + response.json()['access_token']}
        response = requests.request("GET", self.users_endpoint, headers=headers)
        error = response.raise_for_status()
        if error:
            LOGGER.error(
                "Error obtaining userslist token from endpoint: "
                f"{self.users_endpoint}, headers {headers}, "
                f"response error {response.raise_for_status()}"
            )
            return {}

        return response.json()

    def groupslist(self):
        """Get list of groups from keycloak server
        Returns:
            json: group list
        """

        payload = {
            'client_id': self.client_id,
            'client_secret': self.client_secret_key,
            'grant_type': 'client_credentials'
        }
        headers = {
            "content-type": "application/x-www-form-urlencoded",
        }
        response = requests.request(
            "POST", self.client_token_endpoint, data=payload, headers=headers
        )

        error = response.raise_for_status()
        if error:
            LOGGER.error(
                "Error obtaining introspect token from endpoint: "
                f"{self.token_introspection_endpoint}, data {payload}, "
                f" headers {headers}, response error {error}"
            )
            return {}

        headers = {"authorization": "Bearer " + response.json()['access_token']}
        response = requests.request("GET", self.groups_endpoint, headers=headers)
        error = response.raise_for_status()
        if error:
            LOGGER.error(
                "Error obtaining userslist token from endpoint: "
                f"{self.users_endpoint}, headers {headers}, "
                f"response error {response.raise_for_status()}"
            )
            return {}

        return response.json()

    def usergroupslist(self, user_id):
        """Get list of user's groups from keycloak server
        Returns:
            json: groups list
        """

        payload = {
            'client_id': self.client_id,
            'client_secret': self.client_secret_key,
            'grant_type': 'client_credentials'
        }
        headers = {
            "content-type": "application/x-www-form-urlencoded",
        }
        response = requests.request(
            "POST", self.client_token_endpoint, data=payload, headers=headers
        )

        error = response.raise_for_status()
        if error:
            LOGGER.error(
                "Error obtaining introspect token from endpoint: "
                f"{self.token_introspection_endpoint}, data {payload}, "
                f" headers {headers}, response error {error}"
            )
            return {}

        headers = {"authorization": "Bearer " + response.json()['access_token']}
        group_members_endpoint = (
            self.server_url
            + "/admin"
            + "/realms/"
            + self.realm_name
            + "/users/"
            + user_id
            + "/groups"
        )
        response = requests.request("GET", group_members_endpoint, headers=headers)
        error = response.raise_for_status()
        if error:
            LOGGER.error(
                "Error obtaining userslist token from endpoint: "
                f"{self.users_endpoint}, headers {headers}, "
                f"response error {response.raise_for_status()}"
            )
            return {}

        return response.json()

    def getuser(self, username):
        """Get user from keycloak server
        Returns:
            json: user object
        """

        payload = {
            'client_id': self.client_id,
            'client_secret': self.client_secret_key,
            'grant_type': 'client_credentials'
        }
        headers = {
            "content-type": "application/x-www-form-urlencoded",
        }
        response = requests.request(
            "POST", self.client_token_endpoint, data=payload, headers=headers
        )

        error = response.raise_for_status()
        if error:
            LOGGER.error(
                "Error obtaining introspect token from endpoint: "
                f"{self.token_introspection_endpoint}, data {payload}, "
                f" headers {headers}, response error {error}"
            )
            return {}

        headers = {"authorization": "Bearer " + response.json()['access_token']}
        url = self.users_endpoint + '?username=' + username
        response = requests.request("GET", url, headers=headers)
        error = response.raise_for_status()
        if error:
            LOGGER.error(
                "Error obtaining users: "
                f"{self.users_endpoint}, headers {headers}, "
                f"response error {response.raise_for_status()}"
            )
            return {}

        return response.json()[0]

    def checkUserCredentials(self, username, password):
        """Checks whether username, password pair is correct 
        # Returns:
        #     json: user object
        """

        payload = {
            'client_id': 'app-vue',
            'username': username,
            'password': password,
            'grant_type': 'password'
        }
        headers = {
            "content-type": "application/x-www-form-urlencoded",
        }
        response = requests.request(
            "POST", self.client_token_endpoint, data=payload, headers=headers
        )

        error = response.raise_for_status()
        if error:
            LOGGER.error(
                "Error obtaining introspect token from endpoint: "
                f"{self.token_introspection_endpoint}, data {payload}, "
                f" headers {headers}, response error {error}"
            )
            return {}

        return response.json()

    def resetpassword(self, user_id, new_password):
        """Reset password of a user
        """

        payload = {
            'client_id': self.client_id,
            'client_secret': self.client_secret_key,
            'grant_type': 'client_credentials'
        }
        headers = {
            "content-type": "application/x-www-form-urlencoded",
        }
        response = requests.request(
            "POST", self.client_token_endpoint, data=payload, headers=headers
        )

        error = response.raise_for_status()
        if error:
            LOGGER.error(
                "Error obtaining introspect token from endpoint: "
                f"{self.token_introspection_endpoint}, data {payload}, "
                f" headers {headers}, response error {error}"
            )
            return {}

        reset_password_endpoint = (
            self.server_url
            + "/admin"
            + "/realms/"
            + self.realm_name
            + "/users/"
            + str(user_id)
            + "/reset-password"
        )

        payload = {
            'type': 'password',
            'value': new_password,
            'temporary': False
        }
        body = json.dumps(payload)

        headers = {
            "Authorization": "Bearer " + response.json()['access_token'],
            "Content-Type": "application/json;charset=UTF-8"
        }
        response = requests.request(
            "PUT", reset_password_endpoint, data=body, headers=headers
        )

        error = response.raise_for_status()
        if error:
            LOGGER.error(
                "Error resetting password: "
                f"{reset_password_endpoint}, headers {headers}, "
                f"response error {response.raise_for_status()}"
            )
            return {}

        return {}