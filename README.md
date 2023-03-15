# ckanext-keycloak_auth

CKAN extension that enables Keycloak authentication and user management.

## Setup

1. Install <a href="https://docs.ckan.org/en/2.9/extensions/tutorial.html#installing-ckan" target="_blank">CKAN</a>

2. Start a Keycloak instance in Docker - <a href="https://www.keycloak.org/getting-started/getting-started-docker" target="_blank">Guide</a>

3. In Keycloak, create a realm with the <a href="https://github.com/ALTERNATIVE-EU/platform-deployment/blob/main/deployment/charts/keycloak/realms/alternative-realm.json" target="_blank">alternative realm json file</a>

4. Clone the repository in the `src` dir (usually located in `/usr/lib/ckan/default/src`)
    ```
    cd /usr/lib/ckan/default/src
    git clone https://github.com/ALTERNATIVE-EU/ckanext-keycloak_auth.git
    ```

5. Build the extension
    ```
    . /usr/lib/ckan/default/bin/activate
    cd /usr/lib/ckan/default/src/ckanext-keycloak_auth
    sudo python3 setup.py develop
    ```

6. Update the ckan config file (usually `/etc/ckan/default/ckan.ini`)
    - Add the extension to your list of plugins
    ```
    ckan.plugins = stats text_view recline_view keycloak_auth
    ```
    - Add <a href="https://github.com/ALTERNATIVE-EU/platform-deployment/blob/main/ckan-alternative-theme/keycloak_auth-config" target="_blank">these settings</a>; change the `ckan_url`, `server_url` and `client_secret_key` (generate new client credentials secret for `ckan-backend` client) params; you might need to change the URLs (Root URL, Valid Redirect URIs, Admin URL, Web Origins) of the `ckan-backend` and `ckan-frontend` clients in Keycloak

7. Add users in Keycloak; to make a sysadmin user - add them to the `admins` group

8. Start CKAN
   ```
   . /usr/lib/ckan/default/bin/activate
   sudo ckan -c /etc/ckan/default/ckan.ini run
   ```
