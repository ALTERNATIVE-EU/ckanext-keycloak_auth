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

6. Update the CKAN config file (usually located at `/etc/ckan/default/ckan.ini`)

   - Add the `keycloak_auth` extension to the list of CKAN plugins:
    ```ini
    ckan.plugins = stats text_view recline_view keycloak_auth
    ```

   - Include these settings in the CKAN configuration file by following the structure provided [here](https://github.com/ALTERNATIVE-EU/platform-deployment/blob/master/ckan-alternative-theme/keycloak_auth-config).

     Specifically, you need to modify the following parameters:
     - **`ckan_url`**: Set this to the URL of your CKAN instance (e.g., `http://localhost:5000` or your production URL).
     - **`server_url`**: Set this to the Keycloak server URL (e.g., `http://localhost:8080/auth` for a local instance or the actual Keycloak URL in production).
     - **`client_secret_key`**: Generate a new client secret for the `ckan-backend` client in Keycloak and use it here.

     To generate a new **client secret**:
     1. Log in to the Keycloak Admin Console.
     2. Navigate to the **Clients** section and select the `ckan-backend` client.
     3. In the **Credentials** tab, generate and copy a new secret.
     4. Add this secret to the `client_secret_key` parameter in the CKAN config.

   - Ensure the **URLs in Keycloak** for both the `ckan-backend` and `ckan-frontend` clients are configured correctly:
     - **Root URL**: This should point to your CKAN instance (e.g., `http://localhost:5000` for local, or your actual CKAN URL).
     - **Valid Redirect URIs**: Set this to include the URLs where Keycloak will redirect after login, such as `http://localhost:5000/*` (for local) or your CKAN URL with wildcard paths.
     - **Web Origins**: Include the CKAN URL to ensure proper CORS handling, such as `http://localhost:5000`.


7. Add users in Keycloak

   - Log in to the Keycloak Admin Console.
   - Navigate to the **Users** section and create new users.
   - To make a user a CKAN sysadmin, add them to the **`admins` group**:
     1. In the user’s settings, navigate to the **Groups** tab.
     2. Join the user to the `admins` group (this group should be created in Keycloak as part of your realm setup).

8. Start CKAN
   ```
   . /usr/lib/ckan/default/bin/activate
   sudo ckan -c /etc/ckan/default/ckan.ini run
   ```
