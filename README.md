# ckanext-keycloak_auth

## Description
The ckanext-keycloak_auth is a CKAN extension that integrates Keycloak for authentication and user management, leveraging OAuth2 for secure login and user session management.

## Authentication Flow

### 1. **Login Flow**

The login process consists of a series of steps that take the user from unauthenticated to authenticated status within the system. This process leverages **OAuth2 with Keycloak as the identity provider**.

#### Login Flow Diagram:

![Login Flow](./diagrams/login.png)

#### Step-by-Step Login Flow:

1. **User Initiates Login**:
   - The user clicks the "Login" button at the top of the CKAN page.

2. **Redirection to Keycloak**:
   - CKAN constructs a URL pointing to the Keycloak authorization endpoint.
   - The URL includes `client_id`, `redirect_uri`, `response_type=code`, and `scope=openid`.
   - CKAN redirects the user to this Keycloak URL.

3. **Keycloak Authentication**:
   - The user is presented with Keycloak's login form.
   - The user enters their credentials (username and password) and submits the form.

4. **Credential Validation**:
   - Keycloak internally validates the user's credentials.

5. **Authorization Code Generation**:
   - Upon successful authentication, Keycloak generates an authorization code.
   - Keycloak redirects the user back to CKAN's specified `redirect_uri` with the authorization code.

6. **Authorization Code Received**:
   - The user's browser sends a request to CKAN with the authorization code.

7. **Token Exchange Request**:
   - CKAN sends a server-to-server POST request to Keycloak's token endpoint.
   - CKAN exchanges the authorization code for access and refresh tokens.

8. **Token Response**:
   - Keycloak responds to CKAN with the access and refresh tokens.

9. **Session ID Generation**:
   - CKAN generates a secure session ID for the user.

10. **Database Storage**:
    - CKAN stores the session ID, access token, and refresh token in its database.

11. **Storage Confirmation**:
    - The database acknowledges successful storage of the session information.

12. **Cache Storage**:
    - CKAN stores the session information (session ID, access token, refresh token) in the session cache.

13. **Cache Confirmation**:
    - The session cache acknowledges successful caching of the session information.

14. **Cookie Setting**:
    - CKAN sets a `session_id` cookie in the user's browser.

15. **Final Redirection**:
    - The user is redirected to the CKAN interface, now logged in and authenticated.

---

### 2. **Identify (User Verification) Flow**

Once the user is logged in, CKAN needs to verify their identity on each request to ensure the user is authorized to access the requested resources. This is handled by inspecting the session and validating the access token.

#### Identify Flow Diagram:

![Identify Flow](./diagrams/identify.png)

#### Step-by-Step Identity Verification Flow:

1. **User Sends a Request**:
   - The user navigates the CKAN site, making a request (e.g., visiting a dataset page).
   - The request includes the `session_id` cookie.

2. **Session Lookup**:
   - CKAN queries the session cache using the `session_id`.
   - If the session is in the cache:
     - 2.1. The cache returns the cached session information.
   - If the session is not in the cache:
     - 2.2. CKAN queries the database for the session information.
     - 2.3. The database returns the session with Access Token and Refresh Token.
     - 2.4. CKAN stores the session information in the cache.
     - 2.5. The cache acknowledges successful caching.

3. **Token Header Extraction**:
   - CKAN extracts the 'kid' (Key ID) from the Access Token header.

4. **Public Key Retrieval**:
   - CKAN queries the Public Key Cache using the 'kid'.
   - If the public key is in the cache:
     - 4.1. The cache returns the cached public key.
   - If the public key is not in the cache:
     - 4.2. CKAN fetches the JWKS (JSON Web Key Set) from Keycloak.
     - 4.3. Keycloak returns the JWKS.
     - 4.4. CKAN extracts the public key for the specific 'kid'.
     - 4.5. CKAN stores the public key in the cache.
     - 4.6. The cache acknowledges successful caching of the public key.

5. **Access Token Validation**:
   - CKAN validates the Access Token using the public key.
   - If the Access Token is valid:
     - 5.1. CKAN serves the user's request.
   - If the Access Token has expired:
     - 5.2. CKAN requests new tokens from Keycloak using the Refresh Token.
     - 5.3. Keycloak returns new Access and Refresh Tokens.
     - 5.4. CKAN updates the session in the database with the new tokens.
     - 5.5. The database acknowledges the update.
     - 5.6. CKAN updates the cached session information.
     - 5.7. The cache acknowledges the update.
     - 5.8. CKAN serves the user's request.
   - If the Refresh Token is invalid:
     - 5.9. CKAN deletes the session from the database.
     - 5.10. The database acknowledges the session deletion.
     - 5.11. CKAN deletes the cached session.
     - 5.12. The cache acknowledges the deletion.
     - 5.13. CKAN redirects the user to the login page.
---

### 3. **Logout Flow**

When a user logs out, the system must invalidate the session both in CKAN and in Keycloak, and ensure the user is no longer able to access protected resources.

#### Logout Flow Diagram:

![Logout Flow](./diagrams/logout.png)

#### Step-by-Step Logout Flow:

1. **User Initiates Logout**:
   - The user clicks the "Logout" button in the CKAN interface.

2. **Database Session Deletion**:
   - CKAN sends a request to delete the session from the database using the session_id.

3. **Database Acknowledgment**:
   - The database acknowledges the successful deletion of the session.

4. **Cache Session Deletion**:
   - CKAN delete the cached session from the Session Cache.

5. **Cache Acknowledgment**:
   - The Session Cache acknowledges the successful deletion of the cached session.

6. **Cookie Deletion**:
   - CKAN deletes the session_id cookie from the user's browser.

7. **Keycloak Logout Redirection**:
   - CKAN redirects the user to the Keycloak logout endpoint.

8. **Keycloak Session Invalidation**:
   - Keycloak invalidates its own session for the user.

9. **User Redirection to CKAN**:
   - Keycloak redirects the user back to CKAN (typically to the homepage or a logout confirmation page).

10. **Logout Completion**:
    - The user arrives at CKAN, now fully logged out.

---

### **Grant Type: Authorization Code Flow**
The **Authorization Code Grant** is used for the login flow. This is the most secure OAuth2 flow for server-side applications, where the application exchanges an **Authorization Code** for an **Access Token** and a **Refresh Token**.

#### **Key Points:**
- **Authorization Code**: This is a short-lived code that can only be exchanged for tokens when sent via the backend (to protect from exposure).
- **Access Token**: A JWT that contains user identity and permissions, used to authenticate the user for each request.
- **Refresh Token**: Used to obtain a new access token without re-authentication, ensuring seamless user experience after token expiration.
  
**Why Authorization Code Grant is Used:**
- **Security**: Tokens are not exposed in the browser.
- **Server-side Token Management**: CKAN securely manages access and refresh tokens, reducing the risk of token leaks.

---

### **Validation of Access Tokens (JWT Tokens)**
The **Access Token** issued by Keycloak is a **JWT (JSON Web Token)**, which is validated locally by CKAN without needing to contact Keycloak for every request. The token contains information about the user and the session and is validated using the following checks:

1. **Token Signature Validation**:
   - The token’s signature is verified using Keycloak's public key, ensuring the token was issued by Keycloak and has not been tampered with. CKAN fetches the public key from Keycloak’s JWKS (JSON Web Key Set) endpoint.
   
2. **Expiration Time (exp)**:
   - The `exp` claim inside the token specifies the expiration time. CKAN checks this field to ensure the token is still valid. If the token has expired, CKAN uses the **Refresh Token** to obtain a new Access Token.

#### **Token Refresh Process**:
- If the access token is expired but the refresh token is still valid, CKAN sends a **Token Refresh Request** to Keycloak to get a new access token.
- If both the access token and refresh token are invalid, CKAN will delete the session and the user is redirected to the login page.

#### Optimizations:

- **Caching Public Keys**: CKAN caches the public keys fetched from Keycloak to reduce the number of requests to Keycloak’s JWKS endpoint.
- **Asynchronous Public Key Fetching**: CKAN fetches the public keys asynchronously to prevent blocking the main thread.

---

### Summary

- **Login**: The user is redirected to Keycloak, authenticates, and returns to CKAN with tokens that are stored in a session. The session is maintained using a `session_id` cookie.
- **User Verification (Identify)**: On each request, CKAN verifies the user by checking the session, validating the access token, and potentially refreshing it if expired.
- **Logout**: The session is destroyed in CKAN, and the user is logged out from both CKAN and Keycloak. The session cookie is removed.


## Setup

1. Install <a href="https://docs.ckan.org/en/2.9/extensions/tutorial.html#installing-ckan" target="_blank">CKAN</a>

2. Start a Keycloak instance in Docker - <a href="https://www.keycloak.org/getting-started/getting-started-docker" target="_blank">Guide</a>

3. In Keycloak, create a realm with the <a href="https://github.com/ALTERNATIVE-EU/platform-deployment/blob/master/deployment/charts/keycloak/realms/alternative-realm.json" target="_blank">alternative realm json file</a>

4. From the Keycloak admin console, update the URLs of the `ai-ml-api`, `ckan-backend`, `ckan-frontend` and `jupyterhub` clients

5. Clone the repository in the `src` dir (usually located in `/usr/lib/ckan/default/src`)
    ```
    cd /usr/lib/ckan/default/src
    git clone https://github.com/ALTERNATIVE-EU/ckanext-keycloak_auth.git
    ```

6. Build the extension
    ```
    . /usr/lib/ckan/default/bin/activate
    cd /usr/lib/ckan/default/src/ckanext-keycloak_auth
    sudo python3 setup.py develop
    ```

7. Update the CKAN config file (usually located at `/etc/ckan/default/ckan.ini`)

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


8. Add users in Keycloak

   - Log in to the Keycloak Admin Console.
   - Navigate to the **Users** section and create new users.
   - To make a user a CKAN sysadmin, add them to the **`admins` group**:
     1. In the user’s settings, navigate to the **Groups** tab.
     2. Join the user to the `admins` group (this group should be created in Keycloak as part of your realm setup).

9. Start CKAN
   ```
   . /usr/lib/ckan/default/bin/activate
   sudo ckan -c /etc/ckan/default/ckan.ini run
   ```
