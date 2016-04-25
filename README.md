# OAuth 2 Token Authentication

OAuth 2 bearer token manager and client, supporting refresh tokens.

This library is targeted for the browser as it makes use of
the the local storage API.

### Installation
```
jspm install github:n-fuse/token-authn
```

### Usage

```
import TokenAuthN from 'token-authn';

var authN = new TokenAuthN(oAuthURL);

authN.useLocalToken().then(...); // Reads and validates the access token
authN.validateToken().then(...); // Validates the session token
authN.login(username, password, rememberMe).then(...);
authN.logout().then(...);

authN.loggedIn;  // true or false
authN.tokenInfo; // Contains access and refresh token
```

### Additional information

 Stores a token info object in local storage under the following key:
 'oAuthURL + _ + tokenInfo'.

All API operations are promise based.

On `useLocalToken()`:
 - See if persisted token info exists in local storage and read token info
 - See if the 'access_token' is not expired yet
 - If it is, see if a refresh token exists an use it to get a new access token
 - If it fails, the promise rejects

On successful `login()`:
 - Persist the token info
 - If `rememberMe` is `false`, persist anyways but omit the refresh
   token as this is only relevant in case of a browser crash

On `logout()`:
 - Perform an HTTP DELETE against the token end-point to invalidate the session
 - Delete any persisted token info from local storage
