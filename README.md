# token-authn

Allows OAuth 2 token based user log-in and log-out against an Invend API.

### Installation
```
jspm install github:n-fuse/token-authn
```

### Usage

```
import TokenAuthN from 'token-authn';

var authN = new TokenAuthN(oAuthURL);

authN.useLocalToken().then(...);
authN.login(username, password, rememberMe).then(...);
authN.logout().then(...);

authN.loggedIn;  // true or false
authN.tokenInfo; // Contains access and refresh token
```

### Additional information

 Stores a token info object in local storage under the following key:
 'oAuthURL + _ + tokenInfo'.

All API operations are promise based.

On `useLocalToken()` call:
 - See if persisted token info exists in local storage and read token info
 - See if the 'access_token' is not expired yet
 - If it is, see if a refresh token exists an use it to get a new access token
 - If it fails, the promise rejects

On successful `login()` call:
 - Persist the token info
 - If 'remember me' has not been requested, persist anyways but
omit the refresh token as this is only relevant in case of a browser crash

On `logout()` call:
 - Perform DELETE against token end-point to invalidate the session
 - Delete any persisted token info from local storage


### License

[MIT license](LICENSE.txt)
