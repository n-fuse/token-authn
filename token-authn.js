import PAjax from 'pajax';
import { parseIRI } from 'iri';
import _clone from 'lodash/lang/clone';
import store from 'store';
import StateMachine from 'state-machine';
import log from 'log';
import moment from 'moment';

class TokenAuthN {
  constructor(oAuthURL) {
    this.oAuthURL = oAuthURL;
    this.loginAjax = new PAjax({
      contentType: 'application/x-www-form-urlencoded',
      responseType: 'json',
      headers: {
        Accept: 'application/json'
      }
    });

    this.logoutAjax = new PAjax('json-ld');
    this.logoutAjax.use(this);

    StateMachine.create({
      target: this,
      initial: 'unkown',
      events: [
        { name: 'useToken', from: ['loggedOut', 'unkown'],   to: 'loggingIn' },
        { name: 'useCredentials', from: ['loggedOut', 'unkown'],   to: 'loggingIn'  },
        { name: 'tokenValid', from: '*',   to: 'loggedIn'  },
        { name: 'tokenExpired', from: '*',   to: 'loggedOut'  },
        { name: 'tokenInvalidated', from: '*',   to: 'loggedOut'  }
      ]
    });

    // Validate saved token when initializing
    this.promise = new Promise((resolve, reject) => {
      var p;

      var tokenInfo = this.readToken();
      if (tokenInfo && tokenInfo.accessTokenExp) {
        this.useToken();

        var now = moment();
        if (now.isBefore(tokenInfo.accessTokenExp)) {
          // Access token exists and is still valid
          this.tokenInfo = tokenInfo;
          this.tokenValid();
          if(tokenInfo.refreshToken) {
            this.scheduleTokenRefresh();
          }
        } else if (tokenInfo.refreshToken) { // Refresh token exists
          // Try to get a new access token
          p = this.tryTokenRefresh(tokenInfo);
        } else {
          this.tokenExpired();
        }
      } else {
        this.tokenInvalidated();
      }
      resolve(p);
    });
  }

  on(event, cb) {
    this._handlers = this._handlers || {};
    this._handlers[event] = this._handlers[event] || [];
    this._handlers[event].push(cb);
  }

  trigger(event, data) {
    if(this._handlers && this._handlers[event]) {
      this._handlers[event].forEach(cb=> {
        cb(data);
      });
    }
  }

  get loggedIn() {
    return this.current === 'loggedIn';
  }

  get username() {
    return this.tokenInfo ? this.tokenInfo.username : null;
  }

  onenterstate() {
    log.debug(`${this.oAuthURL}: authN state changed to "${this.current}"`);
    this.trigger('stateChanged', this.current);
  }
  ontokenExpired() {
    this.tokenInfo = null;
  }

  ontokenInvalidated() {
    this.tokenInfo = null;
  }

  setBearerToken(username, accessToken, accessTokenExp, rememberMe, refreshToken) {
    rememberMe = rememberMe || true;
    var now = moment();
    accessTokenExp = now.add(accessTokenExp, 'seconds');
    this.tokenInfo = {
      username: username,
      rememberMe: rememberMe,
      accessToken: accessToken,
      accessTokenExp: accessTokenExp,
      refreshToken: refreshToken,
    };
    this.tokenValid();
    this.scheduleTokenRefresh(25);
    this.saveToken();
  }

  login(username, password, rememberMe) {
    var self = this;

    this.useCredentials();

    return this.loginAjax.post(this.oAuthURL, {
        'grant_type': 'password',
        'password': password,
        'username': username
      },
      {
        repsonseType: 'json'
      }).then(function(data) {
        var now = moment();
        var accessTokenExp = now.add(data.expires_in, 'seconds');

        self.tokenInfo = {
          username: username,
          rememberMe: rememberMe,
          accessToken: data.access_token,
          accessTokenExp: accessTokenExp,
          refreshToken: data.refresh_token
        };
        self.tokenValid();
        self.scheduleTokenRefresh(25);
        self.saveToken();
      }).catch( function(err) {
        self.tokenInvalidated();
        return Promise.reject(err);
      });
  }

  logout() {
    var self = this;
    var tokenInfo = this.tokenInfo;
    if(!tokenInfo || !tokenInfo.accessToken) {
      log.warn('No access token found');
    }

    this.unSchedule();

    var invalidate = function() {
      self.tokenInvalidated();
      self.clearToken(); // Delete ´remember me´ data
    };

    // delete token regardless of the outcome
    return this.logoutAjax.del(this.oAuthURL).then(invalidate, invalidate);
  }

  /* ------------- Token operations (internal) ------------ */
  /**
   @private
   */
  tryTokenRefresh(tokenInfo) {
    var self = this;

    tokenInfo = tokenInfo || this.tokenInfo || {};

    if(!tokenInfo.refreshToken) {
      log.debug('No refresh token found');
      return Promise.resolve();
    }

    var oAuthURL = this.oAuthURL;
    return this.loginAjax.post(oAuthURL, {
      grant_type: 'refresh_token',
      client_id: 'res_owner@invend.eu',
      client_secret: 'res_owner',
      refresh_token: tokenInfo.refreshToken
    }).then(function(data) {
      var now = moment();
      var accessTokenExp = now.add(data.expires_in, 'seconds');

      tokenInfo.accessToken = data.access_token;
      tokenInfo.accessTokenExp = accessTokenExp;
      tokenInfo.refreshToken = data.refresh_token;

      self.tokenInfo = tokenInfo;
      self.saveToken();
      // Schedule token refresh trial 25 min before expiration
      self.scheduleTokenRefresh();
      self.tokenValid();

      log.debug(oAuthURL + ': authN token refreshed');
    }).catch(function(err) {
      self.tokenExpired();
      log.error('Token refresh error', err);
      // Only retry if we have a non-auth error
      if (!(err.status === 400 || err.status === 401)) {
        // Schedule retry token refresh in 5 min from now
        self.refreshTimeoutFn = setTimeout(function() {
          self.tryTokenRefresh();
        }, 300 * 1000);
      } else {
        self.clearToken();
      }
    });
  }

  // Schedule token refresh and logout timers
  /**
   @private
   */
  scheduleTokenRefresh(expiryDistance) {
    var self = this;

    expiryDistance = expiryDistance || 25;

    var tokenInfo = this.tokenInfo;

    this.unSchedule();

    var accessTokenExp = tokenInfo.accessTokenExp;
    var timeOutMilis;
    var accessTokenExpOffset;

    // Schedule token refresh in ´expiry date´ - ´expiryDistance min´
    accessTokenExpOffset = moment(accessTokenExp).subtract(expiryDistance, 'minutes');
    timeOutMilis = accessTokenExpOffset.diff(moment());
    this.refreshTimeoutFn = setTimeout(function() {
      self.tryTokenRefresh();
    }, timeOutMilis);

    // Schedule logout state shortly before the token expires
    accessTokenExpOffset = moment(accessTokenExp).subtract(5, 'seconds');
    timeOutMilis = accessTokenExpOffset.diff(moment());
    this.expireTimeoutFn = setTimeout(function() {
      self.tokenExpired();
    }, timeOutMilis);
  }

  unSchedule() {
    clearTimeout(this.refreshTimeoutFn); // Stop automatic token refresh
    clearTimeout(this.expireTimeoutFn); // Stop automatic logout
  }

  readToken() {
    return store.get(this.oAuthURL + '_tokenInfo');
  }

  clearToken(){
    store.remove(this.oAuthURL + '_tokenInfo');
  }

  saveToken() {
    var tokenInfo = this.tokenInfo;
    if(tokenInfo) {
      var tkiClone = _clone(tokenInfo);
      // Don't persist the refresh token if the user wishes not to be remembered
      if (!tokenInfo.rememberMe) {
        tkiClone.refreshToken = null;
      }
      store.set(this.oAuthURL + '_tokenInfo', tkiClone);
    }
  }

  // Inject the l10n info to the ajax as soon as it is available
  beforeSend(req, xhr) {
    if(parseIRI(req.url).hostname===parseIRI(this.oAuthURL).hostname) {
      return this.promise.then(() => {
        var tokenInfo = this.tokenInfo;
        if (tokenInfo && tokenInfo.accessToken) {
          xhr.setRequestHeader('Authorization', 'Bearer ' + tokenInfo.accessToken);
        }
      });
    }
  }

  afterSend(req, xhr, result) {
    // delete token when 40? invalid token
    if(result.status===401) {
      // TODO: Not sure if needed
      this.tokenInvalidated();
      this.clearToken(); // Delete ´remember me´ data
    }
  }

  // Inject the bearer token into the request as soon as it is available
  addBearerToken() {
    return req=>{
      var promise = this.promise;
      if(parseIRI(req.url).hostname===parseIRI(this.oAuthURL).hostname) {
        promise = this.promise.then(() => {
          var tokenInfo = this.tokenInfo;
          if (tokenInfo && tokenInfo.accessToken) {
            req.opts.headers = req.opts.headers || {};
            req.opts.headers.Authorization = 'Bearer ' + tokenInfo.accessToken;
          }
        });
      }
      return promise.then(()=>req);
    }
  }
}


export default TokenAuthN;
