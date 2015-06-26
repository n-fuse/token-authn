import Pajax from 'pajax';
import _clone from 'lodash/lang/clone';
import store from 'store';
import StateMachine from 'state-machine';
import log from 'log';
import moment from 'moment';

class TokenAuthN {
  constructor(oAuthURL) {
    this.oAuthURL = oAuthURL;
    this.pajax = new Pajax.URLEncoded({
      headers: {
        Accept: 'application/json'
      }
    });

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

  login(username, password, rememberMe) {
    this.useCredentials();
    return this.pajax.post(this.oAuthURL)
                     .send({
                            'grant_type': 'password',
                            'password': password,
                            'username': username
                           })
                    .done()
                    .then(res=>{
                      var data = res.body;
                      var now = moment();
                      var accessTokenExp = now.add(data.expires_in, 'seconds');

                      this.tokenInfo = {
                        username: username,
                        rememberMe: rememberMe,
                        accessToken: data.access_token,
                        accessTokenExp: accessTokenExp,
                        refreshToken: data.refresh_token
                      };
                      this.tokenValid();
                      this.scheduleTokenRefresh(25);
                      this.saveToken();
                    }).catch(err=>{
                      this.tokenInvalidated();
                      return Promise.reject(err);
                    });
  }

  logout() {
    var tokenInfo = this.tokenInfo;
    if(!tokenInfo || !tokenInfo.accessToken) {
      log.warn('No access token found');
    }

    this.unSchedule();

    var invalidate = res=>{
      this.tokenInvalidated();
      this.clearToken(); // Delete ´remember me´ data
    };

    // delete token regardless of the outcome
    return Pajax.del(this.oAuthURL)
                .before(this.addBearerToken())
                .done()
                .then(invalidate, invalidate);
  }

  /* ------------- Token operations (internal) ------------ */
  /**
   @private
   */
  tryTokenRefresh(tokenInfo) {
    tokenInfo = tokenInfo || this.tokenInfo || {};

    if(!tokenInfo.refreshToken) {
      log.debug('No refresh token found');
      return Promise.resolve();
    }
    return this.pajax.post(this.oAuthURL)
                     .send({
                            grant_type: 'refresh_token',
                            client_id: 'res_owner@invend.eu',
                            client_secret: 'res_owner',
                            refresh_token: tokenInfo.refreshToken
                           })
                    .done()
                    .then(res=>{
                      var data = res.body;
                      var now = moment();
                      var accessTokenExp = now.add(data.expires_in, 'seconds');

                      tokenInfo.accessToken = data.access_token;
                      tokenInfo.accessTokenExp = accessTokenExp;
                      tokenInfo.refreshToken = data.refresh_token;

                      this.tokenInfo = tokenInfo;
                      this.saveToken();
                      // Schedule token refresh trial 25 min before expiration
                      this.scheduleTokenRefresh();
                      this.tokenValid();

                      log.debug(this.oAuthURL + ': authN token refreshed');
                    }).catch(err=>{
                      this.tokenExpired();
                      log.error('Token refresh error', err);
                      // Only retry if we have a non-auth error
                      if (!(err.status === 400 || err.status === 401)) {
                        // Schedule retry token refresh in 5 min from now
                        this.refreshTimeoutFn = setTimeout(()=>{
                          this.tryTokenRefresh();
                        }, 300 * 1000);
                      } else {
                        // Remove invalid token from local storage
                        this.clearToken();
                      }
                    });
  }

  // Schedule token refresh and logout timers
  /**
   @private
   */
  scheduleTokenRefresh(expiryDistance) {
    expiryDistance = expiryDistance || 25;

    var tokenInfo = this.tokenInfo;

    this.unSchedule();

    var accessTokenExp = tokenInfo.accessTokenExp;
    var timeOutMilis;
    var accessTokenExpOffset;

    // Schedule token refresh in ´expiry date´ - ´expiryDistance min´
    accessTokenExpOffset = moment(accessTokenExp).subtract(expiryDistance, 'minutes');
    timeOutMilis = accessTokenExpOffset.diff(moment());
    this.refreshTimeoutFn = setTimeout(()=>{
      this.tryTokenRefresh();
    }, timeOutMilis);

    // Schedule logout state shortly before the token expires
    accessTokenExpOffset = moment(accessTokenExp).subtract(5, 'seconds');
    timeOutMilis = accessTokenExpOffset.diff(moment());
    this.expireTimeoutFn = setTimeout(()=>{
      this.tokenExpired();
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

  // Inject the bearer token into the request as soon as it is available
  addBearerToken() {
    return req=>{
      var promise = this.promise;
      if(Pajax.parseURL(req.url).hostname===Pajax.parseURL(this.oAuthURL).hostname) {
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

  validateResponse() {
    return res=>{
      // delete token when 40? invalid token
      if(res.status===401) {
        // TODO: Not sure if needed
        this.tokenInvalidated();
        this.clearToken(); // Delete ´remember me´ data
      }
    }
  }
}

export default TokenAuthN;
