/* */
import Pajax from 'pajax';
import store from 'store';
import StateMachine from 'state-machine';
import log from 'log';
import moment from 'moment';

class TokenAuthN {
  constructor(oAuthURL) {
    this.oAuthURL = oAuthURL || '/oauth2/token';
    this.pajax = new Pajax().URLEncoded();
    this.tokenInfo = {};
    this.newSession = true;
    this.loggedIn = false;
    this.username = 'Guest';

    this._handlers = {};

    StateMachine.create({
      target: this,
      initial: 'newSession',
      events: [
        { name: 'validateLocalToken', from: ['newSession', 'loggedOut'],   to: 'loggingIn' },
        { name: 'validateCredentials', from: ['newSession', 'loggedOut'],   to: 'loggingIn'  },
        { name: 'confirmToken', from: ['loggingIn', 'newSession'],   to: 'loggedIn'  },
        { name: 'expireToken', from: ['*'],   to: 'loggedOut'  },
        { name: 'invalidateToken', from: ['*'],   to: 'loggedOut'  }
      ]
    });
  }

  _wait(cb) {
    let promise = this._waitp || Promise.resolve();
    return promise.then(()=>{
      let promise = Promise.resolve(cb())
      // Ignore errors on wait jobs
      this._waitp = promise.catch(err=>null);
      return promise;
    });
  }

  useLocalToken() {
    let tokenInfo = this.tokenInfo = this.readToken() || {};
    if(tokenInfo.accessToken) {
      this.validateLocalToken();
      if (tokenInfo.accessTokenExp && moment().isBefore(tokenInfo.accessTokenExp)) {
        // Access token exists and is still valid
        this.confirmToken();
      } else {
        // Access token exists and is expired
        return this.validateToken();
      }
    }
    return Promise.resolve();
  }

  // Validate session token
  validateToken() {
    let p;
    return this._wait(()=>{
      let tokenInfo = this.tokenInfo;
      if(tokenInfo.accessToken && tokenInfo.accessTokenExp) {
        let now = moment();
        if (!now.isBefore(tokenInfo.accessTokenExp)) {
          this.expireToken();
          if(tokenInfo.refreshToken) {
            this.validateLocalToken();
            let payload = {
              grant_type: 'refresh_token',
              client_id: 'res_owner@invend.eu',
              client_secret: 'res_owner',
              refresh_token: tokenInfo.refreshToken
            };
            return this.pajax
                       .request(this.oAuthURL)
                       .header('Accept', 'application/json')
                       .attach(payload)
                       .post()
                       .then(res=>res.json())
                       .then(data=>{
                         tokenInfo.accessToken = data.access_token;
                         tokenInfo.accessTokenExp = moment().add(data.expires_in, 'seconds').toISOString();
                         tokenInfo.refreshToken = data.refresh_token;
                         this.tokenInfo = tokenInfo;
                         this.confirmToken();
                         this.saveToken();
                       }).catch(res=>{
                         log.error('Token refresh error', res);
                         // Remove invalid token from local storage
                         this.expireToken();
                       });

          } else {
            this.expireToken();
          }
        }
      }
    });
  }

  on(event, cb) {
    this._handlers[event] = this._handlers[event] || [];
    this._handlers[event].push(cb);
  }

  trigger(event, data) {
    if (this._handlers[event]) {
      this._handlers[event].forEach(cb=>{
        cb(data);
      });
    }
  }

  onenterstate() {
    log.debug(`${this.oAuthURL}: authN state changed to "${this.current}"`);
    this.trigger('stateChanged', this.current);
    this.newSession = (this.current === 'newSession');
    this.loggedIn = (this.current === 'loggedIn');
  }

  login(username, password, rememberMe) {
    return this._wait(()=>{
      this.validateCredentials();
      let payload = {
        'grant_type': 'password',
        password,
        username
      };
      return this.pajax
                 .request(this.oAuthURL)
                 .header('Accept', 'application/json')
                 .attach(payload)
                 .post()
                 .then(res=>res.json())
                 .then(data=>{
                   this.tokenInfo = {
                     username: username,
                     rememberMe: rememberMe,
                     accessToken: data.access_token,
                     accessTokenExp: moment().add(data.expires_in, 'seconds').toISOString(),
                     refreshToken: data.refresh_token
                   };
                   this.confirmToken();
                   this.saveToken();
                 }).catch(err=> {
                   this.invalidateToken();
                   return Promise.reject(err);
                 });
    });
  }

  logout() {
    let tokenInfo = this.tokenInfo;
    let invalidate = () => this.invalidateToken();
    return this._wait(()=>{
      if(this.authorizationHeader) {
        // delete token regardless of the outcome
        return this.pajax
        .request(this.oAuthURL)
        .header('Authorization', this.authorizationHeader)
        .delete()
        .then(invalidate, invalidate);
      } else {
        invalidate();
      }
    });
  }

  onconfirmToken() {
    this.username = this.tokenInfo.username;
  }

  oninvalidateToken() {
    this.tokenInfo = {};
    this.clearToken(); // Delete ´remember me´ data
  }

  readToken() {
    return store.get('token-authN_' + this.oAuthURL);
  }

  clearToken() {
    store.remove('token-authN_' + this.oAuthURL);
  }

  saveToken() {
    let tokenInfo = this.tokenInfo;
    if (tokenInfo) {
      store.set('token-authN_' + this.oAuthURL, {
        username: tokenInfo.username,
        accessToken: tokenInfo.accessToken,
        accessTokenExp: tokenInfo.accessTokenExp,
        rememberMe: tokenInfo.rememberMe,
        // Don't persist the refresh token if the user wishes not to be remembered
        refreshToken: tokenInfo.rememberMe ? tokenInfo.refreshToken : null
      });
    }
  }

  get authorizationHeader() {
    return this.tokenInfo.accessToken ? `Bearer ${this.tokenInfo.accessToken}` : null;
  }
}
export default TokenAuthN;
