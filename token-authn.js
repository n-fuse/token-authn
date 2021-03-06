import Pajax from 'pajax';
import 'pajax-uri';
import store from 'store';
import StateMachine from 'state-machine';
import log from 'log';
import moment from 'moment';

export default class TokenAuthN {
  constructor(oAuthURL) {
    this.pajax = new Pajax().URLEncoded();
    this.tokenInfo = {};
    this.username = '';

    this._handlers = {};

    StateMachine.create({
      target: this,
      initial: 'newSession',
      events: [
        { name: 'validateLocalToken', from: ['newSession', 'loggedOut'],   to: 'loggingIn' },
        { name: 'validateCredentials', from: ['newSession', 'loggedOut'],   to: 'loggingIn'  },
        { name: 'confirmToken', from: ['loggingIn', 'loggedIn'],   to: 'loggedIn'  },
        { name: 'expireToken', from: ['*'],   to: 'loggedOut'  },
        { name: 'invalidateToken', from: ['*'],   to: 'loggedOut'  }
      ]
    });

    this.addBearerToken = this.addBearerToken.bind(this);
    this.validateResponse = this.validateResponse.bind(this);

    if(oAuthURL) {
      this.initialize(oAuthURL);
    }
  }

  initialize(oAuthURL) {
    this.oAuthURL = oAuthURL;

    let tokenInfo = this.tokenInfo = this.readToken() || {};
    if(tokenInfo.accessToken) {
      this.validateLocalToken();
      if (tokenInfo.accessTokenExp && moment().isBefore(tokenInfo.accessTokenExp)) {
        // Access token exists and is still valid
        this.confirmToken();
      } else {
        // Access token exists and is expired
        this.expireToken();
      }
    }
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

  // Validate session token
  validateToken() {
    let p;
    return this._wait(()=>{
      let tokenInfo = this.tokenInfo;
      if(tokenInfo.accessToken && tokenInfo.accessTokenExp) {
        let now = moment();
        if (!now.isBefore(tokenInfo.accessTokenExp)) {
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
  off(event, cb) {
    this._handlers[event] = this._handlers[event] || [];
    let index = this._handlers[event].indexOf(cb);
    if (index!==-1) {
      this._handlers[event].splice( index, 1 );
    }
  }
  emit(event, data) {
    if (this._handlers[event]) {
      this._handlers[event].forEach(cb=>{
        cb(data);
      });
    }
  }

  onenterstate() {
    log.debug(`${this.oAuthURL}: authN state changed to "${this.current}"`);
    this.emit('stateChanged', this.current);
  }

  get newSession() {
    return (this.current==='newSession');
  }

  get loggedIn() {
    return (this.current==='loggedIn');
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

  matchHost(url) {
    return (
      !Pajax.URI(url).host() ||
      !Pajax.URI(this.oAuthURL).host() ||
      Pajax.URI(this.oAuthURL).host()===Pajax.URI(url).host()
    );
  }

  // Inject the bearer token into the request as soon as it is available
  addBearerToken(req) {
    // Only add token if req host is relative or matches the oauth url host
    if(this.matchHost(req.url)) {
      // Validate the token before using it
      return this.validateToken().then(()=>{
        if(this.authorizationHeader) {
          return req.header('Authorization', this.authorizationHeader);
        }
      }).catch(err=>{
        // On validation errors just continue with the request
        return req;
      });
    }
  }

  validateResponse(res) {
    // delete token when 401 invalid token
    if (this.matchHost(res.url) && res.status === 401) {
      this.invalidateToken();
    }
    return res;
  }
}
