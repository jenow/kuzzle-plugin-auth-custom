const passport = require('passport-strategy');

class CustomStrategy {

  constructor (options, verify) {
    if (typeof options === 'function') {
      verify = options;
      options = {};
    }
    if (!verify) { throw new TypeError('CustomStrategy requires a verify callback'); }
    
    this._usernameField = options.usernameField || 'username';
    this._passwordField = options.passwordField || 'password';
    
    passport.Strategy.call(this);
    this.name = 'local';
    this._verify = verify;
    this._passReqToCallback = options.passReqToCallback;
  }

  authenticate (req) {
    const username = req.body[this._usernameField];
    const password = req.body[this._passwordField];
    
    const verified = (err, user, info) =>  {
      if (err) { return this.error(err); }
      if (!user) { return this.fail(info); }
      this.success(user, info);
    };
    
    try {
      if (this._passReqToCallback) {
        this._verify(req, username, password, verified);
      } else {
        this._verify(username, password, verified);
      }
    } catch (ex) {
      return this.error(ex);
    }
  }
}

exports = module.exports = CustomStrategy;

exports.Strategy = CustomStrategy;