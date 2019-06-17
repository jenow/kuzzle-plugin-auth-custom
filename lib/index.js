const
  semver = require('semver'),
  CustomStrategy = require('./CustomStrategy').Strategy,
  defaultConfig = {
  };

/**
 * @class AuthenticationPlugin
 */
class AuthenticationPlugin {
  /**
   * @constructor
   */
  constructor () {
    this.context = null;
    this.strategy = null;
    this.userRepository = null;
    this.passwordManager = null;
    // to be used with Kuzzle post-1.4.0
    this.authenticators = {CustomStrategy};
  }

  /**
   * @param {object} customConfig
   * @param {KuzzlePluginContext} context
   * @returns {Promise<*>}
   */
  init (customConfig, context) {
    this.config = Object.assign(defaultConfig, customConfig);
    this.context = context;
    this.initStrategies();

    return true;
  }

  initStrategies () {
    this.strategies = {
      custom: {
        config: {
          strategyOptions: {},
          authenticateOptions: {
            scope: []
          },
          fields: ['username', 'password']
        },
        methods: {
          create: 'create',
          delete: 'delete',
          exists: 'exists',
          getById: 'getById',
          getInfo: 'getInfo',
          update: 'update',
          validate: 'validate',
          verify: 'verify'
        }
      }
    };

    // This snippet simply suppresses a warning emitted by Kuzzle during
    // plugin initialization.
    // See https://github.com/kuzzleio/kuzzle/pull/1145
    if (semver.lt(this.context.config.version, '1.4.0')) {
      this.strategies.custom.config.constructor = CustomStrategy;
    } else {
      this.strategies.custom.config.authenticator = 'CustomStrategy';
    }
  }

  getProviderRepository(provider) {
    if (!this.providerRepository) {
      this.providerRepository = {};
    }

    if (!this.providerRepository[provider]) {
      this.providerRepository[provider] = new this.context.constructors.Repository(provider);
    }

    return this.providerRepository[provider];
  }

  validate () {
    console.log('## I am validate ##');
  }

  exists () {
    console.log('## I am exists ##');
  }

  verify (request, username, password) {

    // Call to extern API to log user in
    // API CALL ...
    // If the user is successfully logged in ni the SSO then we check if it already exists in Kuzzle:
    return this.getProviderRepository('custom')
      .get(username)
      .then(userObject => {
        if (userObject !== null) {
          // Return it's kuid if exists
          return Promise.resolve({kuid: userObject.kuid, message: null});
        }

        throw new this.context.errors.ForbiddenError('Could not login with strategy "custom"');
      })
      .catch(err => {
        // Else we create the user in Kuzzle and log it in
        if (!(err instanceof this.context.errors.NotFoundError)) {
          throw err;
        }

        const req = {
          controller: 'security',
          action: 'createUser',
          body: {
            content: {
              profileIds: this.config.defaultProfiles ? this.config.defaultProfiles : ['default']
            },
            credentials: {}
          }
        };

        req.body.credentials.custom = {
          username
        };

        return this.context.accessors.execute(new this.context.constructors.Request(request.original, req, {refresh: 'wait_for'}))
          .then(res => Promise.resolve({kuid: res.result._id, message: null}));
      });
  }

  create () {
  }

  update () {
  }

  delete () {
  }

  getById () {
  }

  getInfo () {
  }

  getUsersRepository () {
  }

  getCredentialsFromUserId () {
  }
}

module.exports = AuthenticationPlugin;
