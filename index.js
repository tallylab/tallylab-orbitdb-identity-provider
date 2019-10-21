/**
 * @external orbit-db-access-controllers
 */
const AccessControllers = require('orbit-db-access-controllers')

/**
 * @external orbit-db-identity-provider
 */
const Identities = require('orbit-db-identity-provider')

const TallyLabAccessController = require('./src/tallylab-access-controller')
const TallyLabIdentityProvider = require('./src/tallylab-identity-provider')

module.exports = {
  instantiate: async (nacl) => {
    TallyLabIdentityProvider.prototype.nacl = nacl

    Identities.addIdentityProvider(TallyLabIdentityProvider)
    AccessControllers.addAccessController({ AccessController: TallyLabAccessController })

    return {
      TallyLabAccessController,
      TallyLabIdentityProvider,
      Identities,
      AccessControllers
    }
  }
}
