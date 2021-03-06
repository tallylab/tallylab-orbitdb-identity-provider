/**
 * @module TallyLabIdentityProvider
 */

/**
 * @external orbit-db-identity-provider
 * @see https://github.com/orbitdb/orbit-db-identity-provider/
 */

const Identities = require('orbit-db-identity-provider')
const TallyLabIdentityProvider = require('./src/tallylab-identity-provider')

/**
 * This module exposes a single function as the entry point for TallyLabIdentities.
 * The function returns an object containing a {@link TallyLabIdentityProvider} object.
 *
 * Additionally, since linking to Orbit requires both usage and configuration of the
 * Orbit-internal Identities object, this function handles the linking
 * and returns the aforementioned objects as well, in their modified state.
 *
 * @function TallyLabIAM
 * @see https://github.com/orbitdb/orbit-db-access-controllers#creating-a-custom-access-controller
 * @see https://github.com/orbitdb/orbit-db-identity-provider/#creating-an-identity
 *
 * @example
 * const identities = new TallyLabIAM()
 *
 * @returns {TallyLabIdentities} See type definitions below
 */
function TallyLabIdentities () {
  Identities.addIdentityProvider(TallyLabIdentityProvider)

  return {
    TallyLabIdentityProvider,
    Identities
  }
}

/**
 * @typedef {Object} TallyLabIdentities
 * @property {TallyLabIdentityProvider} TallyLabIdentityProvider - Identity via NACL keypairs
 * @property {external:orbit-db-identity-provider} Identities - Identities helper class from Orbit
 */

module.exports = TallyLabIdentities
