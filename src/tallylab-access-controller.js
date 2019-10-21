const TallyLabIdentityProvider = require('./tallylab-identity-provider')

/**
 * > Manages write access to databases via TL keys. Also, by way of doing _that_, also
 * > guarantees that our db addresses are deterministic.
 *
 * An OrbitDB Access controller is mostly a configuration entity, exposing simple
 * functions that regulate permisisons on a DB. Note that as a function of all entries
 * being on the global IPFS network, all databases are public read. However, we can, and do
 * protect writes.
 *
 * Future Work: Explore approaches for grant and revoke of access to individual
 * dbs (shared tallies)
 *
 * ## Usage:
 * ```JavaScript
 * AccessControllers.addAccessController({ AccessController: TallyLabAccessController })
 *
 * const orbitdb = await OrbitDB.createInstance(ipfs, {
 *   AccessControllers: AccessControllers,
 *   identity: identity
 * })
 *
 * const rootDb = await orbitdb.kvstore('root', {
 *   accessController: {
 *     type: 'tallylab',
 *     write: [identity.id]
 *   }
 * })
 * ```
 */
class TallyLabAccessController {
  constructor (orbitdb, options) {
    this._orbitdb = orbitdb
    this._options = options || {}
  }

  static get type () { return 'tallylab' }
  /*
    Return the type for this controller
    NOTE! This is the only property of the interface that
    shouldn't be overridden in the inherited Access Controller
  */
  get type () {
    return this.constructor.type
  }

  /*
    Called by the databases (the log) to see if entry should
    be allowed in the database. Return true if the entry is allowed,
    false is not allowed
  */
  async canAppend (entry, identityProvider, f, b) {
    const orbitIdentity = this._orbitdb.identity
    const entryIdentity = entry.identity
    const verified = await TallyLabIdentityProvider.verifyIdentity(orbitIdentity)

    if (!verified) return false
    if (orbitIdentity.id !== entryIdentity.id) return false
    if (this._options.write.indexOf(orbitIdentity.id) === -1) return false
    if (!(await identityProvider._keystore.hasKey(entryIdentity.id))) return false

    return true
  }

  /*
    Every AC needs to have a 'Factory' method
    that creates an instance of the AccessController
  */
  static async create (orbitdb, options) {
    return new TallyLabAccessController(orbitdb, options)
  }

  /* Each Access Controller has some address to anchor to */
  // get address () {}

  // async canAppend (entry, identityProvider) {}

  /* Add and remove access */
  // async grant (access, identity) { return false }
  // async revoke (access, identity) { return false }

  /* AC creation and loading */
  async load (address) {
    const manifest = await this._orbitdb._ipfs.dag.get(address)
    return manifest.value
  }

  /* Returns AC manifest parameters object */
  async save () {
    const cid = await this._orbitdb._ipfs.dag.put(this._options)
    return { address: cid.toBaseEncodedString() }
  }
}

module.exports = TallyLabAccessController
