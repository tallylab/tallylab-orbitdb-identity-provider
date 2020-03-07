const IPFS = require('ipfs')
const naclFactory = require('js-nacl')
const OrbitDB = require('orbit-db')
const TallyLabIdentities = require('../index')
const TallyLabAccess = require('tallylab-orbitdb-access-controller')
const Keystore = require('orbit-db-keystore')

describe('OrbitDB Integration Testing', function () {
  let nacl, identities, identity, ipfs, orbitdb

  before(async () => {
    nacl = await new Promise((resolve, reject) => {
      naclFactory.instantiate((nacl) => {
        resolve(nacl)
      })
    })

    ipfs = await IPFS.create({
      preload: { enabled: false },
      relay: { enabled: true, hop: { enabled: true, active: true } },
      EXPERIMENTAL: { pubsub: true },
      config: { Bootstrap: [], Addresses: { Swarm: [] } }
    })

    identities = new TallyLabIdentities()

    const tlKeys = identities.TallyLabIdentityProvider.keygen(nacl)
    const keystore = new Keystore()
    await keystore.open()

    const id = tlKeys.signing.signPk.toString()
    const key = await keystore.getKey(id) || await keystore.createKey(id)
    const idSignature = await keystore.sign(key, id)

    const tlAccess = new TallyLabAccess()
    const tlSignature = nacl.crypto_sign(idSignature, tlKeys.signing.signSk)

    identity = await identities.Identities.createIdentity({
      type: 'TallyLab',
      id,
      keystore,
      tlSignature
    })

    orbitdb = await OrbitDB.createInstance(ipfs, {
      AccessControllers: tlAccess.AccessControllers,
      identity: identity
    })
  })

  it('writes an entry based on providing a public key & signature in the entry', async () => {
    const testDb = await orbitdb.feed('root', {
      accessController: {
        type: 'tallylab',
        write: [identity.id]
      }
    })

    await testDb.add('x')
  })

  after(async () => {
    await orbitdb.disconnect()
    await ipfs.stop()
  })
})
