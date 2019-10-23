const assert = require('assert')
const naclFactory = require('js-nacl')
const TallyLabIAM = require('../index')

describe('Identity Provider', function () {
  let iam

  before(async () => {
    iam = await new Promise((resolve, reject) => {
      naclFactory.instantiate((nacl) => {
        iam = new TallyLabIAM(nacl)
        resolve(iam)
      })
    })
  })

  it('is bundled properly with nacl', () => {
    assert(!!iam.TallyLabIdentityProvider.prototype.nacl)
  })

  it('generates deterministic keys based on 32-byte seed strings', () => {
    const seed1 = 'thisisexactlythirtytwocharacters'
    const seed2 = 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
    const seed3 = 'yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy'
    const seed4 = 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'

    const keypair1 = iam.TallyLabIdentityProvider.keygen(seed1)
    assert.strictEqual(keypair1.publicKey.toString(), '196,6,185,18,253,10,139,84,248,51,221,118,178,67,198,54,240,69,252,14,209,185,54,18,133,11,125,130,46,86,69,81')
    assert.strictEqual(keypair1.privateKey.toString(), '32,196,135,206,166,39,190,242,200,133,233,237,195,140,106,215,158,170,95,67,254,186,199,178,105,190,107,61,180,218,175,167')
    assert.strictEqual(keypair1.signing.signPk.toString(), '203,57,32,160,244,50,95,92,194,226,114,226,82,141,243,249,184,46,65,165,102,65,137,254,205,255,177,173,246,143,229,170')
    assert.strictEqual(keypair1.signing.signSk.toString(), '116,104,105,115,105,115,101,120,97,99,116,108,121,116,104,105,114,116,121,116,119,111,99,104,97,114,97,99,116,101,114,115,203,57,32,160,244,50,95,92,194,226,114,226,82,141,243,249,184,46,65,165,102,65,137,254,205,255,177,173,246,143,229,170')
    assert.strictEqual(keypair1.securityVersion, 2.0)

    // Note: These values are derived from the previous security version on TL, ensuring backwards compatibility
    const keypair2 = iam.TallyLabIdentityProvider.keygen(seed2)
    assert.strictEqual(keypair2.publicKey.toString(), '156,37,248,171,221,249,107,216,132,145,204,33,21,40,243,66,159,46,136,134,113,47,1,248,147,36,196,124,86,67,172,32')
    assert.strictEqual(keypair2.privateKey.toString(), '134,168,109,247,140,142,251,82,176,123,150,216,90,191,248,15,98,82,224,119,212,16,238,1,19,239,81,52,17,82,181,199')
    assert.strictEqual(keypair2.signing.signPk.toString(), '238,49,248,60,136,167,18,25,166,252,249,190,224,218,155,194,38,32,88,143,90,21,166,20,85,83,80,77,249,100,158,92')
    assert.strictEqual(keypair2.signing.signSk.toString(), '120,120,120,120,120,120,120,120,120,120,120,120,120,120,120,120,120,120,120,120,120,120,120,120,120,120,120,120,120,120,120,120,238,49,248,60,136,167,18,25,166,252,249,190,224,218,155,194,38,32,88,143,90,21,166,20,85,83,80,77,249,100,158,92')

    const keypair3 = iam.TallyLabIdentityProvider.keygen(seed3)
    assert.strictEqual(keypair3.publicKey.toString(), '38,77,95,113,35,121,169,17,131,104,209,95,8,3,97,1,202,242,154,236,20,156,111,25,52,218,80,95,127,57,147,17')
    assert.strictEqual(keypair3.privateKey.toString(), '177,27,246,150,218,33,134,3,250,250,13,89,164,141,213,227,146,203,56,167,60,181,77,0,56,238,213,54,108,45,148,103')
    assert.strictEqual(keypair3.signing.signPk.toString(), '71,69,209,156,102,236,145,121,250,37,9,112,86,64,158,241,105,103,182,161,167,75,253,143,122,253,82,143,89,99,6,21')
    assert.strictEqual(keypair3.signing.signSk.toString(), '121,121,121,121,121,121,121,121,121,121,121,121,121,121,121,121,121,121,121,121,121,121,121,121,121,121,121,121,121,121,121,121,71,69,209,156,102,236,145,121,250,37,9,112,86,64,158,241,105,103,182,161,167,75,253,143,122,253,82,143,89,99,6,21')

    const keypair4 = iam.TallyLabIdentityProvider.keygen(seed4)
    assert.strictEqual(keypair4.publicKey.toString(), '36,203,195,127,249,160,217,199,142,25,152,27,181,197,155,56,70,168,12,80,42,45,246,117,242,77,134,3,208,106,117,86')
    assert.strictEqual(keypair4.privateKey.toString(), '96,54,154,245,68,207,207,165,161,136,232,31,222,227,91,238,175,121,140,226,34,61,252,166,31,197,116,37,96,54,244,176')
    assert.strictEqual(keypair4.signing.signPk.toString(), '186,66,69,142,131,186,121,38,186,139,143,62,154,185,202,175,15,28,73,24,221,168,197,81,8,79,122,235,16,101,183,75')
    assert.strictEqual(keypair4.signing.signSk.toString(), '122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,186,66,69,142,131,186,121,38,186,139,143,62,154,185,202,175,15,28,73,24,221,168,197,81,8,79,122,235,16,101,183,75')
  })

  it('returns security version 1.1 if a random keygen is used', () => {
    const randomKeypair = iam.TallyLabIdentityProvider.keygen()
    assert.strictEqual(randomKeypair.publicKey.length, 32)
    assert.strictEqual(randomKeypair.privateKey.length, 32)
    assert.strictEqual(randomKeypair.signing.signPk.length, 32)
    assert.strictEqual(randomKeypair.signing.signSk.length, 64)
    assert.strictEqual(randomKeypair.securityVersion, 1.1)
  })

  it('can be added to Identities as a valid identity provider', () => {
    assert(iam.Identities.isSupported(iam.TallyLabIdentityProvider.type))
  })

  it('creates a valid identity object', async () => {
    const tlKeys = iam.TallyLabIdentityProvider.keygen()
    const identity = await iam.Identities.createIdentity({
      type: 'TallyLab',
      id: tlKeys.signing.signPk.toString(),
      tlKeys
    })

    assert.strictEqual(identity.id, tlKeys.signing.signPk.toString())
    assert.strictEqual(identity.type, 'TallyLab')
    assert(identity.provider instanceof iam.Identities)
    await identity.provider._keystore.close()
  })

  it('verifies a proper identity object', async () => {
    const tlKeys = iam.TallyLabIdentityProvider.keygen()
    const identity = await iam.Identities.createIdentity({
      type: 'TallyLab',
      id: tlKeys.signing.signPk.toString(),
      tlKeys
    })

    assert(await iam.TallyLabIdentityProvider.verifyIdentity(identity))
    await identity.provider._keystore.close()
  })

  it('fails verification given an improper identity object', async () => {
    const tlKeys = iam.TallyLabIdentityProvider.keygen()
    const identity = await iam.Identities.createIdentity({
      type: 'TallyLab',
      id: tlKeys.signing.signPk.toString(),
      tlKeys
    })

    identity._id = 'bad ID'
    assert(!await iam.TallyLabIdentityProvider.verifyIdentity(identity))
    await identity.provider._keystore.close()
  })

  it('exports identity in JSON.stringified format', async () => {
    const seed = 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz'
    const keypair = iam.TallyLabIdentityProvider.keygen(seed)
    const stringified = keypair.toStringified()

    const expected = '{"privateKey":"96,54,154,245,68,207,207,165,161,136,232,31,222,227,91,238,175,121,140,226,34,61,252,166,31,197,116,37,96,54,244,176","publicKey":"36,203,195,127,249,160,217,199,142,25,152,27,181,197,155,56,70,168,12,80,42,45,246,117,242,77,134,3,208,106,117,86","signing":{"signPk":"186,66,69,142,131,186,121,38,186,139,143,62,154,185,202,175,15,28,73,24,221,168,197,81,8,79,122,235,16,101,183,75","signSk":"122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,122,186,66,69,142,131,186,121,38,186,139,143,62,154,185,202,175,15,28,73,24,221,168,197,81,8,79,122,235,16,101,183,75"},"securityVersion":"2"}'
    assert.deepStrictEqual(JSON.stringify(stringified), expected)
  })
})
