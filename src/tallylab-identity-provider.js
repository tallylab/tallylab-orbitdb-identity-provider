const crypto = require('libp2p-crypto')
require('libp2p-crypto-secp256k1')

/**
 * > Binds a TL keypair to OrbitDB
 *
 * An OrbitDB Identity Provider is essentially a mechanism proves the ownership of
 * both the TallyLab signing keypair and the OrbitDB keypair via a process of **cross-signing**:
 *
 * 1. Sign the OrbitDB public key with the TL private key
 * 2. Sign the TL public key with the OrbitDB private key
 *
 * Additionally, this registers the TallyLab key in the OrbitDB Keystore, where key is the
 * TallyLab public signing key, and the value is the OrbitDB keypair.
 *
 * ## Usage
 *
 * ```JavaScript
 * // Requirements: js-nacl, orbit-db-keystore
 * nacl_factory.instantiate(async (nacl) => {
 *   const tlIdentities = new TallyLabIdentities()
 *   console.log(tlIdentities)
 *
 *   const keystore = Keystore.create()
 *   await keystore.open()
 *
 *   // Generate keys, either with or without a seed
 *   const seed = 'thisisexactlythirtytwocharacters'
 *   const tlKeys = tlIdentities.TallyLabIdentityProvider.keygen(nacl, seed)
 *   console.log(tlKeys)
 *
 *   // Pre-sign with the keystore
 *   const id = tlKeys.signing.signPk.toString()
 *   const key = await keystore.getKey(id) || await keystore.createKey(id)
 *
 *   // Identities work on the basis of cross-signing the OrbitDB and your provided keys
 *   const idSignature = await keystore.sign(key, id)
 *   const tlSignature = nacl.crypto_sign(idSignature, tlKeys.signing.signSk)
 *
 *   // Create an identity with the TallyLabIdentityProvider, and pass in the keystore
 *   const identity = await tlIdentities.Identities.createIdentity({
 *     type: 'TallyLab', id, tlSignature, keystore
 *   })
 *   console.log(identity)
 *
 *   TallyLabIdentityProvider.verifyIdentity(identity)
 * })
 * ```
 */
class TallyLabIdentityProvider {
  /**
   * Creates a new instance of TallyLabIdentityProvider. Not called directly but instead
   * passed into OrbitDB. See Usage above.
   *
   * @param {String} options.id Stringified representation of the public signing key
   * @param {String} options.idSignature Signature of OrbitDB public key signed by TL
   *
   * @returns TallyLabIdentityProvider
   */
  constructor (options) {
    this.id = options.id
    this.idSignature = options.idSignature
  }

  /**
   * Returns the signing public key of TallyLab. Essentially the user's unique ID
   *
   * @returns {Uint8Array} TallyLab Signing Public Key
   */
  getId () { return this.id }

  /**
   *  After OrbitDB signs the TallyLab keys, it passed an identity back to TallyLab
   *  in the form of a string (publicKey + idSignature), which is then signed by TL
   *
   *  Typically this happens inside the class but for security reasons the signature
   *  is generated beforehand and passed on as `options.tlSignature`
   *
   *  @returns {Uint8Array} Signature as bytes
   */
  async signIdentity (_, options) {
    return options.tlSignature
  }

  /**
   * Set to the string `'TallyLab'`
   */
  static get type () { return 'TallyLab' }

  /**
   * Verifies the identity by checking that the public key in identity.id
   * did, in fact, create the signature created in identity.signature.id
   */
  static async verifyIdentity (identity) {
    return new Promise((resolve, reject) => {
      const secp256k1 = crypto.keys.supportedKeys.secp256k1
      const pkBytes = Buffer.from(identity.publicKey, 'hex')
      const signature = Buffer.from(identity.signatures.id, 'hex')
      const pubKey = secp256k1.unmarshalSecp256k1PublicKey(pkBytes)

      pubKey.verify(Buffer.from(identity.id), signature, (err, valid) => {
        if (err) reject(err)
        resolve(valid)
      })
    })
  }

  /**
   * The TallyLab Identity Object returned from a successful Identities.createIdentity call
   *
   * @typedef {Object} TallyLabIdentityProvider~TallyLabIdentity
   * @property {Uint8Array} privateKey Encryption private key
   * @property {Uint8Array} publicKey Encryption public key
   * @property {Object} signing
   * @property {Uint8Array} signing.signPk Signing public key
   * @property {Uint8Array} signing.signSk Signing private key
   * @property {Number} version TallyLab security version (1.1 or 2.0)
   */

  /**
   * Generates four keys based on a seed string that is passed in from the security questions
   * flow. This functiion verfies that the seed length is exactly 32 bytes and will generate
   * a random seed if none is passed.
   *
   * Inside of the returned `keypair` object:
   * 1. A signing keypair `keypair.signing.signPk` and `keypair.signing.signSk`
   * 2. An encryption keypair, kept as `publicKey` and `keypair.privateKey` for backwards
   * compatibility.
   *
   * Security versions have been set to **1.1** for a randomly generated key and **2.0** for
   * seeded keys.
   *
   * @returns {...TallyLabIdentityProvider~TallyLabIdentity} See type definition below
   */
  static keygen (nacl, seed) {
    if (seed && seed.length !== 32) throw new Error('seed must be exactly 32 chars')

    const toBytes = (string) => {
      let data = string

      if (typeof data === 'string') {
        data = string.split('').map(char => char.charCodeAt(0))
      }

      return Uint8Array.from(data)
    }

    const seedBytes = seed ? toBytes(seed) : nacl.random_bytes(32)
    const version = seed ? 2.0 : 1.1

    const encryptionKeys = nacl.crypto_box_seed_keypair(seedBytes)
    const signingKeys = nacl.crypto_sign_seed_keypair(seedBytes)

    const Identity = function (encryptionKeys, signingKeys, version) {
      this.privateKey = encryptionKeys.boxSk
      this.publicKey = encryptionKeys.boxPk
      this.signing = signingKeys
      this.securityVersion = version
    }

    Identity.prototype.stringCompatible = {
      privateKey: encryptionKeys.boxSk.toString(),
      publicKey: encryptionKeys.boxPk.toString(),
      signing: {
        signPk: signingKeys.signPk.toString(),
        signSk: signingKeys.signSk.toString()
      },
      securityVersion: version.toString()
    }

    const identity = new Identity(encryptionKeys, signingKeys, version)

    return identity
  }
}

module.exports = TallyLabIdentityProvider
