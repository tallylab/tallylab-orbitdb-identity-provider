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
 * // This registers the TLIP with Orbit to let it know it's a valid provider
 * Identities.addIdentityProvider(TallyLabIdentityProvider)
 *
 * // nacl = our current cryptography library
 * nacl_factory.instantiate(async (nacl) => {
 *
 *   // Same keygen function we're used to, in a different home
 *   const tlKeys = TallyLabIdentityProvider.keygen(nacl, 'thisisexactlythirtytwocharacters')
 *
 *   // Creates a single user identity
 *   const identity = await Identities.createIdentity({
 *     type: 'TallyLab',
 *     id: tlKeys.signing.signPk.toString(),
 *     tlKeys,
 *     nacl
 *   })
 *
 *   // Utility function to verify the identity
 *   TallyLabIdentityProvider.verifyIdentity(nacl, identity)
 * })
 * ```
 */
class TallyLabIdentityProvider {
  /**
   * Creates a new instance of TallyLabIdentityProvider. Not called directly but instead
   * passed into OrbitDB. See Usage above.
   *
   * @param {Keypair} options.tlKeys TallyLab keys
   * @param {module} options.nacl Output of `nacl_factory.instantiate`
   *
   * @returns TallyLabIdentityProvider
   */
  constructor (options) {
    this.tlKeys = options.tlKeys
  }

  /**
   * Returns the signing public key of TallyLab. Essentially the user's unique ID
   *
   * @returns {Uint8Array} TallyLab Signing Public Key
   */
  getId () { return this.tlKeys.signing.signPk.toString() }

  /**
   *  After OrbitDB signs the TallyLab keys, it passed an identity back to TallyLab
   *  in the form of a string (publicKey + idSignature), which is then signed by TL
   *
   *  @returns {Uint8Array} Signature as bytes
   */
  async signIdentity (identity, options) {
    return this.nacl.crypto_sign(identity, this.tlKeys.signing.signSk)
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
  static keygen (seed) {
    if (seed && seed.length !== 32) throw new Error('seed must be exactly 32 chars')
    const toBytes = (string) => Uint8Array.from(string.split('').map(char => char.charCodeAt(0)))

    const seedBytes = seed ? toBytes(seed) : this.prototype.nacl.random_bytes(32)
    const version = seed ? 2.0 : 1.1

    const encryptionKeys = this.prototype.nacl.crypto_box_seed_keypair(seedBytes)
    const signingKeys = this.prototype.nacl.crypto_sign_seed_keypair(seedBytes)

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
