/**
 * Cryptographic term dictionary.
 *
 * Ported from the IBM / PQCA `cbomkit` viewer's `crypto-dictionary.json`
 * (https://github.com/PQCA/cbomkit) so the Blindspot CBOM visualizer resolves
 * short CycloneDX codes to the same human-readable names and descriptions the
 * reference viewer shows. Keeping the mapping identical is what makes our
 * visualizer's labels match the CycloneDX CBOM viewer at zurich.ibm.com/cbom.
 *
 * Content was rephrased/condensed only where noted; term full names are kept
 * verbatim because they are the canonical CycloneDX vocabulary.
 */

export interface CryptoTerm {
  fullName: string;
  description: string;
}

export const CRYPTO_DICTIONARY: Record<string, CryptoTerm> = {
  other: { fullName: 'Other', description: 'Another case.' },
  unknown: { fullName: 'Unknown', description: 'This case is not known.' },

  // --- Asset types ---------------------------------------------------------
  algorithm: {
    fullName: 'Algorithm',
    description:
      'Mathematical function commonly used for data encryption, authentication, and digital signatures.',
  },
  certificate: {
    fullName: 'Certificate',
    description:
      'An electronic document that is used to provide the identity or validate a public key.',
  },
  protocol: {
    fullName: 'Protocol',
    description:
      'A set of rules and guidelines that govern the behavior and communication with each other.',
  },
  'related-crypto-material': {
    fullName: 'Related Crypto Material',
    description:
      'Other cryptographic assets related to algorithms, certificates, and protocols such as keys and tokens.',
  },

  // --- Primitives ----------------------------------------------------------
  drbg: {
    fullName: 'Deterministic Random Bit Generator',
    description:
      'A pseudorandom number generator that produces a sequence of bits from an initial seed value, used where reproducibility of random values matters.',
  },
  mac: {
    fullName: 'Message Authentication Code',
    description:
      'Information used for authenticating and integrity-checking a message.',
  },
  'block-cipher': {
    fullName: 'Block Cipher',
    description:
      'A symmetric key algorithm that operates on fixed-size blocks of data to provide confidentiality.',
  },
  'stream-cipher': {
    fullName: 'Stream Cipher',
    description:
      'A symmetric key cipher where plaintext digits are combined with a pseudorandom keystream.',
  },
  signature: {
    fullName: 'Digital Signature',
    description:
      'A cryptographic value calculated from the data and a key known only by the signer.',
  },
  hash: {
    fullName: 'Hash Function',
    description:
      'An algorithm that maps an input to a fixed-size value, used for integrity verification and password hashing.',
  },
  pke: {
    fullName: 'Public Key Encryption',
    description:
      'Encryption using a public/private key pair: the public key encrypts and the private key decrypts.',
  },
  xof: {
    fullName: 'Extendable Output Function',
    description:
      'A function that takes arbitrary input and produces an output stream up to a limit set by its internal state.',
  },
  kdf: {
    fullName: 'Key Derivation Function',
    description:
      'Derives key material from another source of entropy while preserving that entropy.',
  },
  'key-agree': {
    fullName: 'Key Agreement',
    description:
      'A protocol where two or more parties agree on a cryptographic key such that both influence the outcome.',
  },
  kem: {
    fullName: 'Key Encapsulation Mechanism',
    description:
      "A mechanism for transporting random keying material to a recipient using the recipient's public key.",
  },
  ae: {
    fullName: 'Authenticated Encryption',
    description:
      'A process that provides both confidentiality and data integrity for the encrypted data.',
  },
  combiner: {
    fullName: 'Cryptographic Combiner',
    description:
      'Aggregates several candidates for a cryptographic primitive to generate a new candidate for the same primitive.',
  },

  // --- Crypto functions ----------------------------------------------------
  generate: {
    fullName: 'Key Generation',
    description: 'The process of creating cryptographic keys for use in security protocols.',
  },
  sign: {
    fullName: 'Digital Signature Generation',
    description: 'Creating a digital signature using a private key.',
  },
  verify: {
    fullName: 'Digital Signature Verification',
    description: 'Confirming the authenticity and integrity of a message by checking its signature.',
  },
  keygen: {
    fullName: 'Key Pair Generation',
    description: 'Creating a pair of cryptographic keys, typically a public and a private key.',
  },
  encrypt: {
    fullName: 'Encryption',
    description: 'Converting plaintext into ciphertext using an algorithm and a key.',
  },
  decrypt: {
    fullName: 'Decryption',
    description: 'Converting ciphertext back into plaintext using an algorithm and a key.',
  },
  encapsulate: {
    fullName: 'Key Encapsulation',
    description: "Securely transmitting a key by encrypting it with the receiver's public key.",
  },
  decapsulate: {
    fullName: 'Key Decapsulation',
    description: "Retrieving an encapsulated key by decrypting it with the recipient's private key.",
  },
  digest: { fullName: 'Digest', description: 'The output of the hash function.' },
  keyderive: {
    fullName: 'Key Derivation',
    description: 'Deriving key material from an existing source of entropy.',
  },
  tag: {
    fullName: 'Tag',
    description:
      'A message authentication code used for authenticating and integrity-checking a message.',
  },

  // --- Execution environment ----------------------------------------------
  'software-plain-ram': {
    fullName: 'Software Plain RAM',
    description: 'A software implementation running in plain unencrypted RAM.',
  },
  'software-encrypted-ram': {
    fullName: 'Software Encrypted RAM',
    description: 'A software implementation running in encrypted RAM.',
  },
  'software-tee': {
    fullName: 'Software Trusted Execution Environment',
    description: 'A software implementation running in a trusted execution environment.',
  },
  hardware: { fullName: 'Hardware', description: 'A hardware implementation.' },

  // --- Certification levels (FIPS 140) ------------------------------------
  'fips140-1-l1': { fullName: 'FIPS 140-1 Level 1', description: 'FIPS 140-1 Level 1' },
  'fips140-1-l2': { fullName: 'FIPS 140-1 Level 2', description: 'FIPS 140-1 Level 2' },
  'fips140-1-l3': { fullName: 'FIPS 140-1 Level 3', description: 'FIPS 140-1 Level 3' },
  'fips140-1-l4': { fullName: 'FIPS 140-1 Level 4', description: 'FIPS 140-1 Level 4' },
  'fips140-2-l1': { fullName: 'FIPS 140-2 Level 1', description: 'FIPS 140-2 Level 1' },
  'fips140-2-l2': { fullName: 'FIPS 140-2 Level 2', description: 'FIPS 140-2 Level 2' },
  'fips140-2-l3': { fullName: 'FIPS 140-2 Level 3', description: 'FIPS 140-2 Level 3' },
  'fips140-2-l4': { fullName: 'FIPS 140-2 Level 4', description: 'FIPS 140-2 Level 4' },
  'fips140-3-l1': { fullName: 'FIPS 140-3 Level 1', description: 'FIPS 140-3 Level 1' },
  'fips140-3-l2': { fullName: 'FIPS 140-3 Level 2', description: 'FIPS 140-3 Level 2' },
  'fips140-3-l3': { fullName: 'FIPS 140-3 Level 3', description: 'FIPS 140-3 Level 3' },
  'fips140-3-l4': { fullName: 'FIPS 140-3 Level 4', description: 'FIPS 140-3 Level 4' },

  // --- Cipher modes --------------------------------------------------------
  cbc: {
    fullName: 'Cipher Block Chaining (CBC) Mode',
    description:
      'A block cipher mode that chains each ciphertext block with the previous block before encryption.',
  },
  ecb: {
    fullName: 'Electronic Codebook (ECB) Mode',
    description:
      'A block cipher mode that encrypts each block independently; generally not recommended for secure use.',
  },
  ccm: {
    fullName: 'Counter with CBC-MAC (CCM) Mode',
    description:
      'A block cipher mode providing both encryption and integrity protection.',
  },
  gcm: {
    fullName: 'Galois/Counter Mode (GCM)',
    description:
      'A block cipher mode providing confidentiality and authentication, widely used in TLS.',
  },
  cfb: {
    fullName: 'Cipher Feedback (CFB) Mode',
    description: 'A block cipher mode that encrypts data in units smaller than the block size.',
  },
  ofb: {
    fullName: 'Output Feedback (OFB) Mode',
    description: 'A block cipher mode that turns a block cipher into a synchronous stream cipher.',
  },
  ctr: {
    fullName: 'Counter (CTR) Mode',
    description:
      'A block cipher mode that turns a block cipher into a stream cipher, allowing parallel processing.',
  },

  // --- Padding -------------------------------------------------------------
  raw: {
    fullName: 'Raw',
    description: 'A simple padding scheme where input data is padded without a specific structure.',
  },
  pkcs7: {
    fullName: 'PKCS#7',
    description: 'A padding scheme that adds bytes so the total length is a multiple of the block size.',
  },
  oaep: {
    fullName: 'Optimal Asymmetric Encryption Padding (OAEP) for RSA',
    description: 'A randomized padding scheme designed for RSA encryption.',
  },
  pkcs5: {
    fullName: 'PKCS#5',
    description: 'A padding scheme for 8-byte block ciphers; a subset of PKCS#7.',
  },
  pkcs1v15: {
    fullName: 'PKCS#1 v1.5',
    description:
      'A padding scheme used in RSA encryption and signing, largely superseded by OAEP.',
  },

  // --- Related crypto material --------------------------------------------
  'private-key': {
    fullName: 'Private Key',
    description: 'The confidential key of a key pair used in asymmetric cryptography.',
  },
  'public-key': {
    fullName: 'Public Key',
    description: 'The non-confidential key of a key pair used in asymmetric cryptography.',
  },
  'secret-key': {
    fullName: 'Secret Key',
    description: 'A key used to encrypt and decrypt messages in symmetric cryptography.',
  },
  key: {
    fullName: 'Key',
    description:
      'A piece of information that, processed through a cryptographic algorithm, processes cryptographic data.',
  },
  ciphertext: {
    fullName: 'Ciphertext',
    description: 'The result of encryption performed on plaintext using a cipher.',
  },
  'initialization-vector': {
    fullName: 'Initialization Vector',
    description: 'A fixed-size random or pseudo-random input parameter for cryptographic algorithms.',
  },
  nonce: {
    fullName: 'Nonce',
    description: 'A number that can only be used once in a cryptographic communication.',
  },
  seed: {
    fullName: 'Seed',
    description: 'The input to a pseudo-random number generator.',
  },
  salt: {
    fullName: 'Salt',
    description:
      'A value used in a cryptographic process so results for one instance cannot be reused by an attacker.',
  },
  'shared-secret': {
    fullName: 'Shared Secret',
    description: 'Data known only to the parties involved in a secure communication.',
  },
  'additional-data': {
    fullName: 'Additional Data',
    description: 'An unspecified collection of data relevant to cryptographic activity.',
  },
  password: {
    fullName: 'Password',
    description: 'A secret sequence of characters used during authentication or authorization.',
  },
  credential: {
    fullName: 'Credential',
    description: 'Establishes the identity of a party, usually as cryptographic keys or passwords.',
  },
  token: { fullName: 'Token', description: 'An object encapsulating a security identity.' },

  // --- Protocols -----------------------------------------------------------
  tls: { fullName: 'Transport Layer Security', description: 'Transport Layer Security' },
  ssh: { fullName: 'Secure Shell', description: 'Secure Shell' },
  ipsec: { fullName: 'Internet Protocol Security', description: 'Internet Protocol Security' },
  ike: { fullName: 'Internet Key Exchange', description: 'Internet Key Exchange' },
  sstp: { fullName: 'Secure Socket Tunneling Protocol', description: 'Secure Socket Tunneling Protocol' },
  wpa: { fullName: 'Wi-Fi Protected Access', description: 'Wi-Fi Protected Access' },
};

/**
 * Full name for a CycloneDX crypto term, or `undefined` when unknown.
 * Mirrors cbomkit's `getTermFullName`.
 */
export function getTermFullName(termName: unknown): string | undefined {
  if (typeof termName !== 'string') {
    return undefined;
  }
  return CRYPTO_DICTIONARY[termName]?.fullName;
}

/** Description for a CycloneDX crypto term, or `undefined` when unknown. */
export function getTermDescription(termName: unknown): string | undefined {
  if (typeof termName !== 'string') {
    return undefined;
  }
  return CRYPTO_DICTIONARY[termName]?.description;
}

/**
 * Display label: the dictionary full name when known, otherwise the raw term.
 * This is the value shown in the visualizer's table cells and charts.
 */
export function displayTerm(termName: unknown): string {
  if (termName === null || termName === undefined || termName === '') {
    return '';
  }
  const raw = String(termName);
  return getTermFullName(raw) ?? raw;
}
