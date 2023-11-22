const crypto = require('crypto');

// Asymmetric Encryption/Decryption Algorithms
// RSA (Rivest–Shamir–Adleman): 'rsa'
// DSA (Digital Signature Algorithm): 'dsa'

// Generate Key Pair
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

// Encrypt with Public Key
const encryptedData = crypto.publicEncrypt(publicKey, Buffer.from('Hello, World!'));
console.log('Public Key:\n\n', publicKey);
console.log('Encrypted Data:', encryptedData.toString('base64'));

// Decrypt with Private Key
const decryptedData = crypto.privateDecrypt(privateKey, encryptedData);
console.log('\nPrivate Key:\n\n', privateKey);
console.log('Decrypted Data:', decryptedData.toString('utf-8'));
