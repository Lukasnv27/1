const crypto = require('crypto');

// Symmetric Encryption/Decryption Algorithms 
// Advanced Encryption Standard with different key length of bits
// AES-128: 'aes-128-cbc'
// AES-192: 'aes-192-cbc'
// AES-256: 'aes-256-cbc'

// Encrypt
const algorithm = 'aes-256-cbc';
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);
const cipher = crypto.createCipheriv(algorithm, key, iv);
let encryptedData = cipher.update('Hello, World!', 'utf-8', 'hex');
encryptedData += cipher.final('hex');

// Decrypt
const decipher = crypto.createDecipheriv(algorithm, key, iv);
let decryptedData = decipher.update(encryptedData, 'hex', 'utf-8');
decryptedData += decipher.final('utf-8');

// Print
console.log('Key:', key.toString('hex'));
console.log('IV:', iv.toString('hex'));
console.log('Encrypted:', encryptedData);
console.log('Decrypted:', decryptedData);
