const crypto = require('crypto');

// Hash Algorithms
// MD5: 'md5'
// SHA-1: 'sha1'
// SHA-256: 'sha256'
// SHA-512: 'sha512'

// Hashing
const hash = crypto.createHash('sha256');
const data = 'Hello, World!';
const hashedData = hash.update(data, 'utf-8').digest('hex');

// Print
console.log('Data:', data);
console.log('Hashed Data:', hashedData);