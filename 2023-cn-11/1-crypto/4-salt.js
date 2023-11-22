const crypto = require('crypto');

// Hash Algorithms
// MD5: 'md5'
// SHA-1: 'sha1'
// SHA-256: 'sha256'
// SHA-512: 'sha512'

// Function to generate a random salt
const generateSalt = () => {
    return crypto.randomBytes(16).toString('hex');
};
  
// Function to hash a password with a salt
const hashPassword = (password, salt) => {
    const hash = crypto.createHash('sha256');
    hash.update(password + salt, 'utf-8');
    return hash.digest('hex');
};

// Hashing with salt (generates new salt every time)
const password = 'minHundHedderTorben10';
const salt = generateSalt();
const hashedPassword = hashPassword(password, salt);

// Print
console.log('Password:', password);
console.log('Salt:', salt);
console.log('Hashed Password:', hashedPassword);