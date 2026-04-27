const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const fs = require('fs');
const readline = require('readline');

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

rl.question('Choose a password for Claude Pilot: ', async (password) => {
  if (password.length < 6) {
    console.error('Password must be at least 6 characters.');
    process.exit(1);
  }
  const hash = await bcrypt.hash(password, 12);
  const secret = crypto.randomBytes(48).toString('hex');
  const env = `PORT=3000\nJWT_SECRET=${secret}\nPASSWORD_HASH=${hash}\n`;
  fs.writeFileSync('.env', env);
  console.log('\n.env file created.');
  console.log('Start the server with: npm start');
  rl.close();
});
