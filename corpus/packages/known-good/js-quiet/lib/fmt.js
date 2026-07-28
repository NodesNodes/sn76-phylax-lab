const { execSync } = require('child_process');

exports.gitVersion = () => execSync('git describe --tags').toString().trim();
