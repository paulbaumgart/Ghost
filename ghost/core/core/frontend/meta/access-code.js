const crypto = require('crypto');
const getUrl = require('./url');
const _ = require('lodash');

function getAccessCode(data, settingsCache) {
    const context = data.context ? data.context : null;

    if (settingsCache && settingsCache.get('password') && _.includes(context, 'post')) {
        let hasher = crypto.createHash('sha256');
        hasher.update(getUrl(data, false).replace(/\//g, '') + settingsCache.get('password'), 'utf8');
        return hasher.digest('hex');
    }
    return null;
}

module.exports = getAccessCode;
