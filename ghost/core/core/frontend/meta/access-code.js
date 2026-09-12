const crypto = require('crypto');
const getUrl = require('./url');
const _ = require('lodash');

function getAccessCode(data, settingsCache) {
    const context = data.context ? data.context : null;
    const password = settingsCache ? settingsCache.get('password') : null;
    if (!password) {
        return null;
    }

    if (settingsCache && settingsCache.get('is_private') && _.includes(context, 'post')) {
        const rawUrl = getUrl(data, false) || '';
        const normalizedPath = rawUrl.toLowerCase().replace(/^\/+|\/+$/g, '');
        return crypto
            .createHmac('sha256', password)
            .update(`access_code:${normalizedPath}`)
            .digest('hex');
    }
    return null;
}

module.exports = getAccessCode;
