const getUrl = require('./url');
const _ = require('lodash');
const { hashPathAccessCode } = require('../../shared/private-site-access');

function getAccessCode(data, settingsCache) {
  const context = data.context ? data.context : null;
  const password = settingsCache ? settingsCache.get('password') : null;
  if (!password) {
    return null;
  }

  if (settingsCache && settingsCache.get('is_private') && _.includes(context, 'post')) {
    const rawUrl = getUrl(data, false) || '';
    return hashPathAccessCode(password, rawUrl);
  }
  return null;
}

module.exports = getAccessCode;
