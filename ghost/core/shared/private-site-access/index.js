const crypto = require('crypto');
const session = require('cookie-session');
const settingsCache = require('../settings-cache');

const sessionOptions = {
  name: 'ghost-private',
  maxAge: 3650 * 24 * 60 * 60 * 1000,
  signed: false,
};

// Browsers reject `SameSite=None` cookies that aren't also marked `Secure`, so
// only use it when the site is served over HTTPS.
const secureSession = session({ ...sessionOptions, sameSite: 'none' });
const insecureSession = session({ ...sessionOptions, sameSite: 'strict' });

function getAccessCode() {
  const accessCode = settingsCache.get('password');
  return typeof accessCode === 'string' ? accessCode : '';
}

function hasAccessCode(accessCode) {
  return typeof accessCode === 'string' && accessCode.trim().length > 0;
}

function getSessionSecret() {
  const secret = settingsCache.get('theme_session_secret');
  return typeof secret === 'string' ? secret : '';
}

// The ghost-private cookie is unsigned, so the token must depend on a server-held
// secret. Otherwise anyone could compute a valid token for a guessed access code
// and use every gated request as an unthrottled guessing oracle.
function hashAccessCode(accessCode, salt, secret) {
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(`ghost-private:${accessCode}:${salt}`, 'utf8');
  return hmac.digest('hex');
}

/**
 * Hash of the site access code bound to a single URL path, used for shareable
 * links that grant access to one page of a private site.
 */
function hashPathAccessCode(accessCode, pathname) {
  const normalizedPath = String(pathname || '')
    .toLowerCase()
    .replace(/^\/+|\/+$/g, '');

  return crypto
    .createHmac('sha256', accessCode)
    .update(`access_code:${normalizedPath}`)
    .digest('hex');
}

function hasValidPathAccessCode(req) {
  if (!req || !req.path || !req.query || !req.query.access_code) {
    return false;
  }

  const accessCode = getAccessCode();
  if (!hasAccessCode(accessCode)) {
    return false;
  }

  const expected = Buffer.from(hashPathAccessCode(accessCode, req.path), 'utf8');
  const provided = Buffer.from(String(req.query.access_code), 'utf8');

  if (expected.length !== provided.length) {
    return false;
  }

  return crypto.timingSafeEqual(expected, provided);
}

function hasAccess(req) {
  if (hasValidPathAccessCode(req)) {
    return true;
  }

  const accessCode = getAccessCode();
  const salt = req.session?.salt || '';
  const hash = req.session?.token || '';
  const secret = getSessionSecret();

  if (
    typeof salt !== 'string' ||
    typeof hash !== 'string' ||
    !salt ||
    !hash ||
    !secret ||
    !hasAccessCode(accessCode)
  ) {
    return false;
  }

  const expected = Buffer.from(hashAccessCode(accessCode, salt, secret));
  const actual = Buffer.from(hash);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function grantAccess(req, submittedAccessCode) {
  const accessCode = getAccessCode();
  const secret = getSessionSecret();

  if (
    !secret ||
    !hasAccessCode(accessCode) ||
    !hasAccessCode(submittedAccessCode) ||
    accessCode !== submittedAccessCode
  ) {
    return false;
  }

  const salt = Date.now().toString();
  req.session.token = hashAccessCode(submittedAccessCode, salt, secret);
  req.session.salt = salt;
  return true;
}

function loadSession(req, res, next) {
  const isPrivateBlog = settingsCache.get('is_private');

  if (!isPrivateBlog) {
    res.isPrivateBlog = false;
    return next();
  }

  res.isPrivateBlog = true;

  const privateSession = req.protocol === 'https' ? secureSession : insecureSession;
  return privateSession(req, res, next);
}

module.exports = {
  grantAccess,
  hasAccess,
  hashPathAccessCode,
  hasValidPathAccessCode,
  loadSession,
};
