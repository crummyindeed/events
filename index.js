const crypto = require('crypto');
const EdDSA = require('elliptic').eddsa;
const ec = new EdDSA('ed25519');

var Events = Events || {};

Events.simpleSign = function (content, private) {
  var key = ec.keyFromSecret(private);
  var public = key.getPublic('hex');

  var body = public + JSON.stringify(content);
  var hash = crypto.createHash('sha256');
  hash.update(body);

  var digest = hash.digest('hex');
  var signature = key.sign(digest).toHex();

  var message = JSON.stringify({
    iss: public,
    cnt: content,
    dig: digest,
    sig: signature
  });

  return message;
};

Events.create = function ({ type, payload, left, right }, private) {
  var key = ec.keyFromSecret(private);
  var public = key.getPublic('hex');

  var eventBody = public + type + JSON.stringify(payload) + left + right;
  var hash = crypto.createHash('sha256');
  hash.update(eventBody);

  var digest = hash.digest('hex');
  var signature = key.sign(digest).toHex();
  var proof = createPoW(digest);

  var event = JSON.stringify({
    iss: public,
    typ: type,
    pay: payload,
    lt: left,
    rt: right,
    dig: digest,
    sig: signature,
    pow: proof
  });

  return event;
};

Events.validate = function (event) {
  var event = JSON.parse(event);
  //this is not confirming, just verifying the signature, hash and formation
  if (typeof event.iss == 'undefined') { return false; }
  if (typeof event.typ == 'undefined') { return false; }
  if (typeof event.pay == 'undefined') { return false; }
  if (typeof event.lt == 'undefined') { return false; }
  if (typeof event.rt == 'undefined') { return false; }
  if (typeof event.sig == 'undefined') { return false; }
  if (typeof event.dig == 'undefined') { return false; }
  if (typeof event.pow == 'undefined') { return false; }

  if (verifyPoW(event.pow, event.dig) === false) { return false; }

  var eventBody = event.iss + event.typ + JSON.stringify(event.pay) + event.lt + event.rt;
  var hash = crypto.createHash('sha256');
  hash.update(eventBody);

  var digest = hash.digest('hex');
  if (digest !== event.dig) { return false; }

  var key = ec.keyFromPublic(event.iss, 'hex');
  var result = key.verify(event.dig, event.sig);
  return result;
}

var createPoW = function (digest) {
  var version = 1;
  var bits = 20;
  let dt = new Date();
  var date = dt.getFullYear() + (dt.getMonth() + 1).toString().padStart(2, '0') + (dt.getDate()).toString().padStart(2, '0') + (dt.getHours() + 1).toString().padStart(2, '0') + (dt.getMinutes() + 1).toString().padStart(2, '0') + (dt.getSeconds() + 1).toString().padStart(2, '0');
  var ext = '';
  var rand = crypto.randomBytes(16).toString('base64');
  var resource = digest;

  var base = [version, bits, date, resource, ext, rand].join(':');

  for (let i = 0; i < 4828869; i++) { //how many tries should it take?
    var pow = base + ':' + i;
    var hash = crypto.createHash('sha1');
    hash.update(pow);
    var check = hash.digest('hex');
    if (check.match(/^0{5}/)) {
      return pow;
    }
  }
}

Events.simpleValidate = function (message) {
  var message = JSON.parse(message);
  if (typeof message.iss == 'undefined') { return false; }
  if (typeof message.cnt == 'undefined') { return false; }
  if (typeof message.sig == 'undefined') { return false; }
  if (typeof message.dig == 'undefined') { return false; }

  var body = message.iss + JSON.stringify(message.cnt);
  var hash = crypto.createHash('sha256');
  hash.update(body);

  var digest = hash.digest('hex');
  if (digest !== message.dig) { return false; }

  var key = ec.keyFromPublic(message.iss, 'hex');
  var result = key.verify(message.dig, message.sig);

  return result;
}

var verifyPoW = function (pow, digest) {
  var parts = pow.split(':');
  if (parts[3] != digest) {
    return false;
  }
  var hash = crypto.createHash('sha1');
  hash.update(pow);
  if (hash.digest('hex').match(/^0{5}/)) {
    return true;
  } else {
    return false;
  }
}

module.exports = Events;