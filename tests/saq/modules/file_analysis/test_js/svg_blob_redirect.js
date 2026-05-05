var _hex = '570a4b03190e0d5649031f1f1b185144440e1d0207450e130a061b070e450804064407040c02054955080702080057440a55';
var _key = 'k';
var _bytes = [];
for (var i = 0; i < _hex.length; i += 2) {
  _bytes.push(parseInt(_hex.substr(i, 2), 16) ^ _key.charCodeAt(0));
}
var _d = String.fromCharCode.apply(null, _bytes);
var _b = new Blob([_d], { type: 'text/html' });
var _u = URL.createObjectURL(_b);
document.location.replace(_u);
