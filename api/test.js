// Pruebas de autenticación/autorización contra la API en ejecución
const BASE = process.env.BASE || 'http://localhost:3000';
const jwt = require('jsonwebtoken');
const call = async (path, opts = {}) => {
  const r = await fetch(BASE + path, opts);
  return r.status;
};
const login = async (u, p) => (await (await fetch(BASE + '/api/login', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: u, password: p }) })).json()).token;
(async () => {
  const admin = await login('admin', 'Admin#2024');
  const user = await login('alumno', 'Alumno#2024');
  const forged = jwt.sign({ sub: 'x', role: 'admin' }, 'secreto-falso-de-atacante-123456789',
    { issuer: 'actividad3-api', audience: 'actividad3-clientes' });
  const none = Buffer.from('{"alg":"none","typ":"JWT"}').toString('base64url') + '.' +
    Buffer.from('{"sub":"x","role":"admin"}').toString('base64url') + '.';
  const casos = [
    ['GET /api/public sin token', '/api/public', null, 200],
    ['GET /api/admin sin token', '/api/admin', null, 401],
    ['GET /api/admin token falsificado', '/api/admin', forged, 401],
    ['GET /api/admin alg=none', '/api/admin', none, 401],
    ['GET /api/admin rol user', '/api/admin', user, 403],
    ['GET /api/admin rol admin', '/api/admin', admin, 200],
    ['GET /api/profile rol user', '/api/profile', user, 200],
  ];
  let ok = true;
  for (const [n, p, t, esperado] of casos) {
    const s = await call(p, t ? { headers: { Authorization: 'Bearer ' + t } } : {});
    const pass = s === esperado; ok &&= pass;
    console.log(`${pass ? 'PASS' : 'FAIL'}  ${n.padEnd(36)} esperado=${esperado} obtenido=${s}`);
  }
  process.exit(ok ? 0 : 1);
})();
