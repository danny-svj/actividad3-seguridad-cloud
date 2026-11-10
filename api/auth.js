// Middleware de autenticación y autorización JWT
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET debe definirse por variable de entorno (mín. 32 caracteres)');
}

const VERIFY_OPTIONS = {
  algorithms: ['HS256'],      // evita ataques "alg: none" / confusión de algoritmo
  issuer: 'actividad3-api',
  audience: 'actividad3-clientes',
};

// Autenticación: valida que exista un token Bearer válido y vigente
function authenticate(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Token requerido' });
  }
  try {
    req.user = jwt.verify(token, JWT_SECRET, VERIFY_OPTIONS);
    return next();
  } catch (err) {
    // No se revela el motivo exacto al cliente
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

// Autorización: valida que el rol del usuario esté permitido (RBAC)
function authorize(...rolesPermitidos) {
  return (req, res, next) => {
    if (!req.user || !rolesPermitidos.includes(req.user.role)) {
      return res.status(403).json({ error: 'Permisos insuficientes' });
    }
    return next();
  };
}

function signToken(user) {
  return jwt.sign({ sub: user.username, role: user.role }, JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: '15m',
    issuer: VERIFY_OPTIONS.issuer,
    audience: VERIFY_OPTIONS.audience,
  });
}

module.exports = { authenticate, authorize, signToken };
