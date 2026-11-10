const express = require('express');
const helmet = require('helmet');
const { authenticate, authorize, signToken } = require('./auth');

const app = express();
app.use(helmet());                         // cabeceras de seguridad HTTP
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));  // limita tamaño del body

// Usuarios simulados (en producción: BD con contraseñas hasheadas con bcrypt/argon2)
const USERS = {
  admin: { username: 'admin', password: 'Admin#2024', role: 'admin' },
  alumno: { username: 'alumno', password: 'Alumno#2024', role: 'user' },
};

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = USERS[username];
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'Credenciales inválidas' });
  }
  return res.json({ token: signToken(user) });
});

app.get('/api/public', (req, res) => res.json({ mensaje: 'Endpoint público' }));

app.get('/api/profile', authenticate, (req, res) =>
  res.json({ usuario: req.user.sub, rol: req.user.role }));

app.get('/api/admin', authenticate, authorize('admin'), (req, res) =>
  res.json({ mensaje: 'Panel de administración', usuario: req.user.sub }));

app.use((req, res) => res.status(404).json({ error: 'No encontrado' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`API escuchando en puerto ${PORT}`));
