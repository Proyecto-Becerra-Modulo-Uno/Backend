import session from 'express-session'; 
import { error } from "../messages/browser.js"; 
import jwt from 'jsonwebtoken';
import { config } from 'dotenv';
config();


export const verifyToken = (req, res, next) => {
  const authHeader = req.headers['x-access-token'] || req.headers['authorization'];
  const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : authHeader;

  if (!token) {
      return error(req, res, 403, 'Token not provided.');
  }

  jwt.verify(token, process.env.TOKENPRIVATEKEY, (err, decoded) => {
      if (err) {  
          return error(req, res, 401, err.message);
      }
      req.userEmail = decoded.correo; // Añadir el correo del usuario al `req`
      next();
  });
};


// Tiempo de Expiracion
const sessionConfig = session({
    secret: process.env.SESSION_SECRET, 
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 3600000 // 1 hora
    }
});

export default sessionConfig;


const checkIPAccess = async (req, res, next) => {
  try {
    const whitelist = JSON.parse(await fs.readFile(IP_WHITELIST_FILE, 'utf8'));
    const clientIP = req.ip;

    if (whitelist.includes(clientIP)) {
      next();
    } else {
      res.status(403).json({ error: 'Acceso denegado' });
    }
  } catch (error) {
    console.error('Error al leer la lista blanca de IPs:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
};
