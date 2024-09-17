import { Router } from "express";
import { verifyToken } from "../middlewares/oauth.js";
import { logueoUsuario, validarToken } from "../controllers/userController.js";
import { actualizarPoliticasBloqueo } from "../controllers/blockingPoliciesController.js"; // Importa el controlador
import { desbloquearUsuario, listarBloqueos } from "../controllers/controllers.js";
import { backupDatabase, restoreDatabase, listBackups, listUserBackups, backupUserData, restoreUserData } from "../controllers/backupController.js";
import { getAllCertificates, renewCertificate } from "../controllers/certificateController.js";

const rutaAdmin = Router();

// rutaAdmin.get("/", () => {});

rutaAdmin.get("/oauth", verifyToken, validarToken);

rutaAdmin.get("/bloqueos", listarBloqueos);

rutaAdmin.put("/desbloqueo", desbloquearUsuario);

rutaAdmin.post("/login", logueoUsuario);

// Nueva ruta para actualizar las políticas de bloqueo
rutaAdmin.post("/update-blocking-policies", verifyToken, actualizarPoliticasBloqueo);


rutaAdmin.get("/token", verifyToken);
rutaAdmin.get('/user-backups', listUserBackups);
rutaAdmin.post('/user-backup', backupUserData);
rutaAdmin.post('/restore-users', restoreUserData);
rutaAdmin.get('/backups', listBackups);
rutaAdmin.post('/backup', backupDatabase);
rutaAdmin.post('/restore', restoreDatabase);
rutaAdmin.get('/certificates', getAllCertificates);
rutaAdmin.post('/certificates/renew/:id', renewCertificate);

export default rutaAdmin;
