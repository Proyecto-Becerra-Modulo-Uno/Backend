import { Router } from "express";
import { verifyToken } from "../middlewares/oauth.js";
import {
  backupDatabase,
  restoreDatabase,
  listBackups,
  listUserBackups,
  backupUserData,
  restoreUserData,
} from "../controllers/backupController.js";
import {
  getAllCertificates,
  renewCertificate,
} from "../controllers/certificateController.js";
import { historial } from "../controllers/historialControlador.js";

const rutaAdmin = Router();

rutaAdmin.get("/token", verifyToken);
rutaAdmin.get("/user-backups", listUserBackups);
rutaAdmin.post("/user-backup", backupUserData);
rutaAdmin.post("/restore-users", restoreUserData);
rutaAdmin.get("/backups", listBackups);
rutaAdmin.post("/backup", backupDatabase);
rutaAdmin.post("/restore", restoreDatabase);
rutaAdmin.get("/certificates", getAllCertificates);
rutaAdmin.post("/certificates/renew/:id", renewCertificate);
rutaAdmin.get("/historial_todo", historial);

export default rutaAdmin;
