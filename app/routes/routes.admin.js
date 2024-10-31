import { Router } from "express";
import { verifyToken } from "../middlewares/oauth.js";

import { asignarRolUsuario, bloquearUsuario, desbloquearUsuario, listarBloqueos, registroInicioSesion, listarPoliticasSeguridad, listarSesiones} from "../controllers/admin.controllers.js";

import { crearGrupo, addParticipantes, obtenerGrupo, listar_grupos } from "../controllers/groups.controllers.js";

import { updatePhoneNumber, validarToken } from "../controllers/users.controllers.js";
import { backupDatabase, restoreDatabase, listBackups, listUserBackups, backupUserData, restoreUserData } from "../controllers/backupController.js";
import { getAllCertificates, renewCertificate } from "../controllers/certificateController.js";
import { crear_intervalo_contrasena} from "../controllers/users.controllers.js";
import { contarActividadesPorDia, contarAdministradoresPorEstado, contarCertificadosPorEstado, obtenerActividadesSospechosas, obtenerAdministradoresActivos, obtenerEstadoCertificados, obtenerPoliticasBloqueo } from "../controllers/securityController.js";

const rutaAdmin = Router();

// Rutas organizadas

rutaAdmin.post('/admin/asignar-rol', asignarRolUsuario);
rutaAdmin.put("/admin/estado/:id", bloquearUsuario);
rutaAdmin.put("/admin/desbloquear-usuario", desbloquearUsuario);
rutaAdmin.get("/admin/cuentas-bloqueadas", listarBloqueos);
// Historial de sesiones iniciadas
rutaAdmin.post("/admin/historial-sesion", registroInicioSesion);
// Politicas de contraseñas
rutaAdmin.get("/admin/listar-politicas", listarPoliticasSeguridad);
// Rutas para grupos

rutaAdmin.post("/admin/crear-grupo", crearGrupo);
rutaAdmin.post("/admin/añadir-integrante", addParticipantes);
rutaAdmin.get("/admin/ultimo-grupo", obtenerGrupo);
rutaAdmin.get("/admin/listar-grupos", listar_grupos);
rutaAdmin.get("/admin/lista-sesiones", listarSesiones)
rutaAdmin.get("/oauth", verifyToken, validarToken);
rutaAdmin.post('/admin/restore-users', restoreUserData);

// Nueva ruta para actualizar las políticas de bloqueo
rutaAdmin.post("/update-blocking-policies", verifyToken, actualizarPoliticasBloqueo);

// Rutas desorganizadas

rutaAdmin.get("/token", verifyToken);
rutaAdmin.get('/user-backups', listUserBackups);
rutaAdmin.post('/user-backup', backupUserData);
rutaAdmin.get('/backups', listBackups);
rutaAdmin.post('/backup', backupDatabase);
rutaAdmin.post('/restore', restoreDatabase);
rutaAdmin.get('/certificates', getAllCertificates);
rutaAdmin.post('/certificates/renew/:id', renewCertificate);
rutaAdmin.post("/oauth", verifyToken, validarToken)
rutaAdmin.get("/oauth", verifyToken, validarToken)
rutaAdmin.put("/actualizar-intervalo", crear_intervalo_contrasena)
rutaAdmin.put("/update-phone", verifyToken, updatePhoneNumber);


// Ruta para obtener actividades sospechosas
rutaAdmin.get('/actividades-sospechosas', obtenerActividadesSospechosas);

// Ruta para contar actividades por día
rutaAdmin.get('/actividades-por-dia', contarActividadesPorDia);

// Ruta para obtener el estado de los certificados
rutaAdmin.get('/estado-certificados', obtenerEstadoCertificados);

// Ruta para contar certificados por estado
rutaAdmin.get('/certificados-por-estado', contarCertificadosPorEstado);

// Ruta para obtener administradores activos
rutaAdmin.get('/administradores-activos', obtenerAdministradoresActivos);

// Ruta para contar administradores por estado
rutaAdmin.get('/administradores-por-estado', contarAdministradoresPorEstado);

// Ruta para obtener políticas de bloqueo
rutaAdmin.get('/politicas-bloqueo', obtenerPoliticasBloqueo);

export default rutaAdmin;
