import Router from "express";

import { crearUsuario, mostrarUsuarios, mostrarUsuario, logueoUsuario} from "../controllers/users.controllers.js";


import { actualizarPoliticasRetencion, actualizarPoliticasSeguridad, actualizarTiempoIntentos } from "../controllers/users.controllers.js";
import { addIpToList, generarPDFRegistrosInicioSesion, obtenerActividadesSospechosas, obtenerRegistrosInicioSesion } from "../controllers/users.controllers.js";
import {  addParticipantes, bloquearUsuarioIntentos, crearGrupo, obtenerGrupo } from "../controllers/users.controllers.js";
import { actualizarComplejidadPreguntas, listarComplejidadPreguntas, listarPoliticasYTerminos,getLogs } from "../controllers/users.controllers.js";
import { ActualizarEstado, GETModulosYpermisos } from "../controllers/controller.modulos.permisos.js";
import {  exportarDatos, permisos } from "../controllers/users.controllers.js";

const userRout = Router();

// Rutas organizadas
// Ejecución de ruta http://localhost:3000/users/

userRout.post("/users", crearUsuario);
userRout.get("/users", mostrarUsuarios);
userRout.post('/users/login', logueoUsuario);
userRout.get("/users/:id", mostrarUsuario);
userRout.put("/users/bloquear-intentos",  bloquearUsuarioIntentos);


// Rutas desorganizadas

userRout.put("/actualizar-politicas", actualizarPoliticasSeguridad);
userRout.get("/listarPoliticasYTerminos", listarPoliticasYTerminos);
userRout.put("/actualizarComplePreguntas", actualizarComplejidadPreguntas);
userRout.get("/listarComplePreguntas", listarComplejidadPreguntas);

userRout.put("/actualizar-tiempo", actualizarTiempoIntentos);
userRout.get("/actividades-sospechosas", obtenerActividadesSospechosas);
userRout.get('/registros-inicio-sesion', obtenerRegistrosInicioSesion);
userRout.get('/registros-inicio-sesion-pdf', generarPDFRegistrosInicioSesion);
userRout.post('/addIpToList', addIpToList);
userRout.put("/actualizar-politicas", actualizarPoliticasSeguridad)

userRout.post("/datos", actualizarPoliticasRetencion);
userRout.get("/logs-prueba", getLogs)
userRout.get("/modulos", GETModulosYpermisos);
userRout.post("/estado", ActualizarEstado);
userRout.get("/exportar", exportarDatos)
userRout.get("/permisos", permisos)
userRout.put("/actualizar-politicas", actualizarPoliticasSeguridad)
userRout.post("/datos", actualizarPoliticasRetencion);

export default userRout;