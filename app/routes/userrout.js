import Router from "express";
import { asignarRolUsuario, changeUserStatus, crearUsuario, listarUser } from "../controllers/userController.js";

const userRout = Router();

userRout.get("/", listarUser);
userRout.post("/", crearUsuario);
userRout.post('/asignar-rol', asignarRolUsuario);
userRout.put('/:userId/status', changeUserStatus);

export default userRout;