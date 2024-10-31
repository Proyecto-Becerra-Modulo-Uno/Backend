import bcrypt from "bcrypt";
import { basedatos } from "../config/mysql.db.js";
import jwt from "jsonwebtoken";
import { error, success } from "../messages/browser.js";

export const asignarRolUsuario = async (req, res) => {
    const { usuarioId, rolId } = req.body;

    if (!usuarioId || !rolId) {
        return error(req, res, 400, "Se requieren usuarioId y rolId");
    }

    try {
        const [resultado] = await basedatos.query('CALL AsignarRolUsuario(?, ?)', [usuarioId, rolId]);
        const mensaje = resultado[0][0].mensaje;

        if (mensaje === 'Rol asignado correctamente') {
            success(req, res, 200, { mensaje });
        } else {
            error(req, res, 400, { mensaje });
        }
    } catch (err) {
        error(req, res, 500, err.message || "Error interno del servidor");
    }
};

export const bloquearUsuario = async(req, res) => {
    const {id} = req.params;
    const {estado} = req.body;
    try {
        const request = await basedatos.query("CALL SP_ACTUALIZAR_ESTADO_USUARIO(?,?)", [id, estado]);
        success(req, res, 201, "Estado del usuario actualizado")
    } catch (err) {
        console.error(err);
        return error(req, res, 500, "No se pudo actualizar el estado")
    }
}

export const desbloquearUsuario = async(req, res) => {
    const { id } = req.body;
    try {
        // Ejecutamos el procedimiento almacenado para desbloquear al usuario
        const request = await basedatos.query(`CALL SP_CUENTAS_DESBLOQUEADAS(?)`, [id]);

        // Enviar una respuesta de éxito con el formato esperado
        return res.status(200).json({
            success: true,
            message: "El estado del usuario ha sido actualizado correctamente"
        });
    } catch (err) {
        console.error(err);

        // Enviar una respuesta de error con el formato adecuado
        return res.status(500).json({
            success: false,
            message: "No se pudo actualizar el estado del usuario"
        });
    }
};


export const listarBloqueos = async (req, res)=> {
    try {
        const request = await basedatos.query("CALL SP_CUENTAS_BLOQUEADAS()");
        success(req, res, 200, request[0][0])   
    } catch (err) {
        console.error(err);
        return error(req, res, 500, "No se pudo traer la lista de bloqueos")
    }
}

export const listarSesiones = async (req, res) => {
    try {
        const request = await basedatos.query("CALL SP_LISTAR_REGISTROS()");
        
        const sesiones = request[0][0];
        
        // Verificamos si hay registros
        if (sesiones.length > 0) {
            success(req, res, 200, sesiones); 
        } else {
            success(req, res, 200, []); // Si no hay registros, devolvemos un array vacío
        }
    } catch (err) {
        console.error(err);
        return error(req, res, 500, "No se pudo traer la lista de sesiones");
    }
};


export const registroInicioSesion = async (req, res) => {

    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    
    const userAgent = req.headers['user-agent'];
    const platform = detectPlatform(userAgent);

    const { id } = req.body;

    try {
        const request = await basedatos.query("CALL SP_INSERTAR_HISTORIAL_SESION_USUARIO(?,?,?)", [id, ip, platform]);
        success(req, res, 201, { id, ip, platform });
    } catch (e) {
        console.error(e);
        return error(req, res, 500, "Error en el servidor");
    }
};

// Función para detectar el sistema operativo a partir del User-Agent
const detectPlatform = (userAgent) => {
    if (/win/i.test(userAgent)) {
        return 'Windows';
    } else if (/mac/i.test(userAgent)) {
        return 'MacOS';
    } else if (/linux/i.test(userAgent)) {
        return 'Linux';
    } else if (/android/i.test(userAgent)) {
        return 'Android';
    } else if (/ios/i.test(userAgent)) {
        return 'iOS';
    }
    return 'Unknown';
};


export const listarPoliticasSeguridad = async(req, res) => {
    try {
        const request = await basedatos.query("CALL SP_LISTAR_POLI()");
        success(req, res, 200, request[0][0]);
    } catch (err) {
        console.error(err);
        error(req, res, 500, "Error al listar políticas");
    }
}