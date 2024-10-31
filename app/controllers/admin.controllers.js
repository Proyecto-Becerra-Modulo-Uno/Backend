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

export const CambiarConfiguraciónDesactivarUser = async (req, res) => {
    const { 
        tiempoInactividad, 
        unidadInactividad, 
        tiempoNotificacion, 
        unidadNotificacion, 
        tiempoEliminacion, 
        unidadEliminacion, 
        tiempoGuardar, 
        unidadGuardar, 
        tiempoReactivacion, 
        unidadReactivacion 
    } = req.body;

    try {
        // Llamada al procedimiento almacenado con los parámetros de inactividad
        const [respuesta] = await basedatos.query(
            'CALL SP_InactivarUsuario(?, ?, ?, ?, ?, ?, ?, ?, ?, ?);',
            [
                tiempoInactividad,
                unidadInactividad,
                tiempoNotificacion,
                unidadNotificacion,
                tiempoEliminacion,
                unidadEliminacion,
                tiempoGuardar,
                unidadGuardar,
                tiempoReactivacion,
                unidadReactivacion
            ]
        );

        // Verificamos el resultado de la llamada
        if (respuesta.affectedRows > 0) {
            // Respuesta de éxito si el procedimiento modificó filas
            res.status(200).json({ message: "Configuración de inactividad guardada exitosamente" });
        } else {
            // Respuesta de error si no hubo filas modificadas
            res.status(400).json({ message: "No se pudo actualizar la configuración de inactividad" });
        }
    } catch (err) {
        console.error("Error al actualizar configuración de inactividad:", err);
        // Respuesta de error en caso de fallo en el servidor
        res.status(500).json({ message: "Error interno del servidor al actualizar configuración de inactividad" });
    }
};

export const configuracionDesactivaUsuario = async(req, res) => {
    try {
        const respuesta = await basedatos.query('CALL SP_MostrarDesactivacionUsuario();');
        success(req, res, 200, respuesta[0][0]);
    } catch (err) {
        error(req, res, 200, err || "Error interno del servidor")
    }
}
