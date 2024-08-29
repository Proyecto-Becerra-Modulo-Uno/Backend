import bcrypt from "bcrypt";
import { basedatos } from "../config/mysql.db";
import { error, success } from "../messages/browr";


export const listarUser = async(req, res) => {
    try {
        const respuesta = await basedatos.query('CALL ObtenerPanelControlUsuarios();');
        success(req, res, 200, respuesta[0][0]);
    } catch (err) {
        error(req, res, 200, err || "Error interno del servidor")
    }
}

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
export const crearUsuario = async (req, res) => {
    const { usuario, nombre, email, contrasena, contasena } = req.body;

    // Usar contrasena o contasena, lo que esté presente
    const passwordToUse = contrasena || contasena;

    // Verificar que todos los campos requeridos estén presentes
    if (!usuario || !nombre || !email || !passwordToUse) {
      return error(req, res, 400, "Todos los campos son requeridos: usuario, nombre, email, contraseña");
    }

    try {
        // Usar 10 rondas de sal para mayor seguridad
        const hash = await bcrypt.hash(passwordToUse, 10);

        const [respuesta] = await basedatos.query(
            'CALL SP_CrearUsuario(?, ?, ?, ?);',
            [usuario, nombre, hash, email]
        );

        if (respuesta.affectedRows === 1) {
            success(req, res, 201, "Usuario creado exitosamente");
        } else {
            error(req, res, 400, "No se pudo agregar el nuevo usuario");
        }
        } catch (err) {
        console.error("Error al crear usuario:", err);
        error(req, res, 500, "Error interno del servidor al crear usuario");
    }
};
export const logueoUsuario = async(req, res) => {
    const { usuario, contrasena } = req.body;
    console.log(usuario + contrasena);

    try {
        // Verificamos si el usuario existe
        const rol = await basedatos.query(`CALL SP_VerificarUsuario(?)`, [usuario]);
        const respuesta = await basedatos.query(`CALL SP_BuscarUsuario(?)`, [usuario]);

        // Si el usuario no existe, devolvemos un error
        if (!respuesta || respuesta[0][0] == 0) {
            error(req, res, 404, "Usuario no existe");
            return;
        }

        // Obtenemos la contraseña hasheada del resultado
        const password = respuesta[0][0].contrasena;
        
        // Verificamos si la contraseña está definida
        if (!password) {
            console.log();
            error(req, res, 404, "Contraseña no encontrada");
            return;
        }

        // Comparamos la contraseña proporcionada con la almacenada
        const match = await bcrypt.compare(contrasena, password);
        
        // Si no coinciden, devolvemos un error
        if (!match) {
            error(req, res, 401, "Contraseña Incorrecta");
            return;
        }

        let payload = {
            "usuario": respuesta[0][0].usuario,
        }; 

        let token = jwt.sign(payload, process.env.TOKEN_PRIVATEKEY, {
            expiresIn: process.env.TOKEN_EXPIRES_IN
        });

        /*
        if (rol[0][0]?.rol === "Administrador") {
            success(req, res, 200, { token, "rol": "/" });
        } else if (rol[0][0]?.rol === "Usuario") {
            success(req, res, 200, { token, "rol": "/" });
        }
        */

    } catch (e) {
        error(req, res, 500, "Error en el servidor, por favor inténtalo de nuevo más tarde");
        console.log(e);
    }
}