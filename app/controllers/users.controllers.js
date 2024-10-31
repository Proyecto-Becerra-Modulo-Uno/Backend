import bcrypt from "bcrypt";
import { basedatos } from "../config/mysql.db.js";
import jwt from "jsonwebtoken";
import { error, success } from "../messages/browser.js";
import { jwtDecode } from "jwt-decode";

import jsPDF from 'jspdf';

// Crear usuario

export const crearUsuario = async (req, res) => {
    const { usuario, nombre, email, telefono, contrasena, rol, estado } = req.body;
    const passwordToUse = contrasena;  
    if (!usuario || !nombre || !email || !passwordToUse) {
        return error(req, res, 400, "Todos los campos son requeridos: usuario, nombre, email, contraseña, rol");
    }

    try {
        const hash = await bcrypt.hash(passwordToUse, 10);
        const [respuesta] = await basedatos.query(
            'CALL SP_CrearUsuario(?, ?, ?, ?, ?, ?, ?);',
            [usuario, nombre, hash, email, rol, estado, telefono]
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

// Mostrar o enlistar usuarios

export const mostrarUsuarios = async(req, res) => {
    try {
        const respuesta = await basedatos.query('CALL SP_ObtenerPanelControlUsuarios();');
        success(req, res, 200, respuesta[0][0]);
    } catch (err) {
        error(req, res, 200, err || "Error interno del servidor")
    }
}

// Mostrar un solo usuario
export const mostrarUsuario = async(req, res) => {
    const {id} = req.params;
    
    try {
        const request = await basedatos.query('CALL SP_BuscarUsuario(?)', [id]);
        success(req, res, 200, request[0][0]);
    } catch (err) {
        console.error(err);
        return error(req, res, 500, "No se pudo mostrar el usuario")
    }
}



// Logueo de usuario

export const logueoUsuario = async (req, res) => {
    const { usuario, contrasena } = req.body;
    try {
        // Verificar si el usuario existe y obtener su rol, contraseña y estado
        const [request] = await basedatos.query('CALL SP_VERIFICAR_ROLES(?)', [usuario]);


        if (request[0].length === 0) {
            console.log('Usuario no encontrado');
            return error(req, res, 404, 'Usuario no existe');
        }

        const userData = request[0][0];
        const { id, id_rol, nombre_usuario, contrasena_hash, nombre, email, id_estado } = userData;

        // Verificar si la cuenta está bloqueada (id_estado = 3)
        if (id_estado === 3) {
            console.log('Cuenta bloqueada');
            return error(req, res, 403, 'Esta cuenta está bloqueada, no es posible ingresar');
        }

        // Verificar la contraseña
        const match = await bcrypt.compare(contrasena, contrasena_hash);
        console.log(`contrasena coincide: ${match}`);

        if (!match) {
            console.log('Contraseña incorrecta');
            return error(req, res, 401, 'Contraseña Incorrecta');
        }

        // Obtener la duración del token
        const [duracionResult] = await basedatos.query('CALL SP_LISTAR_POLI()');
        const duracionToken = duracionResult[0][0]?.duracion_token || '1h';

        // Generar el payload y el token
        const payload = {
            id_usuario: id,
            usuario: nombre_usuario,
            nombre: nombre,
            correo: email,
            rol: id_rol
        };

        const token = jwt.sign(payload, process.env.TOKEN_PRIVATEKEY, {
            expiresIn: duracionToken,
        });

        // Obtener el sistema operativo y la IP
        const userAgentString = req.headers['user-agent'];
        const osMatch = userAgentString.match(/\(([^)]+)\)/);
        const os = osMatch ? osMatch[1] : 'Unknown OS';
        const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.socket.remoteAddress || req.connection.socket.remoteAddress;

        // Respuesta exitosa con el token
        if (id_rol == 1) {
            success(req, res, 200, { token: token, rol: id_rol, platform: os, ip: ip, id: id, ruta: "/usuario" });
        } else if (id_rol == 2) {
            success(req, res, 200, { token: token, rol: id_rol, platform: os, ip: ip, id: id, ruta: "/invitado" });
        }else if(id_rol == 3){
            success(req, res, 200, { token: token, rol: id_rol, platform: os, ip: ip, id: id, ruta: "/panel" });
        } else if (id_rol == 4) {
            success(req, res, 200, { token: token, rol: id_rol, platform: os, ip: ip, id: id, ruta: "/moderador" });
        }

        const decodedToken = jwtDecode(token)

        console.log(decodedToken);
        

    } catch (e) {
        console.error(e);
        return error(req, res, 500, 'Error en el servidor, por favor inténtalo de nuevo más tarde');
    }
};


export const addIpToList = async (req, res) => {
    const { id, ipAddress, listType } = req.body;

    if (!ipAddress || !listType) {
        return error(req, res, 400, "Se requieren dirección IP y tipo de lista");
    }

    let tableName;
    if (listType === 'white') {
        tableName = 'lista_blanca';
    } else if (listType === 'black') {
        tableName = 'lista_negra';
    } else {
        return error(req, res, 400, "Tipo de lista inválido");
    }

    try {
        const [result] = await basedatos.query(
            `INSERT INTO ${tableName} (id_usuario, direccion_ip) VALUES (?, ?)`,
            [id, ipAddress]
        );

        if (result.affectedRows === 1) {
            success(req, res, 201, "IP agregada exitosamente a la lista");
        } else {
            error(req, res, 400, "No se pudo agregar la IP a la lista");
        }
    } catch (err) {
        console.error("Error al agregar IP a la lista:", err);
        error(req, res, 500, "Error interno del servidor al agregar IP a la lista");
    }
};






// const validarPoliticasDeContrasena = (usuario, contrasena) => {
//     if (contrasena.length < 8) {
//         return "La contraseña debe tener al menos 8 caracteres.";
//     }

//     const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+{}:"<>?|[\];',./`~\-\\=]).+$/;
//     if (!regex.test(contrasena)) {
//         return "La contraseña debe contener al menos una letra mayúscula, una letra minúscula, un número y un carácter especial.";
//     }

//     const contrasenasComunes = ['123456', 'password', 'admin', 'qwerty'];
//     if (contrasenasComunes.includes(contrasena.toLowerCase())) {
//         return "La contraseña es demasiado común.";
//     }

//     if (contrasena.toLowerCase() === usuario.toLowerCase()) {
//         return "La contraseña no puede ser igual al nombre de usuario.";
//     }

//     if (contrasena.toLowerCase().includes('password')) {
//         return "La contraseña no puede contener la palabra 'password'.";
//     }


//     return null; 
// };



export const bloquearUsuarioIntentos = async (req, res) => {
    const {email, estado} = req.body;
    try {
        const request = await basedatos.query("CALL SP_actualizarEstadoPorEmail(?, ?)", [email, estado]);
        success(req, res, 201, "Tu cuenta ha sido bloqueada por exceder el límite de intentos")        
    } catch (e) {
        console.error(e);
        return error(req, res, 500, "Error en el servidor")
    }
}

export const validarToken = (req, res) =>{
    success(req, res, 201, {"token" : "El token es valido"});
}

export const obtenerRegistrosInicioSesion = async (req, res) => {
    try {
        const [registros] = await basedatos.query("CALL SP_OBTENER_REGISTROS_INICIO_SESION()");
        success(req, res, 200, registros[0]);
    } catch (e) {
        console.error(e);
        return error(req, res, 500, "Error al obtener los registros de inicio de sesión");
    }
}

export const generarPDFRegistrosInicioSesion = async (req, res) => {
    try {
        const [registros] = await basedatos.query("CALL SP_OBTENER_REGISTROS_INICIO_SESION()");
        
        const doc = new jsPDF();
        doc.setFontSize(12); 
        doc.text("Registros de Inicio de Sesión", 20, 10);

        let yPos = 20;
        registros[0].forEach((registro, index) => {
            const texto = `${index + 1}. Usuario ID: ${registro.usuario_id}, IP: ${registro.direccion_ip}, Dispositivo: ${registro.dispositivo}, Fecha: ${registro.fecha_inicio_sesion}`;
            const textoDividido = doc.splitTextToSize(texto, 170); 

            doc.text(textoDividido, 20, yPos);
            yPos += (textoDividido.length * 10); 

            if (yPos > 280) { 
                doc.addPage();
                yPos = 20;
            }
        });

        const pdfBuffer = doc.output('arraybuffer');
        res.contentType('application/pdf');
        res.send(Buffer.from(pdfBuffer));
    } catch (e) {
        console.error(e);
        return error(req, res, 500, "Error al generar el PDF de registros de inicio de sesión");
    }
}






export const listarPoliticasYTerminos = async(req, res) => {
    try {
        const request = await basedatos.query("CALL SP_LISTAR_POLICITA_Y_TERMINOS()");
        success(req, res, 200, request[0][0]);
    } catch (err) {
        console.error(err);
        error(req, res, 500, "Error al listar politica y terminos");
    }
}

export const actualizarPoliticasSeguridad = (req, res) =>   {
    const {longitud, duracion, frecuencia, intervalo, cant_min_minusculas, cant_min_mayusculas, cant_min_numeros, cant_min_caracteres_esp} = req.body;
    try {
        const request = basedatos.query("CALL SP_ACTUALIZAR_POLITICA(?, ?, ?, ?)", [longitud, duracion, frecuencia, intervalo])
        const requestt = basedatos.query("CALL SP_ACTUALIZAR_TERMINOS_CONTRASENA(?, ?, ?, ?, ?)", [longitud, cant_min_minusculas, cant_min_mayusculas, cant_min_numeros, cant_min_caracteres_esp])

        success(req, res, 201, "Politicas ActualIzadas")
    } catch (err) {
        console.error(err);
        error(req, res, 500, "Error en la actualización")
    }
}

export const actualizarPoliticasRetencion = (req, res) => {
    const { dias_inactividad } = req.body;

    console.log(`Días de inactividad configurados: ${dias_inactividad}`);
 
    res.send('Política de retención actualizada correctamente');
};

export const listarComplejidadPreguntas = async(req, res) =>   {
    try {
        const request = await basedatos.query("CALL SP_LISTAR_COMPLEJIDAD_PREGUNTAS()");
        success(req, res, 200, request[0][0]);
    } catch (err) {
        console.error(err);
        error(req, res, 500, "Error en la actualización")
    }
}

export const actualizarComplejidadPreguntas = (req, res) =>   {
    const {caracteres_pregunta, caracteres_respuesta, cant_preguntas} = req.body;
    try {
        const request = basedatos.query("CALL SP_ACTUALIZAR_COMPLEJIDAD_PREGUNTAS(?, ?, ?)", [caracteres_pregunta, caracteres_respuesta, cant_preguntas])
        success(req, res, 201, "Complejidad de preguntas actualizadas")
    } catch (err) {
        console.error(err);
        error(req, res, 500, "Error en la actualización")
    }
}

export const contrasena = async (req, res) => {
    try {
        const respuesta = await basedatos.query('CALL ObtenerPanelControlUsuarios();');
        if (respuesta[0].affectedRows == 1) {
            let msg = `
                <!DOCTYPE html>
  <html lang="es">
  <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <style>
          body {
              font-family: Arial, sans-serif;
              background-color: #f4f4f4;
              color: #333;
              line-height: 1.6;
              padding: 20px;
          }
          .container {
              background-color: #fff;
              border-radius: 10px;
              box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
              padding: 20px;
              max-width: 600px;
              margin: auto;
          }
          h1 {
              color: #808080;
          }
          p {
              font-size: 2em;
          }
      </style>
  </head>
  <body>
      <div class="container">
          <h1>¡Hola estimado usuario!</h1>
          <p>¡Queremos informarte que tienes que cambiar tu contraseña en nuestra pagina APEX!</p>
          <p>¡Te queremos informar que el cambio de contraseña es obligatorio!</p>
          <p>¡Gracias por tu atención!</p>
      </div>
  </body>
  </html>
            `; 
        } 
    } catch (err) {
        error(req, res, 400, err);
    }
};

export const sendEmail = async (messages, receiverEmail, subject) => {
    try {
        let transporter = nodemailer.createTransport({
            host: "smtp.gmail.com",
            service: "gmail",
            secure: true,
            auth: {
                user: process.env.EMAIL_CORREO,
                pass: process.env.EMAIL_CLAVE
            },
            tls: {
                rejectUnauthorized: false 
            }
        });

        let info = await transporter.sendMail({
            from: process.env.EMAIL_CORREO,
            to: receiverEmail,
            subject: subject,
            html: messages
        });

        console.log("Email enviado:", info.messageId);
    } catch (error) {
        console.error("Error al enviar el correo:", error);
        throw error;
    }
};

export const actualizarTiempoIntentos = (req, res) => {
    const {tiempo, intentos} = req.body;
    try {
        const request = basedatos.query("CALL SP_ACTUALIZAR_TIEMPO_INTENTOS(?, ?)", [intentos, tiempo]);
        success(req, res, 201, "Intentos y tiempo actualizados")
    } catch (err) {
        console.error(err);
        error(req, res, 500, "Error actualizando el tiempo y los intentos");
    }
}

export const changeUserStatus = async(req, res) => {
    const { userId } = req.params;
    const { newStatus } = req.body;
    try {
        // Llamar al procedimiento almacenado
        const [results] = await basedatos.execute('CALL cambiar_estado_usuario(?, ?)', [userId, newStatus]);
        // Verificar el resultado del procedimiento almacenado
        if (results[0][0].success) {
            success(req, res, 201, "Estado del usuario actualizado correctamente");
        } else {
            success(req, res, 400, "No se pudo actualizar el estado del usuario");
        }
    } catch (error) {
        console.error('Error al cambiar el estado del usuario:', error);
        error(req, res, 500, "Error interno del servidor");
    }
}

export const obtenerActividadesSospechosas = async (req, res) => {
    try {
        const [result] = await basedatos.query('SELECT * FROM actividades_sospechosas');
        if (result.length === 0) {
            return res.json([]); // Devuelve un array vacío si no hay datos
        }
        // res.json(result); 
        success(req, res, 200, result);
    } catch (error) {
        console.error('Error al obtener actividades sospechosas:', error);
        res.status(500).json({ message: 'Error al obtener actividades sospechosas' });
    }
};

export const crear_intervalo_contrasena = async(req, res) => {
    const {tiempo} = req.body;
    try {
        const request = await basedatos.query("CALL SP_ACTUALIZAR_INTERVALO_CAMBIO_CONTRASENA(?)", [tiempo]);
        success(req, res, 201, "Intervalo actualizado");
    } catch (err) {
        console.error(err);
        error(req, res, 500, "Error listando grupos");
    }
}

export const updatePhoneNumber = async (req, res) => {
    try {
        const {userEmail} = req;
        if (!userEmail) {
            return error(req, res, 400, "No se pudo obtener el correo del usuario.");
        }

        const { phoneNumber } = req.body;

        if (!phoneNumber) {
            return error(req, res, 400, "Faltan parámetros requeridos: número de teléfono.");
        }

        const [result] = await basedatos.query(
            "UPDATE usuario SET telefono = ? WHERE email = ?",
            [phoneNumber, userEmail]
        );

        if (result.affectedRows > 0) {
            return success(req, res, 200, "Número de teléfono actualizado correctamente.");
        } else {
            return error(req, res, 404, "Usuario no encontrado para actualizar.");
        }
    } catch (err) {
        console.error("Error detallado:", err);
        return error(req, res, 500, `Error en el servidor: ${err.message} - Código: ${err.code}`);
    }
};

const logs = [
    { level: "DEBUG", message: "Depuración: Mensaje DEBUG", timestamp: new Date() },
    { level: "INFO", message: "Información: Mensaje INFO", timestamp: new Date() },
    { level: "WARN", message: "Advertencia: Mensaje WARN", timestamp: new Date() },
    { level: "ERROR", message: "Error: Mensaje ERROR", timestamp: new Date() },
    { level: "FATAL", message: "Fallo Fatal: Mensaje FATAL", timestamp: new Date() }
];


// Controlador para obtener logs según los niveles seleccionados
export const getLogs = (req, res) => {
    const { levels } = req.query; // Los niveles de logs seleccionados vienen como query params
    const selectedLevels = levels ? levels.split(',') : []; // Convertir los niveles en un array

    // Filtrar logs según los niveles seleccionados
    const filteredLogs = logs.filter(log => selectedLevels.includes(log.level));

    // Devolver los logs filtrados
    res.json(filteredLogs);
};

export const exportarDatos = async (req, res) => {
    try {
        const respuesta = await basedatos.query('CALL SP_EXPORTAR_DATOS();');
        success(req, res, 200, respuesta[0][0]);
    } catch (err) {
        console.error(err);
        error(req, res, 500, err.message || "Error interno del servidor"); 
    }
}

export const permisos = async (req, res) => {
    const{
        idUsuario,
         idPermiso, 
         estado
    } =req.body
    try {
        const respuesta = await basedatos.query('CALL SP_PERMITIR_PERMISOS(?)(?)(?)', [idUsuario, idPermiso, estado]);
        success(req, res, 200, respuesta[0][0]);
    } catch (err) {
        console.error(err);
        error(req, res, 500, err.message || "Error interno del servidor"); 
    }
}