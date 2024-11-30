/**
 * Envía una respuesta exitosa al cliente.
 *
 * @param {Object} req - El objeto de la solicitud HTTP.
 * @param {Object} res - El objeto de respuesta HTTP.
 * @param {number} [status=200] - El código de estado HTTP (debe ser un número entre 100 y 599).
 * @param {string} [message=""] - El mensaje que se enviará en el cuerpo de la respuesta.
 * @param {Object|null} [data=null] - Los datos adicionales a enviar en la respuesta (puede ser null).
 */
export const success = (req, res, status = 200, message = "Success", data = null) => {
    // Validar que el estado sea un número válido dentro del rango de códigos HTTP
    if (typeof status !== 'number' || status < 100 || status > 599) {
        console.warn(`Estado HTTP no válido: ${status}. Estableciendo valor predeterminado 200.`);
        status = 200; // Valor predeterminado si el código de estado no es válido
    }

    // Enviar la respuesta con el formato JSON
    res.status(status).json({
        error: false,     // Indicador de que no hubo error
        status,           // Código de estado HTTP
        message,          // Mensaje para el cliente
        data              // Datos opcionales (puede ser null)
    });
};

/**
 * Envía una respuesta de error al cliente.
 *
 * @param {Object} req - El objeto de la solicitud HTTP.
 * @param {Object} res - El objeto de respuesta HTTP.
 * @param {number} [status=500] - El código de estado HTTP (debe ser un número entre 100 y 599).
 * @param {string} [message=""] - El mensaje de error que se enviará en el cuerpo de la respuesta.
 * @param {string|null} [errorCode=null] - Un código de error específico (opcional) para ayudar a identificar el problema.
 */
export const error = (req, res, status = 500, message = "Internal Server Error", errorCode = null) => {
    // Validar que el estado sea un número válido dentro del rango de códigos HTTP
    if (typeof status !== 'number' || status < 100 || status > 599) {
        console.warn(`Estado HTTP no válido: ${status}. Estableciendo valor predeterminado 500.`);
        status = 500; // Valor predeterminado si el código de estado no es válido
    }

    // Enviar la respuesta con el formato JSON
    res.status(status).json({
        error: true,      // Indicador de que ocurrió un error
        status,           // Código de estado HTTP
        message,          // Mensaje de error
        errorCode         // Código de error opcional para identificar el tipo de error
    });
};
