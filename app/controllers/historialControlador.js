import { basedatos } from "../config/mysql.db";
import { error, success } from "../messages/browser";

export const historial = async (req, res) => {
  try {
    const result = await basedatos.query("CALL obtener_datos_detallados();");
    success(req, res, 200, "listar usuarios", result[0]);
  } catch (err) {
    error(req, res, 400, err);
  }
};
