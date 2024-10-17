import jwt from "jsonwebtoken";
import { config } from "dotenv";
import { error } from "../messages/browr.js"; 
config();

export const verifyToken = async (req, res, next) =>{
    const token = req.headers["x-access-token"];
    try{
        const valida = await jwt.verify(
            token,
            process.env.TOKENPRIVATEKEY
        );
        next();
    } catch (e) {
        error(req, res, 401, e)
    }
}
