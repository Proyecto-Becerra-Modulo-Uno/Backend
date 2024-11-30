import Router from "express";
import rutaAdmin from "./routes.admin";
import userRout from "./userrout.js";

const ruta = Router();

ruta.use('/users',userRout);
ruta.use("/", rutaAdmin);
ruta.use("/", (req, res) =>{
    res.json({message:'hola mundo'})
});



export default ruta