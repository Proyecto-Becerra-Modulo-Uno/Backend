import mysql from 'mysql2/promise';
import dotenv from 'dotenv';

dotenv.config();

export const basedatos = mysql.createPool({
    host: process.env.MYSQLHOST,
    user: process.env.MYSQLUSER,
    password: process.env.MYSQLPASSWORD,
    port: process.env.MYSQLPORT,
    database: process.env.MYSQLDATABASE,
    connectionLimit: 10
});
