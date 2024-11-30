import { exec } from 'child_process';
import path from 'path';
import fs from 'fs';
import { basedatos } from "../config/mysql.db.js";
import { error, success } from "../messages/browser.js";
import dotenv from 'dotenv';
dotenv.config();

// Función para restaurar la base de datos desde un archivo SQL
export const restoreDatabase = async (req, res) => {
  try {
    const { filename } = req.body; // Nombre del archivo de respaldo
    if (!filename) {
      return error(req, res, 400, 'Nombre de archivo no proporcionado');
    }

    const backupDir = path.join(process.cwd(), 'backups');
    const backupFilePath = path.join(backupDir, filename);

    // Verificar si el archivo existe
    if (!fs.existsSync(backupFilePath)) {
      return error(req, res, 404, 'Archivo de respaldo no encontrado');
    }

    const dbUser = process.env.MYSQLUSER;
    const dbPassword = process.env.MYSQLPASSWORD;
    const dbName = process.env.MYSQLDATABASE;
    const dbHost = process.env.MYSQLHOST;
    const dbPort = process.env.MYSQLPORT;

    // Comando para ejecutar la restauración
    const command = `mysql -h ${dbHost} -P ${dbPort} -u ${dbUser} -p${dbPassword} ${dbName} < ${backupFilePath}`;

    exec(command, (err, stdout, stderr) => {
      if (err) {
        console.error('Error al restaurar la base de datos:', stderr);
        return error(req, res, 500, 'Error al restaurar los datos');
      }

      console.log('Resultado de la restauración:', stdout);
      success(req, res, 200, 'Datos restaurados correctamente', stdout);
    });
  } catch (err) {
    console.error('Error inesperado:', err);
    error(req, res, 500, 'Error interno del servidor');
  }
};

// Función para realizar un respaldo de la base de datos
export const backupDatabase = async (req, res) => {
  try {
    const dbUser = process.env.MYSQLUSER;
    const dbPassword = process.env.MYSQLPASSWORD;
    const dbName = process.env.MYSQLDATABASE;
    const dbHost = process.env.MYSQLHOST;
    const dbPort = process.env.MYSQLPORT;

    const backupDir = path.join(process.cwd(), 'backups');
    if (!fs.existsSync(backupDir)){
      fs.mkdirSync(backupDir);
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupFilePath = path.join(backupDir, `backup-${timestamp}.sql`);

    const command = `mysqldump -h ${dbHost} -P ${dbPort} -u ${dbUser} -p${dbPassword} ${dbName} > ${backupFilePath}`;

    exec(command, (err, stdout, stderr) => {
      if (err) {
        console.error('Error al crear el respaldo:', stderr);
        return error(req, res, 500, 'Error al crear el respaldo');
      }

      console.log('Respaldo creado:', backupFilePath);
      success(req, res, 200, 'Respaldo creado correctamente', { backupFile: path.basename(backupFilePath) });
    });
  } catch (err) {
    console.error('Error inesperado:', err);
    error(req, res, 500, 'Error interno del servidor');
  }
};

// Función para listar los archivos de respaldo disponibles
export const listBackups = (req, res) => {
  const backupDir = path.join(process.cwd(), 'backups');

  fs.readdir(backupDir, (err, files) => {
    if (err) {
      console.error('Error al leer el directorio de respaldos:', err);
      return error(req, res, 500, 'Error al listar los respaldos');
    }

    const backups = files.filter(file => file.endsWith('.sql'));
    success(req, res, 200, 'Lista de respaldos', backups );
    console.log((backups))
  });
};

export const exportDatabase = async (req, res) => {
    let connection;
    try {
        const exportFormat = req.query.format || 'csv'; // Por defecto CSV
        connection = await basedatos.getConnection();
        const [tables] = await connection.query('SHOW TABLES');
        let exportData = {};

        if (exportFormat === 'csv') {
            // Exportar datos en CSV

            // Exportar datos de cada tabla
            for (const tableRow of tables) {
                const tableName = Object.values(tableRow)[0]; // Obtiene el nombre de la tabla
                const [rows] = await connection.query(`SELECT * FROM ${tableName}`);
                exportData[tableName] = rows;
            }

            // Verificar si hay datos para exportar
            if (Object.keys(exportData).length === 0) {
                throw new Error('No hay datos para exportar');
            }

            // Preparar los datos para CSV
            const flattenedData = Object.entries(exportData).flatMap(([tableName, rows]) =>
                rows.map(row => ({ table: tableName, ...row }))
            );

            // Convertir a CSV
            const parser = new Parser({ flatten: true });
            const csv = parser.parse(flattenedData);

            // Configurar la respuesta para CSV
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', 'attachment; filename=database_export.csv');
            res.send(csv);

        } else if (exportFormat === 'sql') {
            // Exportar datos en SQL

            let sqlDump = '';

            // Exportar la estructura y los datos de cada tabla
            for (const tableRow of tables) {
              const tableName = Object.values(tableRow)[0]; // Obtiene el nombre de la tabla

              // Obtener la estructura de la tabla
              const [[{ 'Create Table': createTableSQL }]] = await connection.query(`SHOW CREATE TABLE ${tableName}`);
              sqlDump += `-- Estructura de la tabla ${tableName} \n`;
              sqlDump += `${createTableSQL};\n\n`;

              // Exportar los datos de la tabla
              const [rows] = await connection.query(`SELECT * FROM ${tableName}`);
              if (rows.length > 0) {
                  sqlDump += `-- Datos de la tabla ${tableName} \n`;
                  rows.forEach(row => {
                      const columns = Object.keys(row).map(col => `\`${col}\``).join(', ');
                      const values = Object.values(row).map(val => connection.escape(val)).join(', ');
                      sqlDump += `INSERT INTO \`${tableName}\` (${columns}) VALUES (${values});\n`;
                  });
                  sqlDump += `\n`;
              }
            }

            // Verificar si hay datos para exportar
            if (sqlDump.length === 0) {
                throw new Error('No hay datos para exportar');
            }

            // Configurar la respuesta para SQL
            res.setHeader('Content-Type', 'application/sql');
            res.setHeader('Content-Disposition', 'attachment; filename=database_export.sql');
            res.send(sqlDump);
            success()
        } else {
            throw new Error('Formato de exportación no soportado');
        }

    } catch (err) {
        console.error('Error al exportar la base de datos:', err);
        error(req, res, 500, err.message || "Error al exportar la base de datos");
    } finally {
        if (connection) connection.release();
    }
};

// Función para restaurar datos de usuarios desde un archivo
export const restoreUserData = async (req, res) => {
  try {
    const { filename } = req.body; // Nombre del archivo de respaldo
    if (!filename) {
      return error(req, res, 400, 'Nombre de archivo no proporcionado');
    }

    const backupDir = path.join(process.cwd(), 'backups');
    const backupFilePath = path.join(backupDir, filename);

    // Verificar si el archivo existe
    if (!fs.existsSync(backupFilePath)) {
      return error(req, res, 404, 'Archivo de respaldo no encontrado');
    }

    // Ejecutar la consulta directamente con async/await
    const sql = `CALL restore_user_data('${backupFilePath}')`;
    const [result] = await basedatos.query(sql); // Using await instead of a callback
    console.log('Resultado de la restauración:', result);

    success(req, res, 200, 'Datos de usuarios restaurados correctamente');
  } catch (err) {
    console.error('Error inesperado:', err);
    error(req, res, 500, 'Error interno del servidor');
  }
};

// Función para realizar un respaldo de los datos de usuarios
export const backupUserData = async (req, res) => {
  try {
    const dbUser = process.env.MYSQLUSER;
    const dbPassword = process.env.MYSQLPASSWORD;
    const dbName = process.env.MYSQLDATABASE;
    const dbHost = process.env.MYSQLHOST;
    const dbPort = process.env.MYSQLPORT;

    const backupDir = path.join(process.cwd(), 'backups');
    if (!fs.existsSync(backupDir)){
      fs.mkdirSync(backupDir);
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupFilePath = path.join(backupDir, `user_backup-${timestamp}.sql`);

    const command = `mysqldump -h ${dbHost} -P ${dbPort} -u ${dbUser} -p${dbPassword} ${dbName} usuario > ${backupFilePath}`;

    exec(command, (err, stdout, stderr) => {
      if (err) {
        console.error('Error al crear el respaldo de usuarios:', stderr);
        return error(req, res, 500, 'Error al crear el respaldo de usuarios');
      }

      console.log('Respaldo de usuarios creado:', backupFilePath);
      success(req, res, 200, 'Respaldo de usuarios creado correctamente', { backupFile: path.basename(backupFilePath) });
    });
  } catch (err) {
    console.error('Error inesperado:', err);
    error(req, res, 500, 'Error interno del servidor');
  }
};

// Función para listar los archivos de respaldo de usuarios disponibles
export const listUserBackups = (req, res) => {
  const backupDir = path.join(process.cwd(), 'backups');

  fs.readdir(backupDir, (err, files) => {
    if (err) {
      console.error('Error al leer el directorio de respaldos:', err);
      return error(req, res, 500, 'Error al listar los respaldos de usuarios');
    }

    const backups = files.filter(file => file.startsWith('user_backup') && file.endsWith('.sql'));
    success(req, res, 200, 'Lista de respaldos de usuarios',backups[0] );
    console.log(backups);
  });
};
