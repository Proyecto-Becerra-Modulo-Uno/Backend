import { basedatos } from "../config/mysql.db";
import { error, success } from "../messages/browser";
import { exec } from "child_process";

export const getAllCertificates = async(req, res) => {
  const certificates = await basedatos.query('SELECT * FROM certificates');
  //res.render('certificates', { certificates });
  success(req, res, 200, 'certificaciones',certificates[0]);
}

// Función para generar un CSR usando OpenSSL
const generateCSR = (domain) => {
    return new Promise((resolve, reject) => {
        const command = `openssl req -new -newkey rsa:2048 -nodes -keyout ${domain}.key -out ${domain}.csr -subj "/CN=${domain}"`;
        exec(command, (error, stdout, stderr) => {
            if (error) {
                reject(`Error generando CSR para ${domain}: ${stderr}`);
            } else {
                resolve({ csr: `${domain}.csr`, key: `${domain}.key` });
            }
        });
    });
};

// Función para renovar el certificado
export const renewCertificate = async (req, res) => {
    const certId = req.params.id;

    // Obtener el certificado de la base de datos
    const [cert] = await basedatos.query('SELECT * FROM certificates WHERE id = ?', [certId]);
    if (!cert) {
        //return res.status(404).send('Certificado no encontrado');
        return success(req, res, 404, 'Certificado no encontrado',cert);
    }

    try {
        // Generar CSR
        const { csr, key } = await generateCSR(cert.domain);

        // Aquí, enviar el CSR a la autoridad de certificación (esto depende de la CA, se haría mediante API o manualmente)
        // Ejemplo de una llamada API a la CA (esto depende del proveedor):
        // const response = await someCAApi.sendCSR(csr);
        // if (response.status !== 'success') {
        //     throw new Error('Error al renovar el certificado con la CA');
        // }

        // Actualizar el certificado en la base de datos (simulando renovación exitosa)
        const newExpiryDate = new Date();
        newExpiryDate.setFullYear(newExpiryDate.getFullYear() + 1); // Renovamos por un año más

        await basedatos.query('UPDATE certificates SET cert_status = ?, issue_date = ?, expiry_date = ?, renewal_reminder = ? WHERE id = ?',
            ['active', new Date(), newExpiryDate, false, certId]);

        // Enviar respuesta al frontend
        //res.send(`Certificado para ${cert.domain} renovado con éxito hasta ${newExpiryDate.toISOString().split('T')[0]}`);
        success(req, res, 200, `Certificado para ${cert.domain} renovado con éxito hasta ${newExpiryDate.toISOString().split('T')[0]}`);

    } catch (error) {
        console.error(error);
        // res.status(500).send('Error al renovar el certificado');
        error(req, res, 500, 'Error al renovar el certificado');
    }
};
