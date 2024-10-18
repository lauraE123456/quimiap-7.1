// Requiriendo los módulos necesarios
const express = require("express");
const bodyParser = require("body-parser");
const nodemailer = require("nodemailer");
const multer = require("multer");
const path = require("path");
const cors = require('cors');
const axios = require('axios');
const fs = require('fs'); 
const bcrypt = require('bcrypt');
const mysql = require('mysql2');
// Asegúrate de incluir esto
// Creando una nueva aplicación Express.
const app = express();

// Configuración de middlewares
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));


// Establecer EJS como el Motor de plantillas
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Conectar a la base de datos
const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'Root',
    database: 'quimiap'
  });
  
  connection.connect((err) => {
    if (err) {
      console.error('Error conectando a la base de datos:', err.stack);
      return;
    }
    console.log('Conexión exitosa a la base de datos.');
  });
// Configuración de CORS para permitir solicitudes desde el puerto 4000
app.use(cors({
    origin: ['http://localhost:3000', 'http://localhost:4001'], // Puedes restringir esto a 'http://localhost:4000' si prefieres, o para todos:'*'
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Definiendo la ruta Home
app.get("/", (req, res) => {
    res.render("bienvenida");
});

// Configuración de multer para manejar la carga de archivos
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, path.join(__dirname, "files_emails")); // Ruta donde se guardarán los archivos adjuntos
    },
    filename: (req, file, cb) => {
        cb(null, file.originalname);
    },
});
const upload = multer({ storage: storage });

// Configuración del servicio de correo electrónico
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: "quimiap.1999.quimicos@gmail.com",
        pass: "earklpwhyjllbkff", // Asegúrate de usar una contraseña de aplicación si usas Gmail
    },
});

// Ruta para procesar el registro de usuario
app.post("/usuarios", (req, res) => {
    const userData = req.body; // Datos del usuario desde el formulario
    // Aquí puedes agregar la lógica para guardar `userData` en la base de datos

    res.status(201).send("Usuario registrado con éxito");
});

// Ruta para enviar correo de verificación
app.post("/enviar-verificacion", (req, res) => {
    const { correo_electronico, id} = req.body;
    console.log(`Enviando verificación a ID de usuario: ${id}`);

    // Generar el enlace de verificación
    const verificationLink = `http://localhost:5000/verificar-correo/${id}`;
    
    const verificationMailOptions = {
        from: "quimiap.1999.quimicos@gmail.com",
        to: correo_electronico,
        subject: "Verificación de correo",
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px; background-color: #f9f9f9; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);">
                <!-- Logo de la empresa -->
                <div style="text-align: center; margin-bottom: 20px;">
                    <img src="../public/img/Logo.png" alt="Logo Quimiap" style="max-width: 150px;">
                </div>
                
                <!-- Mensaje principal -->
                <h2 style="color: #28a745; text-align: center;">¡Gracias por registrarte en Quimiap!</h2>
                <p style="color: #555; font-size: 16px; text-align: center;">Por favor verifica tu correo haciendo clic en el botón de abajo:</p>
                
                <!-- Botón de verificación -->
                <div style="text-align: center; margin: 20px 0;">
                    <a href="${verificationLink}" style="display: inline-block; padding: 12px 24px; font-size: 18px; color: #fff; background-color: #28a745; border-radius: 6px; text-decoration: none; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);">Verificar correo</a>
                </div>
                
                <!-- Enlace alternativo -->
                <p style="color: #777; font-size: 14px; text-align: center;">Si el botón no funciona, copia y pega el siguiente enlace en tu navegador:</p>
                <p style="word-break: break-all; text-align: center; background-color: #f1f1f1; padding: 10px; border-radius: 5px; color: #007bff;">${verificationLink}</p>
                
                <!-- Pie de página -->
                <p style="text-align: center; font-size: 12px; color: #888; margin-top: 20px;">© 2024 Quimiap. Todos los derechos reservados.</p>
            </div>
        `,
    };

    transporter.sendMail(verificationMailOptions, (error, info) => {
        if (error) {
            console.log("Error al enviar el correo de verificación:", error);
            return res.status(500).send("Error al enviar el correo de verificación");
        } else {
            console.log("Correo de verificación enviado:", info.response);
            return res.status(200).send("Correo de verificación enviado");
        }
    });
});

// Ruta que hace una solicitud a la bd en el puerto 4001
app.get("/usuarios", async (req, res) => {
    try {
        // Haciendo una solicitud GET al puerto 4000
        const response = await axios.get('http://localhost:4001/usuarios');
        res.status(200).json(response.data); // Enviar los datos obtenidos al cliente
    } catch (error) {
        console.error('Error al hacer la solicitud a la bd del puerto 4000:', error);
        res.status(500).send('Error al obtener los datos de la BD');
    }
});
//verificacion-correo
// Nueva ruta para verificar el correo del usuario
app.get("/verificar-correo/:id", (req, res) => {
    const userId = parseInt(req.params.id, 10); // Convertir a entero
    // Verifica si userId se obtuvo correctamente
    if (isNaN(userId)) {
        console.error('ID de usuario no válido:', req.params.id);
        return res.status(400).send("ID de usuario no válido.");
    }

    // Consulta SQL para actualizar el estado del usuario
    const query = 'UPDATE Usuario SET estado = ? WHERE id_usuario = ?';
    const newState = 'activo';

    connection.query(query, [newState, userId], (error, results) => {
        if (error) {
            console.error('Error al actualizar el estado del usuario:', error);
            return res.status(500).send("Error al actualizar el estado del usuario.");
        }

        // Verifica si se actualizó algún registro
        if (results.affectedRows === 0) {
            return res.status(404).send("Usuario no encontrado.");
        }

        // Respuesta HTML de éxito
        res.send(`
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Correo Verificado</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        background-color: #f0f9ff;
                        margin: 0;
                        padding: 0;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                    }
                    .container {
                        background-color: #fff;
                        padding: 40px;
                        border-radius: 10px;
                        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
                        text-align: center;
                    }
                    h1 {
                        color: #28a745;
                        font-size: 36px;
                        margin-bottom: 10px;
                    }
                    p {
                        font-size: 18px;
                        color: #555;
                        margin-bottom: 30px;
                    }
                    .button {
                        display: inline-block;
                        padding: 12px 24px;
                        font-size: 18px;
                        color: #fff;
                        background-color: #007bff;
                        border-radius: 6px;
                        text-decoration: none;
                        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                        transition: background-color 0.3s ease;
                    }
                    .button:hover {
                        background-color: #0056b3;
                    }
                    img {
                        max-width: 150px;
                        margin-bottom: 20px;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <img src="http://localhost:3000/img/LOGO_JEFE_DE_PRODUCCIÓN-Photoroom.png" alt="Logo Quimiap">
                    <h1>¡Correo Verificado!</h1>
                    <p>Gracias por verificar tu correo electrónico. Ahora tu cuenta está activa.</p>
                    <a href="http://localhost:3000/inicio_registro.js" class="button">Ir al Inicio</a>
                </div>  
            </body>
            </html>
        `);
    });
});

// restablecer la contraseña:
// Ruta para enviar el correo de restablecimiento de contraseña
app.post("/enviar-restablecer-contrasena", (req, res) => {
    const { correo_electronico } = req.body;

    // Aquí puedes agregar la lógica para verificar si el correo existe en tu base de datos.
    // Si el correo es válido, genera un enlace de restablecimiento.
    
    const resetPasswordLink = `http://localhost:5000/restablecer-contrasena/${correo_electronico}`;
    
    const resetPasswordMailOptions = {
        from: "quimiap.1999.quimicos@gmail.com",
        to: correo_electronico,
        subject: "Restablecer contraseña",
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px; background-color: #f9f9f9; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);">
                <h2 style="color: #28a745; text-align: center;">Solicitud para restablecer tu contraseña</h2>
                <p style="color: #555; font-size: 16px; text-align: center;">Haz clic en el botón de abajo para restablecer tu contraseña:</p>
                
                <!-- Botón de restablecimiento -->
                <div style="text-align: center; margin: 20px 0;">
                    <a href="${resetPasswordLink}" style="display: inline-block; padding: 12px 24px; font-size: 18px; color: #fff; background-color: #28a745; border-radius: 6px; text-decoration: none; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);">Restablecer contraseña</a>
                </div>
                
                <!-- Enlace alternativo -->
                <p style="color: #777; font-size: 14px; text-align: center;">Si el botón no funciona, copia y pega el siguiente enlace en tu navegador:</p>
                <p style="word-break: break-all; text-align: center; background-color: #f1f1f1; padding: 10px; border-radius: 5px; color: #007bff;">${resetPasswordLink}</p>
            </div>
        `,
    };

    transporter.sendMail(resetPasswordMailOptions, (error, info) => {
        if (error) {
            console.log("Error al enviar el correo de restablecimiento:", error);
            return res.status(500).send("Error al enviar el correo de restablecimiento");
        } else {
            console.log("Correo de restablecimiento enviado:", info.response);
            return res.status(200).send("Correo de restablecimiento enviado");
        }
    });
});
// Ruta para mostrar el formulario de restablecimiento de contraseña
app.get("/restablecer-contrasena/:correo_electronico", (req, res) => {
    const { correo_electronico } = req.params;
    res.send(`
        <!DOCTYPE html>
        <html lang="es">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Restablecer Contraseña</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background-color: #f0f9ff;
                    margin: 0;
                    padding: 0;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                }
                .reset-password-container {
                    width: 100%;
                    max-width: 400px;
                    background-color: #fff;
                    padding: 40px;
                    border-radius: 10px;
                    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
                    text-align: center;
                }
                .logo {
                    max-width: 100px;
                    margin-bottom: 20px;
                }
                h1 {
                    font-size: 24px;
                    margin-bottom: 20px;
                    color: #333;
                }
                .error-message {
                    color: red;
                    margin: 10px 0;
                }
                .success-message {
                    color: green;
                    margin: 10px 0;
                }
                input[type="password"] {
                    width: 100%;
                    padding: 10px;
                    margin: 10px 0;
                    border: 1px solid #ccc;
                    border-radius: 5px;
                }
                .submit-btn {
                    padding: 10px 20px;
                    border: none;
                    background-color: #28a745;
                    color: white;
                    border-radius: 5px;
                    cursor: pointer;
                }
                .submit-btn:hover {
                    background-color: #218838;
                }
            </style>
        </head>
        <body>
            <div class="reset-password-container">
                <h1>Restablecer Contraseña</h1>
                <form action="/actualizar-contrasena" method="POST">
                    <input
                        type="hidden"
                        name="correo_electronico"
                        value="${correo_electronico}" />
                    <input
                        type="password"
                        name="nueva_contrasena"
                        placeholder="Nueva contraseña"
                        required />
                    <input
                        type="password"
                        name="confirmar_contrasena"
                        placeholder="Confirmar nueva contraseña"
                        required />
                    <button type="submit" class="submit-btn">Actualizar Contraseña</button>
                </form>
                        <div class="password-rules">
            <p><strong>Reglas de la contraseña:</strong></p>
            <ul>
                <li>Entre 8 y 16 caracteres</li>
                <li>Al menos una letra mayúscula</li>
                <li>Al menos un signo especial (por ejemplo, !@#$%^&*)</li>
            </ul>
        </div>
            </div>
        </body>
        </html>
    `);
});

// Ruta para actualizar la contraseña del usuario
// Ruta para actualizar la contraseña del usuario
app.post("/actualizar-contrasena", async (req, res) => {
    const { correo_electronico, nueva_contrasena, confirmar_contrasena } = req.body;

    // Comprobar si las contraseñas coinciden
    if (nueva_contrasena !== confirmar_contrasena) {
        return res.status(400).send("Las contraseñas no coinciden.");
    }

    try {
        // Encriptar la nueva contraseña
        const saltRounds = 10; // Número de rondas para el hash
        const hashedPassword = await bcrypt.hash(nueva_contrasena, saltRounds);

        const filePath = path.join(__dirname, 'trabajo.json');

        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                return res.status(500).send("Error al leer el archivo.");
            }

            const usuariosData = JSON.parse(data);
            const usuarios = usuariosData.Users;

            const usuarioIndex = usuarios.findIndex(u => u.correo_electronico === correo_electronico);

            if (usuarioIndex === -1) {
                return res.status(404).send("Usuario no encontrado.");
            }

            // Actualiza la contraseña encriptada
            usuarios[usuarioIndex].contrasena = hashedPassword;

            fs.writeFile(filePath, JSON.stringify(usuariosData, null, 2), (err) => {
                if (err) {
                    return res.status(500).send("Error al guardar los cambios.");
                }

                // Mensaje de éxito
                res.send(`
                    <!DOCTYPE html>
                    <html lang="es">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>Contraseña Actualizada</title>
                        <style>
                            body {
                                font-family: Arial, sans-serif;
                                background-color: #f0f9ff;
                                margin: 0;
                                padding: 0;
                                display: flex;
                                justify-content: center;
                                align-items: center;
                                height: 100vh;
                            }
                            .message-container {
                                width: 100%;
                                max-width: 400px;
                                background-color: #fff;
                                padding: 40px;
                                border-radius: 10px;
                                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
                                text-align: center;
                            }
                            .logo {
                                max-width: 100px;
                                margin-bottom: 20px;
                            }
                            h1 {
                                font-size: 24px;
                                margin-bottom: 20px;
                                color: #28a745;
                            }
                            p {
                                font-size: 16px;
                                color: #555;
                                margin-bottom: 30px;
                            }
                            .button {
                                padding: 12px 24px;
                                border: none;
                                background-color: #007bff;
                                color: white;
                                border-radius: 5px;
                                cursor: pointer;
                                text-decoration: none;
                                display: inline-block;
                            }
                            .button:hover {
                                background-color: #0056b3;
                            }
                        </style>
                    </head>
                    <body>
                        <div class="message-container">
                            <h1>¡Contraseña Actualizada!</h1>
                            <p>Tu contraseña se ha actualizado con éxito.</p>
                            <a href="http://localhost:3000/inicio_registro.js" class="button">Ir al Inicio</a>
                        </div>
                    </body>
                    </html>
                `);
            });
        });
    } catch (err) {
        console.error("Error al encriptar la contraseña:", err);
        res.status(500).send("Error al encriptar la contraseña.");
    }
});
// Ruta para enviar los detalles de la venta y alerta por bajo stock
app.post("/enviar-detalle-venta", async (req, res) => {
    try {
        const { venta_id, productos, id, correo_electronico } = req.body;

        // Configura el contenido del correo para el cliente
        const ventaMailOptions = {
            from: "quimiap.1999.quimicos@gmail.com",
            to: correo_electronico,
            subject: "Detalles de tu Venta",
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px; background-color: #f9f9f9; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);">
                    <h2 style="color: #28a745; text-align: center;">Detalles de tu Venta</h2>
                    <p style="color: #555; font-size: 16px;">Aquí tienes los detalles de tu venta:</p>
                    <h3 style="color: #28a745;">Productos Comprados:</h3>
                    <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                        <thead>
                            <tr>
                                <th style="padding: 10px;">Nombre del Producto</th>
                                <th style="padding: 10px;">Imagen</th>
                                <th style="padding: 10px;">Cantidad</th>
                                <th style="padding: 10px;">Precio Unitario</th>
                                <th style="padding: 10px;">Subtotal</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${productos.map(prod => `
                                <tr>
                                    <td style="padding: 10px;">${prod.nombre}</td>
                                    <td style="padding: 10px;">
                                        <img src="${prod.imagen}" alt="Producto" style="width: 50px; height: auto;" />
                                    </td>
                                    <td style="padding: 10px;">${prod.cantidad}</td>
                                    <td style="padding: 10px;">$${parseFloat(prod.precio_unitario).toFixed(2)}</td>
                                    <td style="padding: 10px;">$${parseFloat(prod.subtotal).toFixed(2)}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                    <h4 style="color: #28a745; text-align: right;">Precio Total de la Venta: $${parseFloat(productos.reduce((acc, prod) => acc + prod.subtotal, 0)).toFixed(2)}</h4>
                    <p style="color: #555; font-size: 16px; text-align: center;">¡Gracias por confiar en nosotros!</p>
                    <p style="text-align: center; font-size: 12px; color: #888;">© 2024 Quimiap. Todos los derechos reservados.</p>
                </div>
            `,
        };

        // Enviar correo al cliente
        await transporter.sendMail(ventaMailOptions);

        // Verificar si algún producto tiene bajo stock
        const productosBajoStock = productos.filter(prod => prod.cantidad <= 2);

        if (productosBajoStock.length > 0) {
            // Configura el contenido del correo para el jefe de producción
            const jefeProduccionMailOptions = {
                from: "quimiap.1999.quimicos@gmail.com",
                to: "jeissuvan@gmail.com", // Correo del jefe de producción
                subject: "Alerta: Stock Bajo de Productos",
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px; background-color: #f9f9f9; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);">
                        <h2 style="color: #dc3545; text-align: center;">Alerta de Stock Bajo</h2>
                        <p style="color: #555; font-size: 16px;">Los siguientes productos están por debajo del nivel de stock:</p>
                        <ul>
                            
                            ${productosBajoStock.map(prod => `
                                <tr>
                                    <td style="padding: 10px;">${prod.nombre}</td>
                                    <td style="padding: 10px;">
                                        <img src="${prod.imagen}" alt="Producto" style="width: 50px; height: auto;" />
                                    </td>
                                    <td style="padding: 10px;"> cantidad restante: ${prod.cantidad}</td>
                                </tr>
                            `).join('')}

                        </ul>
                        <p style="color: #555; font-size: 16px;">Es necesario reponer el stock de estos productos lo antes posible.</p>
                    </div>
                `,
            };

            // Enviar correo al jefe de producción
            await transporter.sendMail(jefeProduccionMailOptions);
        }

        // Responder al cliente
        res.status(200).json({ message: "Detalles de la venta y alerta de stock bajo enviados exitosamente." });
    } catch (error) {
        console.error("Error al enviar el detalle de la venta:", error);
        res.status(500).json({ message: "Error al enviar los detalles de la venta o la alerta de stock bajo." });
    }
});


// Iniciar el servidor con Express
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Servidor de correos escuchando en http://localhost:${PORT}`);
});