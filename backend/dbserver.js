const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const axios = require('axios');
const app = express();
const port = 4001;
const bcrypt = require('bcrypt');
const session = require('express-session');
const jwt = require('jsonwebtoken');// henerar token


// Configuración de express-session
app.use(session({
  secret: 'uFJG768ujfghASDGJKL!@1234asdf8976&%$#', // Debes cambiar esto por un secreto fuerte y único
  resave: false, // No volver a guardar la sesión si no se ha modificado
  saveUninitialized: false, // No guardar sesiones vacías o sin inicializar
  cookie: { 
    secure: false, // true si usas HTTPS
    maxAge: 1000 * 60 * 60 * 24 // 1 día de duración para las cookies de sesión
  }
}));

app.use(cors()); // Habilita CORS para permitir solicitudes desde tu frontend
app.use(express.json()); // Permite el parsing de JSON en las solicitudes

// Conectar a la base de datos
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'r1234',
  database: 'quimiap'
});

connection.connect((err) => {
  if (err) {
    console.error('Error conectando a la base de datos:', err.stack);
    return;
  }
  console.log('Conexión exitosa a la base de datos.');
});
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:5000'], // Puedes restringir esto a 'http://localhost:4000' si prefieres, o para todos:'*'
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

//USUARIOS

// Consulta general de la tabla Usuario
app.get('/usuarios', (req, res) => {
  const query = 'SELECT * FROM Usuario';
  
  connection.query(query, (error, results) => {
    if (error) {
      console.error('Error al realizar la consulta:', error);
      res.status(500).json({ error: 'Error al realizar la consulta' });
    } else {
      res.json(results); // Devuelve los resultados de la consulta
    }
  });
});
// Función para generar una contraseña aleatoria
function generarContraseña(length) {
  const caracteres = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
  let contraseña = '';
  for (let i = 0; i < length; i++) {
      contraseña += caracteres.charAt(Math.floor(Math.random() * caracteres.length));
  }
  return contraseña;
}
// Función para registrar un usuario
const registrarUsuario = (datosUsuario) => {
  return new Promise((resolve, reject) => { // Devolver una promesa
      const query = 'INSERT INTO Usuario (nombres, apellidos, telefono, correo_electronico, tipo_doc, num_doc, contrasena, rol) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';

      connection.query(query, datosUsuario, (err, results) => {
          if (err) {
              console.error('Error al registrar usuario:', err);
              return reject(err); // Rechazar la promesa en caso de error
          }
          resolve(results); // Resolver la promesa con los resultados
      });
  });
};

// Función para verificar si el usuario ya existe en la base de datos
const verificarUsuarioExistente = (correo_electronico, num_doc) => {
  return new Promise((resolve, reject) => {
      const query = 'SELECT id_usuario FROM Usuario WHERE correo_electronico = ? OR num_doc = ?';
      connection.query(query, [correo_electronico, num_doc], (err, results) => {
          if (err) {
              console.error('Error al verificar el usuario:', err);
              return reject(err);
          }
          resolve(results.length > 0); // Retorna true si el usuario existe, false si no
      });
  });
};
// Endpoint para registrar usuarios
app.post('/registrarUser', async (req, res) => {
    const {
        nombres, 
        apellidos, 
        telefono, 
        correo_electronico, 
        tipo_doc, 
        num_doc, 
        contrasena, 
        rol 
    } = req.body;

    let contraseñaUsar;

    const rolesAdministrativos = ['gerente', 'domiciliario', 'jefe de produccion'];

    try {
        // Verificar si el usuario ya está registrado
        const usuarioExistente = await verificarUsuarioExistente(correo_electronico, num_doc);
        if (usuarioExistente) {
            return res.status(400).json({ success: false, message: 'El usuario ya está registrado.' });
        }

        // Generar o asignar la contraseña
        if (rolesAdministrativos.includes(rol.toLowerCase())) {
            contraseñaUsar = generarContraseña(12); // Generar contraseña aleatoria para roles administrativos
        } else if (rol.toLowerCase() === 'cliente') {
            // Usar la contraseña proporcionada por el cliente
            if (!contrasena) {
                return res.status(400).json({ success: false, message: 'La contraseña es requerida para clientes.' });
            }
            contraseñaUsar = contrasena;
        } else {
            // Rol no reconocido
            return res.status(400).json({ success: false, message: 'Rol no reconocido.' });
        }

        // Hashear la contraseña antes de guardarla
        const hashedPassword = bcrypt.hashSync(contraseñaUsar, 10);

        // Preparar los datos para el procedimiento almacenado
        const datosUsuario = [nombres, apellidos, telefono, correo_electronico, tipo_doc, num_doc, hashedPassword, rol];

        // Registrar el usuario en la base de datos
        const results = await registrarUsuario(datosUsuario);
        const userId = results.insertId;

        // Si es un rol administrativo, enviar la contraseña por correo
        if (rolesAdministrativos.includes(rol.toLowerCase())) {
            try {
                await axios.post('http://localhost:5000/enviar_contrasena', {
                    correo_electronico,
                    id: userId,
                    contrasena: contraseñaUsar
                });
                console.log('Correo de verificación enviado con éxito.');
            } catch (error) {
                console.error('Error al enviar el correo de verificación:', error);
                // Eliminar al usuario si ocurre un error al enviar el correo
                await eliminarUsuario(userId);
                return res.status(500).json({ success: false, message: 'Error al enviar el correo de verificación.' });
            }
        }

        return res.json({ success: true, id_usuario: userId, results });
    } catch (err) {
        console.error('Error al registrar el usuario:', err);
        return res.status(500).json({ success: false, error: err });
    }
});



// Función para eliminar un usuario en caso de error al enviar el correo
const eliminarUsuario = (userId) => {
  return new Promise((resolve, reject) => {
      const query = 'DELETE FROM Usuario WHERE id_usuario = ?';
      connection.query(query, [userId], (err, results) => {
          if (err) {
              console.error('Error al eliminar usuario:', err);
              return reject(err);
          }
          resolve(results);
      });
  });
};
// funcion para verificar el numero de documento existente
const verificarUsuarioExistentePorDocumento = (num_doc) => {
  return new Promise((resolve, reject) => {
      const query = 'SELECT id_usuario FROM Usuario WHERE num_doc = ?';
      connection.query(query, [num_doc], (err, results) => {
          if (err) {
              console.error('Error al verificar el usuario:', err);
              return reject(err);
          }
          resolve(results.length > 0); // Retorna true si el usuario existe, false si no
      });
  });
};

// Endpoint para verificar si el número de documento ya está registrado
app.get('/usuarios/documento/:num_doc', async (req, res) => {
  const { num_doc } = req.params;
  try {
      const usuario = await verificarUsuarioExistentePorDocumento(num_doc); // Implementa esta función en tu modelo
      if (usuario) {
          return res.json([usuario]); // Retorna un arreglo con el usuario si existe
      }
      return res.json([]); // Retorna un arreglo vacío si no existe
  } catch (error) {
      console.error('Error checking document number:', error);
      return res.status(500).json({ message: 'Error al verificar el número de documento.' });
  }
});


// endpoint para actualizar usuarios
app.put('/actualizarUser/:id_usuario', (req, res) => {
  const {
      id_usuario,            // ID del usuario a actualizar
      nombres, 
      apellidos, 
      telefono, 
      correo_electronico, 
      tipo_doc, 
      num_doc, 
      contrasena, 
      estado, 
      rol 
  } = req.body;

  const query = `CALL ActualizarUsuario(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

  connection.query(query, 
    [id_usuario, nombres, apellidos, telefono, correo_electronico, tipo_doc, num_doc, contrasena, estado, rol], 
    (err, results) => {
      if (err) {
          console.error('Error ejecutando la consulta:', err);
          return res.status(500).json({ success: false, error: err });
      }
      res.json({ success: true, results });
  });
});

// Endpoint para cambiar estado al usuario
app.put('/cambiarEstadoUsuario/:id_usuario', (req, res) => {
const { estado } = req.body; // Se espera que el estado venga en el cuerpo de la solicitud
const id_usuario = req.params.id_usuario; // Obtener el ID del usuario desde la URL

const query = `CALL CambiarEstadoUsuario(?, ?)`;

connection.query(query, [id_usuario, estado], (err, results) => {
    if (err) {
        console.error('Error ejecutando la consulta:', err);
        return res.status(500).json({ success: false, error: err });
    }
    res.json({ success: true, results });
});
});

app.post('/login', (req, res) => {
  const { correo_electronico, contrasena } = req.body;
  
  console.log('Correo electrónico recibido:', correo_electronico);
  console.log('Contraseña recibida:', contrasena);

  // Verifica que los campos no estén vacíos
  if (!correo_electronico || !contrasena) {
      return res.status(400).json({ success: false, message: 'Por favor, complete todos los campos requeridos.' });
  }

  // Consulta para encontrar el usuario
  const query = 'SELECT * FROM Usuario WHERE correo_electronico = ?';
  connection.query(query, [correo_electronico], (err, results) => {
      if (err) {
          console.error('Error al ejecutar la consulta:', err);
          return res.status(500).json({ success: false, message: 'Error en el servidor.' });
      }

      // Verifica si el usuario existe
      if (results.length === 0) {
          console.log('No se encontró el usuario con el correo proporcionado.');
          return res.status(401).json({ success: false, message: 'Credenciales incorrectas.' });
      }

      const user = results[0];
      console.log('Usuario encontrado:', user);

      // Verificar el estado de la cuenta
      if (user.estado !== 'activo') {
          console.log('Estado de la cuenta:', user.estado);
          return res.status(403).json({ success: false, message: 'Cuenta inactiva o pendiente.' });
      }

      // Verifica la contraseña
      bcrypt.compare(contrasena, user.contrasena, (err, isMatch) => {
          if (err) {
              console.error('Error al comparar contraseñas:', err);
              return res.status(500).json({ success: false, message: 'Error en el servidor.' });
          }

          if (!isMatch) {
              console.log('La contraseña no coincide.');
              return res.status(401).json({ success: false, message: 'Credenciales incorrectas.' });
          }

          // Almacena la información del usuario en la sesión
          req.session.user = {
              id_usuario: user.id_usuario,
              nombres: user.nombres,
              apellidos: user.apellidos,
              rol: user.rol
          };

          // Devuelve la respuesta con los datos del usuario
          res.json({
              success: true,
              message: 'Inicio de sesión exitoso.',
              user: {
                  id_usuario: user.id_usuario,
                  nombres: user.nombres,
                  apellidos: user.apellidos,
                  rol: user.rol
              }
          });
      });
  });
});



// Ruta para buscar usuario por correo electrónico
app.get('/usuarios/correo/:correo_electronico', (req, res) => {
  const correoElectronico = req.params.correo_electronico;

  const query = 'SELECT * FROM Usuario WHERE correo_electronico = ?';
  
  connection.query(query, [correoElectronico], (error, results) => {
      if (error) {
          console.error('Error al realizar la consulta:', error);
          return res.status(500).json({ error: 'Error al realizar la consulta' });
      }
      res.json(results); // Devuelve los resultados de la consulta
  });
});

// TRAER USUARIOS POR ID
app.get('/usuarios/porid/:id_usuario', (req, res) => {
  const id_usuario = req.params.id_usuario; // Obtener el ID del usuario desde la URL

  const query = `SELECT * FROM Usuario WHERE id_usuario = ?`;

  connection.query(query, [id_usuario], (error, results) => {
    if (error) {
      console.error('Error ejecutando la consulta:', error);
      return res.status(500).json({ success: false, error: error });
    }

    // Verificar si se encontró el usuario
    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
    }

    res.json(results); // Devolver el primer resultado
  });
});


// PRODUCTOS
// Consulta general de la tabla Categoria
app.get('/categoria', (req, res) => {
  const query = 'SELECT * FROM Categoria';
  
  connection.query(query, (error, results) => {
    if (error) {
      console.error('Error al realizar la consulta:', error);
      res.status(500).json({ error: 'Error al realizar la consulta' });
    } else {
      res.json(results); // Devuelve los resultados de la consulta
    }
  });
});

// Consulta general de la tabla Producto
app.get('/Producto', (req, res) => {
  const query = `
      SELECT 
          p.id_producto,
          p.nombre,
          p.descripcion,
          p.composicion,
          p.contenido_neto,
          p.usos,
          p.advertencias,
          p.cantidad_producto,
          p.precio_unitario,
          p.estado,
          c.nombre_categoria AS categoria,
          p.imagen
      FROM 
          Producto p
      JOIN 
          Categoria c ON p.categoria_id = c.id_categoria;
  `;

  connection.query(query, (error, results) => {
      if (error) {
          console.error('Error al realizar la consulta:', error);
          res.status(500).json({ error: 'Error al realizar la consulta' });
      } else {
          res.json(results); // Devuelve los resultados de la consulta
      }
  });
});

// Registrar un nuevo producto
app.post('/registrarProducto', (req, res) => {
  const {
      nombre, 
      descripcion, 
      imagen, 
      categoria_id, // Cambié a categoria_id para que coincida con la estructura de la tabla
      composicion, 
      contenido_neto, 
      usos, 
      advertencias, 
      cantidad_producto, 
      precio_unitario, 
      estado 
  } = req.body;

  const query = `CALL RegistrarProducto(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

  connection.query(query, 
    [nombre, descripcion, imagen, categoria_id, composicion, contenido_neto, usos, advertencias, cantidad_producto, precio_unitario, estado], 
    (err, results) => {
      if (err) {
          console.error('Error ejecutando la consulta:', err);
          return res.status(500).json({ success: false, error: err });
      }
      res.json({ success: true, results });
  });
});

// Actualizar un producto
app.put('/actualizarProducto', (req, res) => {
  const {
      id_producto, 
      nombre, 
      descripcion, 
      imagen, 
      categoria_id, 
      composicion, 
      contenido_neto, 
      usos, 
      advertencias, 
      cantidad_producto, 
      precio_unitario, 
      estado 
  } = req.body;

  const query = `CALL ActualizarProducto(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

  connection.query(query, 
    [id_producto, nombre, descripcion, imagen, categoria_id, composicion, contenido_neto, usos, advertencias, cantidad_producto, precio_unitario, estado], 
    (err, results) => {
      if (err) {
          console.error('Error ejecutando la consulta:', err);
          return res.status(500).json({ success: false, error: err });
      }
      res.json({ success: true, results });
  });
});

// Cambiar estado de un producto
// Descontinuar un producto
app.put('/descontinuarProducto', (req, res) => {
  const { id_producto } = req.body; // Asegúrate de recibir el ID del producto

  const query = `UPDATE Producto SET estado = 'descontinuado' WHERE id_producto = ?`;

  connection.query(query, [id_producto], (err, results) => {
      if (err) {
          console.error('Error ejecutando la consulta:', err);
          return res.status(500).json({ success: false, error: err });
      }
      res.json({ success: true, message: 'Producto descontinuado correctamente' });
  });
});


app.listen(port, () => {
  console.log(`Servidor corriendo en el puerto ${port}`);
});
