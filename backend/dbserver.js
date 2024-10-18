const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');

const app = express();
const port = 4001;

app.use(cors()); // Habilita CORS para permitir solicitudes desde tu frontend
app.use(express.json()); // Permite el parsing de JSON en las solicitudes

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
// Resgistrar usuarios 
// Registrar usuarios 
app.post('/registrarUser', (req, res) => {
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

  const query = `CALL RegistrarUsuario(?, ?, ?, ?, ?, ?, ?, ?)`;

  connection.query(query, 
    [nombres, apellidos, telefono, correo_electronico, tipo_doc, num_doc, contrasena, rol], 
    (err, results) => {
      if (err) {
          console.error('Error ejecutando la consulta:', err);
          return res.status(500).json({ success: false, error: err });
      }
      
      // Asegúrate de que estás extrayendo el ID correctamente
      const userId = results[0][0]?.id_usuario; // Cambia según la estructura del resultado

      // Envía la respuesta incluyendo el ID del usuario
      res.json({ success: true, id_usuario: userId, results });
  });
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
// endpoint para iniciar sesion
app.get('/iniciarSesion', (req, res) => {
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
