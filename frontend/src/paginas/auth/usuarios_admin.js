import { faEdit, faFilter, faSearch, faTrash } from '@fortawesome/free-solid-svg-icons';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import axios from 'axios';
import React, { useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import Swal from 'sweetalert2';
import Header2 from '../../componentes/header2';
import '../../styles/style_usuarios.css';


const UsuariosAdmin = () => {
  const [formData, setFormData] = useState({
    nombres: '',
    apellidos: '',
    telefono: '',
    correo_electronico: '',
    tipo_doc: '',
    num_doc: '',
    rol: '',
    estado: 'Activo'
  });
  const [users, setUsers] = useState([]);
  const [isEditing, setIsEditing] = useState(false);
  const [currentUser, setCurrentUser] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [userTypeFilter, setUserTypeFilter] = useState('todos');
  const [showFilters, setShowFilters] = useState(false);
  const [allowLetters, setAllowLetters] = useState(false);
  const navigate = useNavigate();
  const filterMenuRef = useRef(null);
  
  // Paginación
  const [currentPageUser, setCurrentPageUser] = useState(1);
  const recordsPerPage = 5;

  // Fetch users from the API
  const fetchUsers = async () => {
    try {
      const response = await axios.get('http://localhost:4001/usuarios');
      setUsers(response.data);
    } catch (error) {
      console.error('Error fetching users:', error);
      Swal.fire({
        title: 'Error!',
        text: 'Error al obtener los usuarios.',
        icon: 'error',
        timer: 2000,
        showConfirmButton: false
      });
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  // Filtrar usuarios según la búsqueda y el filtro de tipo de usuario
  const filteredUsers = users
  .filter((user) =>  
    user.num_doc.toString().includes(searchTerm)
  )
  .filter((user) => {
    if (userTypeFilter === 'UsuariosAdmin') {
      return user.rol !== 'cliente';
    }
    else if(userTypeFilter === 'Cliente') {
      return user.rol === 'cliente';
    }
    return userTypeFilter === 'todos' || user.rol === userTypeFilter;
  });

  // Calcular el índice del primer y último registro para la página actual
  const indexOfLastRecordUser = currentPageUser * recordsPerPage;
  const indexOfFirstRecordUser = indexOfLastRecordUser - recordsPerPage;

  // Obtener los usuarios filtrados para la página actual
  const currentRecordsUser = filteredUsers.slice(indexOfFirstRecordUser, indexOfLastRecordUser);
  const totalPagesUser = Math.ceil(filteredUsers.length / recordsPerPage);

  // Cambiar de página
  const handlePageChangeUser = (pageNumber) => {
    setCurrentPageUser(pageNumber);
  };
  // Restrict non-numeric input in the name fields
const handleNameKeyPress = (e) => {
  // Only allow letters, spaces, and common name punctuation
  if (!/^[a-zA-Z\s]*$/.test(e.key)) {
    e.preventDefault();
  }
};

  

  // Handle input changes
  const handleInputChange = (e) => {
    const { id, value } = e.target;

    // Actualiza el estado del formulario
    if (id === "tipo_doc") {
        // Maneja el cambio en el tipo de documento
        setFormData((prevData) => ({
            ...prevData,
            tipo_doc: value,
            num_doc: '' // Resetea el campo de identificación
        }));

        // Verifica el tipo de documento seleccionado
        if (value === "cedula de extranjería") {
            setAllowLetters(true); // Permite letras y números
        } else {
            setAllowLetters(false); // Solo permite números para tarjeta y cédula
        }
    } else if (id === "num_doc") {
        // Maneja el cambio en el campo de identificación
        // Lógica para cédula (10 dígitos solo numéricos) y tarjeta (10 dígitos solo numéricos)
        if ((formData.tipo_doc === "cedula de ciudadania" || formData.tipo_doc === "tarjeta de identidad") && /^[0-9]{0,10}$/.test(value)) {
            setFormData((prevData) => ({ ...prevData, num_doc: value }));
        } 
        // Lógica para cédula de extranjería (10-12 caracteres alfanuméricos)
        else if (formData.tipo_doc === "cedula de extranjería" && /^[a-zA-Z0-9]{0,12}$/.test(value) && value.length <= 12) {
            setFormData((prevData) => ({ ...prevData, num_doc: value }));
        }
    } else {
        // Para otros campos, se actualiza normalmente
        setFormData({
            ...formData,
            [id]: value,
        });
    }
};


  // registro de usuarios admin
  const handleSaveUser = async () => {
    // Asegúrate de que formData esté definido y tiene los campos necesarios
    if (!formData) {
        console.error('formData es undefined');
        return; // Salir si formData es undefined
    }

    // Lista de campos requeridos
    const requiredFields = ['nombres', 'apellidos', 'telefono', 'correo_electronico', 'tipo_doc', 'num_doc', 'rol'];

    // Filtrar campos vacíos, asegurando que sean cadenas
    const emptyFields = requiredFields.filter(field => {
        const value = formData[field];
        return typeof value !== 'string' || value.trim() === ''; // Verificar que sea una cadena y no esté vacía
    });

    // Validar campos vacíos
    if (emptyFields.length > 0) {
        const fieldsString = emptyFields.map(field => field.charAt(0).toUpperCase() + field.slice(1)).join(', ');
        Swal.fire({
            title: 'Complete los campos requeridos',
            text: `Por favor, complete los siguientes campos: ${fieldsString}.`,
            icon: 'warning',
            timer: 3000,
            showConfirmButton: false
        });
        return;
    }

    // Validar contraseña (ejemplo de validación de longitud)
    if (formData.contrasena && formData.contrasena.length < 8) {
        Swal.fire({
            title: 'Contraseña inválida',
            text: 'La contraseña debe tener al menos 8 caracteres.',
            icon: 'warning',
            timer: 3000,
            showConfirmButton: false
        });
        return;
    }

    // Verificar si se está editando un usuario
    if (isEditing && currentUser) {
        Swal.fire({
            title: '¿Desea continuar para guardar los cambios?',
            icon: 'warning',
            showDenyButton: true,
            showCancelButton: true,
            confirmButtonText: 'Guardar',
            denyButtonText: 'No Guardar',
            cancelButtonText: 'Cancelar',
            confirmButtonColor: '#3085d6',
        }).then(async (result) => {
            if (result.isConfirmed) {
                try {
                    await axios.put(`http://localhost:4001/actualizarUser/${currentUser.id}`, formData);
                    fetchUsers();
                    resetForm();
                    setIsEditing(false);
                    Swal.fire({
                        title: '¡Éxito!',
                        text: 'Usuario actualizado exitosamente.',
                        icon: 'success',
                        timer: 2000,
                        showConfirmButton: false
                    }).then(() => {
                        navigate('/usuarios_admin.js');
                    });
                } catch (error) {
                    console.error('Error updating user:', error);
                    Swal.fire({
                        title: 'Error!',
                        text: error.response?.data?.message || 'Error al actualizar el usuario.',
                        icon: 'error',
                        timer: 3000,
                        showConfirmButton: false
                    });
                }
            } else if (result.isDenied) {
                Swal.fire({
                    title: 'Cambios no guardados',
                    text: 'Los cambios que has hecho no se guardaron.',
                    icon: 'info',
                    timer: 2000,
                    showConfirmButton: false
                }).then(() => {
                    navigate('/usuarios_admin.js');
                });
            }
        });
    } else {
        try {
            // Registrar al usuario con estado "Pendiente"
            const response = await axios.post('http://localhost:4001/registrarUser', {
                ...formData,
                estado: 'Pendiente'
            });

            // Verifica que el registro fue exitoso
            console.log('Usuario registrado, respuesta del servidor:', response);

            // Alerta para revisar correo electrónico
            await Swal.fire({
                title: 'Revisa tu correo electrónico',
                text: 'Para activar tu cuenta.',
                icon: 'info',
                timer: 1000,
                showConfirmButton: false,  // Elimina el temporizador para esperar confirmación del usuario
            });

        } catch (error) {
            console.error('Error saving user:', error);
            let errorMessage;

            // Manejar errores específicos según el mensaje del backend
            if (error.response) {
                if (error.response.status === 400 && error.response.data.message === 'El usuario ya está registrado.') {
                    errorMessage = 'El usuario ya existe con ese número de documento.';
                } else {
                    errorMessage = error.response.data.message || 'Error al guardar el usuario.';
                }
            } else {
                errorMessage = 'Error al guardar el usuario.';
            }

            Swal.fire({
                title: 'Error!',
                text: errorMessage,
                icon: 'error',
                timer: 3000,
                showConfirmButton: false
            });
        }
    }
};

  const handleEditUser = (user) => {
    setIsEditing(true);
    setCurrentUser(user);
    setFormData(user);
  };

// Inactivacion usuario
const handleSetInactiveUser = async (id_usuario) => {
  const confirmInactive = await Swal.fire({
      title: '¿Estás seguro?',
      text: 'El usuario será marcado como inactivo.',
      icon: 'warning',
      showCancelButton: true,
      confirmButtonText: 'Sí, inactivar',
      cancelButtonText: 'Cancelar',
      confirmButtonColor: '#d33',
      cancelButtonColor: '#3085d6',
  });

  if (confirmInactive.isConfirmed) {
      try {
          // Llamar al procedimiento almacenado para cambiar el estado
          await axios.put(`http://localhost:4001/cambiarEstadoUsuario/${id_usuario}`, {
              estado: 'inactivo' // Cambiar a 'inactivo'
          });

          Swal.fire({
              title: '¡Inactivado!',
              text: 'Usuario marcado como inactivo exitosamente.',
              icon: 'success',
              timer: 2000,
              showConfirmButton: false
          }).then(() => {
              fetchUsers(); // Volver a cargar la lista de usuarios
          });
      } catch (error) {
          console.error('Error setting user inactive:', error);
          Swal.fire({
              title: 'Error!',
              text: 'Error al inactivar el usuario.',
              icon: 'error',
              confirmButtonText: 'OK',
              confirmButtonColor: '#d33',
          });
      }
  }
};

  // Reset form to initial state
  const resetForm = () => {
    setFormData({
      nombres: '',
      apellidos: '',
      telefono: '',
      correo_electronico: '',
      tipo_doc: '',
      num_doc: '',
      rol: '',
      estado: 'Activo',
    });
    setCurrentUser(null);
    setIsEditing(false);
  };

  // Handle search input change
  const handleSearchChange = (e) => {
    setSearchTerm(e.target.value);
  };

  // Handle user type filter change
  const handleUserTypeFilterChange = (e) => {
    setUserTypeFilter(e.target.value);
  };

// Nuevo manejador de eventos para evitar números
const handleKeyPress = (e) => {
  // Expresión regular para evitar números
  const regex = /[0-9]/;
  
  // Si el carácter presionado es un número, prevenir la entrada
  if (regex.test(e.key)) {
    e.preventDefault();
  }
};

  const renderUserTable = () => {
    return (
      <div className="table-container">
      <table className="table table-striped mt-4">
        <thead>
          <tr>
          <th>Nº Identificación</th>
            <th>Nombres</th>
            <th>Apellidos</th>
            <th>Correo Electrónico</th>
            <th>Teléfono</th>
            <th>Tipo de Documento</th>
            <th>Rol</th>
            <th>Estado</th>
            <th>Editar</th>
            <th>Desactivar</th>
          </tr>
        </thead>
        <tbody>
          {currentRecordsUser.map(user => (
            <tr key={user.num_doc}>
              <td>{user.num_doc}</td>
              <td>{user.nombres}</td>
              <td>{user.apellidos}</td>
              <td>{user.correo_electronico}</td>
              <td>{user.telefono}</td>
              <td>{user.tipo_doc}</td>
              <td>{user.rol}</td>
              <td>{user.estado}</td>
              <td>
                  <div className="center-buttons">
    <button
      type="button"
      className="button-style"
      data-bs-toggle="modal"
      data-bs-target="#registroUserModal"
      onClick={() => handleEditUser(user)}
    >
      <FontAwesomeIcon icon={faEdit} />
    </button>
  </div>
</td>
<td>
  <div className="center-buttons">
    <button
      type="button"
      className="button-style"
      onClick={() => handleSetInactiveUser(user.id_usuario)}
    >
      <FontAwesomeIcon icon={faTrash} />
    </button>
  </div>
</td>
            </tr>
          ))}
        </tbody>
      </table>
      </div>
    );
  };
  return (
    <div>
      <Header2 />
      <div className="container">
        <section className="container mt-5">
          <h2>Registro de usuarios</h2>
          <br />
          <div className="d-flex justify-content-between align-items-center mb-3 position-relative">
            {/* Barra de búsqueda */}
            <div className="d-flex align-items-center">
              <FontAwesomeIcon icon={faSearch} className="me-2" style={{ fontSize: '20px' }} />
              <input
                type="text"
                id="searchInput"
                className="form-control"
                placeholder="Buscar Usuario"
                value={searchTerm}
                onChange={handleSearchChange}
                required
              />
              {/* Ícono de filtro */}
              <button
                type="button"
                className="btn btn-light ms-2 position-relative"
                onClick={() => setShowFilters(!showFilters)}
              >
                <FontAwesomeIcon icon={faFilter} style={{ fontSize: '20px' }} />
              </button>
              {showFilters && (
                <div ref={filterMenuRef} className="filter-menu position-absolute mt-2 p-2 bg-white border rounded shadow">
                  <select id="userTypeFilter" className="form-select" value={userTypeFilter} onChange={handleUserTypeFilterChange}>
                    <option value="todos">Todos</option>
                    <option value="UsuariosAdmin">UsuariosAdmin</option>
                    <option value="Cliente">Cliente</option>
                    </select>
            </div>
          )}
        </div>
    

       
            {/* Botón para abrir el modal */}
            <button
              type="button"
              className="btn btn-success"
              data-bs-toggle="modal"
              data-bs-target="#registroUserModal"
              onClick={resetForm}
            >
              Registrar Usuario
            </button>
            </div>
          <div className="modal fade" id="registroUserModal" tabIndex={-1} aria-labelledby="registroUserModalLabel" aria-hidden="true">
            <div className="modal-dialog">
              <div className="modal-content">
                <div className="modal-header">
                  <h5 className="modal-title" id="registroUserModalLabel">Registrar Usuario</h5>
                  <button type="button" className="btn-close" data-bs-dismiss="modal" aria-label="Close" />
                </div>
                <div className="modal-body">
                  <form>
                    {/* Formulario de registro */}
                    <div className="mb-3">
                      <label htmlFor="tipo_doc" className="form-label">Tipo de Documento</label>
                      <select className="form-select" id="tipo_doc" value={formData.tipo_doc} onChange={handleInputChange} required>
                        <option value="" disabled>Selecciona una opción</option>
                        <option value="cedula extranjeria">CE</option>
                        <option value="tarjeta de identidad">TI</option>
                        <option value="cedula de ciudadania">CC</option>
                        </select>
                        </div>
                    <div className="mb-3">
                      <label htmlFor="num_doc" className="form-label">Nº Identificación</label>
                      <input type="number" className="form-control" id="num_doc" placeholder="Ingrese Nº Identificación" value={formData.num_doc} onChange={handleInputChange} required />
                    </div>
                    <div className="mb-3">
                      <label htmlFor="nombres" className="form-label">Nombres</label>
                      <input type="text" className="form-control" id="nombres" placeholder="Ingrese Nombres" value={formData.nombres} onChange={handleInputChange} onKeyPress={handleNameKeyPress} required/>
                    </div>
                    <div className="mb-3">
                      <label htmlFor="apellidos" className="form-label">Apellidos</label>
                      <input type="text" className="form-control" id="apellidos" placeholder="Ingrese Apellidos" value={formData.apellidos} onChange={handleInputChange} onKeyPress={handleKeyPress}required />
                    </div>
                    <div className="mb-3">
                      <label htmlFor="correo_electronico" className="form-label">Correo Electrónico</label>
                      <input type="email" className="form-control" id="correo_electronico" placeholder="Ingrese Correo Electrónico" value={formData.correo_electronico} onChange={handleInputChange}required />
                    </div>
                    <div className="mb-3">
                      <label htmlFor="telefono" className="form-label">Número Celular</label>
                      <input type="number" className="form-control" id="telefono" placeholder="Ingrese Número Celular" value={formData.telefono} onChange={handleInputChange} required/>
                    </div>
                    <div className="mb-3">
                      <label htmlFor="rol" className="form-label">Rol</label>
                      <select className="form-select" id="rol" value={formData.rol} onChange={handleInputChange} required>
                        <option value="" disabled>Selecciona una opción</option>
                        <option value="domiciliario">Domiciliario</option>
                        <option value="jefe de produccion">Jf Producción</option>
                        <option value="Gerente">Gerente</option>
                        </select>
                </div>
              </form>
            </div>
                <div className="modal-footer">
                  <button type="button" className="btn btn-secondary" data-bs-dismiss="modal" onClick={resetForm}>Cerrar</button>
                  <button type="button" className="btn btn-success" onClick={handleSaveUser}>
                    {isEditing ? 'Guardar Cambios' : 'Guardar'}
                    </button>
            </div>
          </div>
        </div>
      </div>
     
      {renderUserTable()}

{/* Paginación */}
<div className="d-flex justify-content-center mt-4">
  <nav>
  <ul className="pagination">
                          <li
                            className={`paginate_button page-item  ${
                              currentPageUser === 1 ? "disabled" : ""
                            }`}
                          >
                            <Link
                              onClick={() =>
                                handlePageChangeUser(currentPageUser - 1)
                              }
                              to="#"
                              className="page-link"
                            >
                              Anterior
                            </Link>
                          </li>
                          {[...Array(totalPagesUser)].map((_, index) => (
                            <li
                              key={index}
                              className={`paginate_button page-item ${
                                currentPageUser === index + 1 ? "active" : ""
                              }`}
                            >
                              <button
                                onClick={() => handlePageChangeUser(index + 1)}
                                className="page-link"
                              >
                                {index + 1}
                              </button>
                            </li>
                          ))}
                          <li
                            className={`paginate_button page-item next ${
                              currentPageUser === totalPagesUser ? "disabled" : ""
                            }`}
                          >
                            <Link
                              onClick={() =>
                                handlePageChangeUser(currentPageUser + 1)
                              }
                              to="#"
                              className="page-link"
                            >
                              Siguiente
                            </Link>
                          </li>
    </ul>
  </nav>
</div>
</section>
</div>
</div>
      
  );
};

export default UsuariosAdmin;