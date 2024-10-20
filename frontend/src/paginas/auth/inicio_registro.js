import React, { useState, useEffect } from 'react';
import '../../styles/inicio_registro.css';
import Header from "../../componentes/header1";
import Footer from "../../componentes/footer";
import { useNavigate, Link } from 'react-router-dom';
import axios from 'axios';
import Swal from 'sweetalert2';
import bcrypt from 'bcryptjs';

const Inicio_registro = () => {
    const [formData, setFormData] = useState({
        nombres: '',
        apellidos: '',
        telefono: '',
        correo_electronico: '',
        tipo_doc: '',
        num_doc: '',
        contrasena: '',
        rol: 'Cliente',
        estado: 'Pendiente'
    });
    const [showPassword, setShowPassword] = useState(false);
    const [phoneError, setPhoneError] = useState('');
    const [passwordError, setPasswordError] = useState('');
    const [passwordLengthError, setPasswordLengthError] = useState('');
    const [allowLetters, setAllowLetters] = useState(false);
    const [contadorCarrito, setContadorCarrito] = useState(0); // Estado para el contador del carrito
    const [carrito, setCarrito ] = useState([]);


    const actualizarContador = (nuevoCarrito) => {
        const totalProductos = nuevoCarrito.reduce((total, producto) => total + producto.cantidad, 0);
        setContadorCarrito(totalProductos);
      };

      useEffect(() => {
        const carritoGuardado = JSON.parse(localStorage.getItem('carrito')) || [];
        setCarrito(carritoGuardado);
        actualizarContador(carritoGuardado); // Inicializa el contador con los productos en el carrito
      }, []);
    
    const togglePassword = () => {
        setShowPassword(prevShowPassword => !prevShowPassword);
    };

    const validatePassword = (password) => {
        const minLength = 8;
        const maxLength = 16;
        const hasUpperCase = /[A-Z]/.test(password);
        const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
        const lengthValid = password.length >= minLength && password.length <= maxLength;

        if (!lengthValid) {
            return 'La contraseña debe tener entre 8 y 16 caracteres.';
        }
        if (!hasUpperCase) {
            return 'La contraseña debe contener al menos una letra mayúscula.';
        }
        if (!hasSpecialChar) {
            return 'La contraseña debe contener al menos un carácter especial.';
        }

        return '';
    };
    // registrar usuarios
    const handleRegisterSubmit = async (event) => {
        event.preventDefault();
        
        // Verificar errores individuales y mostrar alertas
        if (phoneError) {
            Swal.fire({
                title: 'Error',
                text: 'Número de teléfono inválido.',
                icon: 'error',
                timer: 2000,
                showConfirmButton: false
            });
            return;
        }
        
        if (passwordError) {
            Swal.fire({
                title: 'Error en la Contraseña',
                text: 'La contraseña es incorrecta, ingresa los campos que se solicitan ',
                icon: 'error',
                timer: 2000,
                showConfirmButton: false
            });
            return;
        }
        
        if (passwordLengthError) {
            Swal.fire({
                title: 'Error',
                text: 'La contraseña debe tener al menos 8 caracteres.',
                icon: 'error',
                timer: 2000,
                showConfirmButton: false
            });
            return;
        }
        
        try {
            // Verificar si el correo ya está registrado
            const checkResponse = await axios.get(`http://localhost:4001/usuarios/correo/${encodeURIComponent(formData.correo_electronico)}`);
        
            if (checkResponse.data.length > 0) {
                // Si el correo ya está en la base de datos, mostrar la alerta
                await Swal.fire({
                    title: 'Cuenta ya existe',
                    text: 'El correo electrónico ya está registrado. Por favor, inicia sesión.',
                    icon: 'warning',
                    timer: 2000,
                    showConfirmButton: false
                });
                return; // Detener el flujo aquí si la cuenta ya existe
            }
            // Verificar si el número de documento ya existe
    try {
        const checkResponse = await axios.get(`http://localhost:4001/usuarios/documento/${encodeURIComponent(formData.num_doc)}`);

        if (checkResponse.data.length > 0) {
            // Si el número de documento ya está en la base de datos, mostrar la alerta
            await Swal.fire({
                title: 'Número de Documento ya existe',
                text: 'El número de documento ya está registrado. Por favor, verifica los datos.',
                icon: 'warning',
                timer: 2000,
                showConfirmButton: false
            });
            return; // Detener el flujo aquí si el número de documento ya existe
                }
            } catch (error) {
                console.error('Error checking document number:', error);
                Swal.fire({
                    title: 'El',
                    text: 'Ocurrió un error al verificar el número de documento.',
                    icon: 'error',
                    timer: 2000,
                    showConfirmButton: false
                });
                return; // Detener el flujo en caso de error en la verificación
            }
        
            // Encripta la contraseña antes de enviarla al servidor
            const hashedPassword = bcrypt.hashSync(formData.contrasena, 10);
        
            // Si el correo no existe, proceder con el registro
            const response = await axios.post("http://localhost:4001/registrarUser", {
                ...formData,
                contrasena: hashedPassword,
                estado: "Pendiente" // Cambia el estado a pendiente
            });
        
            // Mostrar mensaje de éxito tras el registro
            await Swal.fire({
                title: 'Revisa tu correo electrónico',
                text: 'Para activar tu cuenta.',
                icon: 'info',
                timer: 2000,
                showConfirmButton: false
            });
            window.location.href = '/';
        
            // Enviar el correo de verificación
            const verificationResponse = await axios.post('http://localhost:5000/enviar-verificacion', {
                correo_electronico: formData.correo_electronico,
                id: response.data.id_usuario
            });
        
            console.log('Correo de verificación enviado:', verificationResponse.data);
        
        } catch (error) {
            console.error("Error al enviar los datos:", error);
        
            Swal.fire({
                title: 'Error',
                text: 'Hubo un problema al registrar tu cuenta. Inténtalo de nuevo.',
                icon: 'error',
                timer: 2000,
                showConfirmButton: false
            });
        }
    };

    const handleChange = (event) => {
        const { name, value } = event.target;

        if (name === 'telefono') {
            // Elimina cualquier carácter que no sea un número
            const sanitizedValue = value.replace(/\D/g, '');
    
            // Si el valor tiene más de 10 dígitos, lo recorta
            const limitedValue = sanitizedValue.slice(0, 10);
    
            if (limitedValue.length <= 10) {
                setPhoneError(''); // Limpia el error si es válido
                setFormData(prevFormData => ({
                    ...prevFormData,
                    [name]: limitedValue // Solo actualiza si es válido
                }));
            } else {
                setPhoneError('El número de teléfono no debe tener más de 10 dígitos.');
            }
            return; // Se asegura que no pase al siguiente bloque
        }

        if (name === 'contrasena') {
            let newValue = value;
            if (newValue.length > 16) {
                newValue = newValue.slice(0, 14); // Limita a 16 caracteres
                setPasswordLengthError('La contraseña no puede tener más de 14 caracteres.');
            } else {
                setPasswordLengthError('');
            }
            setPasswordError(validatePassword(newValue));
            setFormData(prevFormData => ({
                ...prevFormData,
                [name]: newValue
            }));
            return;
        }

        setFormData(prevFormData => ({
            ...prevFormData,
            [name]: value
        }));
    };
    // Función para prevenir el pegar en el campo de contraseña
    const handlePaste = (event) => {
        if (event.target.name === 'contrasena') {
            event.preventDefault();
            setPasswordError('No se permite pegar en el campo de contraseña.');
        }
    };

    const handleKeyPress = (event) => {
        if (!/^[a-zA-Z\s]*$/.test(event.key)) {
            event.preventDefault();
        }
    };
    

    useEffect(() => {
        const script = document.createElement('script');
        script.src = '/script/login.js';
        script.async = true;
        document.body.appendChild(script);

        return () => {
            document.body.removeChild(script);
        };
    }, []);

    /*inicio de sesion*/
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [isAuthenticated, setIsAuthenticated] = useState(
        sessionStorage.getItem("isAuthenticated") === "true"
    );
    const [userName, setUserName] = useState(() => {
        return sessionStorage.getItem("userName") || "";
    });
    const navigate = useNavigate();

    useEffect(() => {
        if (isAuthenticated) {
            const storedUserName = sessionStorage.getItem("userName");
            if (storedUserName) {
                setUserName(storedUserName);
            }
        } else {
            setUserName("");
        }
    }, [isAuthenticated]);

    const handleLogin = async (e) => {
        e.preventDefault();
    
        try {
            // Realizar una solicitud POST a la API para el inicio de sesión
            const response = await axios.post("http://localhost:4001/login", {
                correo_electronico: email,
                contrasena: password
            });
            console.log('Correo electrónico enviado:', email);
            console.log('Contraseña enviada:', password);

            const user = response.data.user; // Obtener datos del usuario de la respuesta
            console.log('Respuesta del servidor:', response.data);

    
            if (user) {
                // Verificar el estado del usuario
                if (user.estado === "activo") {
                    // Guardar datos del usuario en sessionStorage
                    sessionStorage.setItem("isAuthenticated", "true");
                    sessionStorage.setItem("userRole", user.rol);
                    sessionStorage.setItem("userName", user.nombres);
                    sessionStorage.setItem("userId", user.id_usuario);
                    setIsAuthenticated(true);
                    setUserName(user.nombres);
    
                    // Mostrar alerta de inicio de sesión exitoso
                    await Swal.fire({
                        title: 'Inicio de sesión exitoso',
                        text: `Bienvenid@, ${user.nombres}!`,
                        icon: 'success',
                        timer: 2000,
                        showConfirmButton: false
                    });
    
                  // Navegar según el rol del usuario
const route = user.rol.toLowerCase() === "cliente" ? "/" :
user.rol.toLowerCase() === "jefe de produccion" ? "/jf_produccion.js" :
user.rol.toLowerCase() === "domiciliario" ? "/domiciliario.js" :
user.rol.toLowerCase() === "gerente" ? "/usuarios_admin.js" : "/";

navigate(route);

                } else if (user.estado === "Pendiente") {
                    // Mostrar alerta si el usuario está pendiente
                    await Swal.fire({
                        title: 'Cuenta Pendiente',
                        text: 'Tu cuenta está pendiente de verificación. Por favor, revisa tu correo electrónico para completar la verificación.',
                        icon: 'info',
                        timer: 2000,
                        showConfirmButton: false
                    });
                } else if (user.estado === "Inactivo") {
                    // Mostrar alerta si el usuario está inactivo
                    await Swal.fire({
                        title: 'Cuenta Inactiva',
                        text: 'Tu cuenta está inactiva. Por favor, contacta a soporte.',
                        icon: 'warning',
                        timer: 2000,
                        showConfirmButton: false
                    });
                }
            } else {
                // Mostrar alerta si el usuario no es encontrado
                await Swal.fire({
                    title: 'Error',
                    text: 'Correo o contraseña incorrectos',
                    icon: 'error',
                    timer: 2000,
                    showConfirmButton: false
                });
            }
        } catch (error) {
            // Manejo de errores
            if (error.response) {
                // La solicitud fue realizada y el servidor respondió con un código de estado que no está en el rango de 2xx
                console.error("Error en la respuesta del servidor:", error.response.data);
                console.error("Código de estado:", error.response.status);
                
                // Mostrar alerta personalizada según el código de error
                if (error.response.status === 403) {
                    await Swal.fire({
                        title: 'Acceso Prohibido',
                        text: 'No tienes permiso para acceder a esta acción. Por favor, verifica tus credenciales.',
                        icon: 'error',
                        timer: 2000,
                        showConfirmButton: false
                    });
                } else if (error.response.status === 401) {
                    await Swal.fire({
                        title: 'Error',
                        text: 'Credenciales incorrectas. Por favor, intenta nuevamente.',
                        icon: 'error',
                        timer: 2000,
                        showConfirmButton: false
                    });
                } else {
                    await Swal.fire({
                        title: 'Error',
                        text: 'Ocurrió un error durante el inicio de sesión. Por favor, intente nuevamente.',
                        icon: 'error',
                        timer: 2000,
                        showConfirmButton: false
                    });
                }
            } else if (error.request) {
                // La solicitud fue realizada pero no se recibió respuesta
                console.error("Error en la solicitud:", error.request);
                await Swal.fire({
                    title: 'Error',
                    text: 'No se recibió respuesta del servidor. Por favor, verifica tu conexión.',
                    icon: 'error',
                    timer: 2000,
                    showConfirmButton: false
                });
            } else {
                // Algo sucedió al configurar la solicitud que lanzó un error
                console.error("Error:", error.message);
                await Swal.fire({
                    title: 'Error',
                    text: 'Ocurrió un error al intentar iniciar sesión. Por favor, intenta nuevamente.',
                    icon: 'error',
                    timer: 2000,
                    showConfirmButton: false
                });
            }
        }
    };
    
    
     // Maneja el cambio en el tipo de documento
     const handleTipoDocChange = (event) => {
        const { value } = event.target;

        // Actualiza el estado del tipo de documento
        setFormData((prevData) => ({
            ...prevData,
            tipo_doc: value,
            num_doc: '' // Resetea el campo de identificación al cambiar el tipo de documento
        }));

        // Verifica el tipo de documento seleccionado
        if (value === "cedula extranjería") {
            setAllowLetters(true); // Permite letras y números
        } else {
            setAllowLetters(false); // Solo permite números para tarjeta y cédula
        }
    };
    
    // Maneja el cambio en el campo de identificación
    const handleIdentificacionChange = (event) => {
        const { value } = event.target;

        // Lógica para cédula (10 dígitos solo numéricos) y tarjeta (10 dígitos solo numéricos)
        if ((formData.tipo_doc === "cedula de ciudadania" || formData.tipo_doc === "tarjeta de identidad") && /^[0-9]{0,10}$/.test(value)) {
            setFormData((prevData) => ({ ...prevData, num_doc: value }));
        } 
        // Lógica para cédula de extranjería (10-12 caracteres alfanuméricos)
        else if (formData.tipo_doc === "cedula extranjeria" && /^[a-zA-Z0-9]{0,12}$/.test(value) && value.length <= 12) {
            setFormData((prevData) => ({ ...prevData, num_doc: value }));
        }
    };
    //solicitar correo en olvisdate tu contraseña:
    const handleForgotPasswordClick = async () => {
        // Mostrar alerta para que el usuario ingrese su correo
        const { value: email } = await Swal.fire({
            title: 'Recuperar contraseña',
            input: 'email',
            inputLabel: '      Por favor ingresa tu correo electrónico para recuperar la contraseña:',
            inputPlaceholder: 'correo@ejemplo.com',
            showCancelButton: true,
            confirmButtonText: 'Enviar',
            confirmButtonColor: '#45A049',
            cancelButtonText: 'Cancelar',
            inputValidator: (value) => {
                if (!value) {
                    return 'Debes ingresar un correo electrónico';
                }
            }
        });
    
        if (email) {
            try {
                // Verificar si el correo existe en la base de datos
                const checkResponse = await fetch(`http://localhost:4001/usuarios?correo_electronico=${email}`);
                const data = await checkResponse.json();
    
                if (data.length > 0) {
                    // Si el correo existe, enviar el correo de restablecimiento de contraseña
                    const response = await fetch('http://localhost:5000/enviar-restablecer-contrasena', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ correo_electronico: email })
                    });
    
                    if (response.ok) {
                        // Mostrar alerta de éxito si se envió el correo correctamente
                        Swal.fire({
                            icon: 'success',
                            title: 'Correo enviado',
                            text: 'Se ha enviado un link de recuperación a tu correo electrónico.',
                            timer: 2000,
                            showConfirmButton: false
                        });
                    } else {
                        // Mostrar alerta de error si no se pudo enviar el correo
                        Swal.fire({
                            icon: 'error',
                            title: 'Error',
                            text: 'Hubo un problema al enviar el correo. Inténtalo de nuevo.',
                            timer: 2000,
                            showConfirmButton: false
                        });
                    }
                } else {
                    // Mostrar alerta si el correo no existe en la base de datos
                    Swal.fire({
                        icon: 'error',
                        title: 'Usuario no encontrado',
                        text: 'El correo electrónico no está registrado. Por favor, regístrate.',
                        timer: 3000,
                        showConfirmButton: false
                    });
                }
            } catch (error) {
                console.error("Error:", error);
                Swal.fire({
                    icon: 'error',
                    title: 'Error',
                    text: 'Hubo un error al verificar el correo. Inténtalo de nuevo.',
                    timer: 2000,
                    showConfirmButton: false
                });
            }
        }
    };
    return (
        <div className="registro-container">
      <Header productos={[]} contadorCarrito={contadorCarrito} />
            <br/>
            <br/>
            <br/>
            <br/>
            <br/>

            <br/>
            <br/>
            <br/>
            <br/>

            <div className="main">
                <div className="contenedor__todo">
                    <div className="caja__trasera">
                        <div className="caja__trasera-login">
                            <h3>¿Ya tienes una cuenta?</h3>
                            <p>Inicia sesión para entrar en la página</p>
                            <button id="btn__iniciar-sesion">Iniciar Sesión</button>
                        </div>
                        <div className="caja__trasera-register">
                            <h3>¿Aún no tienes una cuenta?</h3>
                            <p>Regístrate para que puedas iniciar sesión</p>
                            <button id="btn__registrarse">Regístrarse</button>
                        </div>
                    </div>
                    {/*Formulario de Login y registro*/}
                    <div className="contenedor__login-register">
                        {/*Login*/}
                        <form onSubmit={handleLogin} className="formulario__login">
                            <h2 style={{ marginBottom: '80px' }}>Iniciar Sesión</h2>
                            <label htmlFor="email">Correo Electrónico:</label>
                            <input type="email" placeholder="Ingresa correo electrónico"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                required
                            />
                            <label htmlFor="password">Contraseña:</label>
                            <div className="input-container">
                                <input 
                                    type={showPassword ? "text" : "password"}
                                    placeholder="Ingresa la contraseña"
                                    name="contrasena"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    onPaste={handlePaste}
                                    required
                                />
                                <button type="button" className="btn-toggle-visibility" onClick={togglePassword}>
                                    <i className={showPassword ? "bi bi-eye-slash" : "bi bi-eye"} />
                                </button>
                            </div>
                            <div style={{ marginTop: '20px', textAlign: 'left' }}>
                                <Link to="#" 
                                style={{ color: '#28a745', textDecoration: 'none' }}
                                onClick={handleForgotPasswordClick}
                                >
                                    ¿Olvidaste tu contraseña?
                                </Link>
                            </div>
                            <div style={{textAlign: 'right'}}>
                                <button type="submit">Ingresar</button>
                            </div>
                        </form>

                        {/*Register*/}
                        <form onSubmit={handleRegisterSubmit} className="formulario__register" style={{padding: '10px 20px'}}>
                            <h2>Registrarse</h2>
                            <select 
                                id="tipoDoc" 
                                name="tipo_doc" 
                                className="tipoDoc"
                                value={formData.tipo_doc}
                                onChange={handleTipoDocChange}
                                required
                            >
                                <option value="" disabled>Tipo Documento</option>
                                <option value="cedula extranjeria">CE</option>
                                <option value="tarjeta de identidad">TI</option>
                                <option value="cedula de ciudadania">CC</option>
                            </select>

                            <input 
                                type="text" 
                                placeholder="N° identificación" 
                                id="identificacion" 
                                name="num_doc"
                                value={formData.num_doc}
                                onChange={handleIdentificacionChange}
                                required 
                            />

                            <label htmlFor="nombres">Nombres:</label>
                            <input 
                                type="text" 
                                placeholder="Ingrese sus nombres" 
                                name="nombres"
                                value={formData.nombres}
                                onChange={handleChange}
                                onKeyPress={handleKeyPress}
                                required 
                            />

                            <label htmlFor="apellidos">Apellidos:</label>
                            <input 
                                type="text" 
                                placeholder="Ingrese sus apellidos" 
                                name="apellidos"
                                value={formData.apellidos}
                                onChange={handleChange}
                                onKeyPress={handleKeyPress}
                                required 
                            />

                            <label htmlFor="telefono">Teléfono:</label>
                            <input 
                                type="number" 
                                placeholder="Dijite su telefono" 
                                name="telefono"
                                value={formData.telefono}
                                onChange={handleChange}
                                maxLength={10}
                                required 
                            />
                            {phoneError && <div className="error-message">{phoneError}</div>}

                            <label htmlFor="correo_electronico">Correo Electrónico:</label>
                            <input 
                                type="email" 
                                placeholder="Ingrese su correo" 
                                name="correo_electronico"
                                value={formData.correo_electronico}
                                onChange={handleChange}
                                required 
                            />

                            <label htmlFor="contrasena">Contraseña:</label>
                            <div className="input-container">
                                <input 
                                type={showPassword ? "text" : "password"}
                                placeholder="Ingrese una contraseña" 
                                name="contrasena"
                                value={formData.contrasena}
                                onChange={handleChange}
                                onPaste={handlePaste}
                                required
                                maxLength={16} 
                                />
                                <button type="button" className="btn-toggle-visibility" onClick={togglePassword}>
                                <i className={showPassword ? "bi bi-eye-slash" : "bi bi-eye"} />
                                </button>
                            </div>
                            {passwordError && <div className="error-message">{passwordError}</div>}
                            {passwordLengthError && <div className="error-message">{passwordLengthError}</div>}

                            <div className="checkbox-container">
                                <input
                                type="checkbox"
                                id="terminos"
                                name="terminos"
                                className="caja"
                                required
                                />
                                <label htmlFor="terminos">
                                Autorizo el Tratamiento de datos. Acepto los Términos y Condiciones
                                </label>
                            </div>

                            <div className="registrarse">
                                <button type="submit">Registrarse</button>
                            </div>
                        </form>

                    </div>
                </div>
            </div>
            <br/>
            <br/>

            <Footer/>
        </div>
    );
}

export default Inicio_registro;
