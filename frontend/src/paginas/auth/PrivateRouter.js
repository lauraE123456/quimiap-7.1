// src/componentes/PrivateRoute.js
import React from 'react';
import { Navigate } from 'react-router-dom';

const PrivateRoute = ({ children, allowedRoles }) => {
    // Obtén el rol del usuario desde sessionStorage
    const userRole = sessionStorage.getItem("userRole");

    // Verifica si el rol del usuario está en la lista de roles permitidos
    return allowedRoles.includes(userRole) ? children : <Navigate to="/AccesoDenegado.js" />;
};

export default PrivateRoute;
