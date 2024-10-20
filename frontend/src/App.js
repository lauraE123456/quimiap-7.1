import React, { Fragment } from "react";
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Bienvenida from "./paginas/auth/bienvenida";
import Nosotros from "./paginas/auth/nosotros";
import Contacto from "./paginas/auth/contactanos";
import UsuariosAdmin from "./paginas/auth/usuarios_admin";
import Productos from "./paginas/auth/productos";
import VentasAdmin from "./paginas/auth/ventas_admin";
import DomicilioAdmin from "./paginas/auth/domicilios_admin";
import Carrito from "./paginas/auth/carrito";
import JfProduccion from "./paginas/auth/jf_produccion";
import VentasjfProduccion from "./paginas/auth/ventas_jfproduccion";
import Domiciliario from "./paginas/auth/domiciliario";
import VentasDomiciliario from "./paginas/auth/ventas_domiciliario";
import VentasCliente from "./paginas/auth/venta_cliente";
import MisVentas from "./paginas/auth/MisVentas";
import Inicio_registro from "./paginas/auth/inicio_registro";
import PrivateRoute from './componentes/PrivateRoute';
import AccesoDenegado from "./paginas/auth/AcessoDenegado";
import PerfilPage from "./paginas/auth/perfil";




function App() {
  return (
    <Fragment>
      <Router>
        <Routes>
          <Route path='/' exact element={<Bienvenida />} />
          <Route path='/nosotros.js' exact element={<Nosotros />} />
          
          
          {/* Rutas protegidas */}
          <Route path='/usuarios_admin.js' exact element={
              <UsuariosAdmin />
          } />
          <Route path='/perfil.js' exact element={
            <PrivateRoute allowedRoles={['Cliente']}>
              <PerfilPage />
            </PrivateRoute>
          } />
          <Route path='/productos.js' exact element={<Productos />} />
          <Route path='/ventas_admin.js' exact element={
            <PrivateRoute allowedRoles={['Gerente']}>
              <VentasAdmin />
            </PrivateRoute>
          } />
          <Route path='/domicilios_admin.js' exact element={
            <PrivateRoute allowedRoles={['Gerente']}>
              <DomicilioAdmin />
            </PrivateRoute>
          } />
          <Route path='/carrito.js' exact element={<Carrito />} />
          
          <Route path='/jf_produccion.js' exact element={
            <PrivateRoute allowedRoles={['jefe de produccion']}>
              <JfProduccion />
            </PrivateRoute>
          } />
          <Route path='/ventas_jfproduccion.js' exact element={
            <PrivateRoute allowedRoles={['jefe de produccion']}>
              <VentasjfProduccion />
            </PrivateRoute>
          } />
            <Route path='/contactanos.js' exact element={
              <Contacto />
          } />
          
          <Route path='/domiciliario.js' exact element={
            <PrivateRoute allowedRoles={['domiciliario']}>
              <Domiciliario />
            </PrivateRoute>
          } />
          <Route path='/ventas_domiciliario.js' exact element={
            <PrivateRoute allowedRoles={['domiciliario']}>
              <VentasDomiciliario />
            </PrivateRoute>
          } />
          
          <Route path='/venta_cliente.js' exact element={<VentasCliente />} />
          <Route path='/MisVentas.js' exact element={
            <PrivateRoute allowedRoles={['Cliente']}>
              <MisVentas />
            </PrivateRoute>
          } />
          <Route path='/inicio_registro.js' exact element={<Inicio_registro />} />
          {/* Ruta de acceso no autorizado */}
          <Route path="/AccesoDenegado.js" element={<AccesoDenegado />} />
          
        </Routes>
      </Router>
    </Fragment>
  );
}

export default App;
