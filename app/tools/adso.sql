-- phpMyAdmin SQL Dump
-- version 5.2.0
-- https://www.phpmyadmin.net/
--
-- Servidor: localhost:8889
-- Tiempo de generación: 28-08-2024 a las 14:51:01
-- Versión del servidor: 5.7.39
-- Versión de PHP: 8.2.0

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Base de datos: `adso`
--

DELIMITER $$
--
-- Procedimientos
--
CREATE DEFINER=`root`@`localhost` PROCEDURE `AsignarRolUsuario` (IN `p_usuario_id` INT, IN `p_rol_id` INT)   BEGIN
    DECLARE usuario_existe INT;
    DECLARE rol_existe INT;
    
    -- Verificar si el usuario existe
    SELECT COUNT(*) INTO usuario_existe FROM usuario WHERE id = p_usuario_id;
    
    -- Verificar si el rol existe
    SELECT COUNT(*) INTO rol_existe FROM rol WHERE id = p_rol_id;
    
    -- Si ambos existen, actualizar el rol del usuario
    IF usuario_existe > 0 AND rol_existe > 0 THEN
        UPDATE usuario SET id_rol = p_rol_id WHERE id = p_usuario_id;
        SELECT 'Rol asignado correctamente' AS mensaje;
    ELSE
        SELECT 'Error: Usuario o Rol no existe' AS mensaje;
    END IF;
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `ObtenerPanelControlUsuarios` ()   BEGIN
    SELECT 
        u.id AS ID,
        u.nombre AS Nombre,
        u.email AS Correo,
        u.contrasena_hash AS Contrasena,
        r.nombre AS Rol,
        e.tipo_estado AS Estado
    FROM 
        usuario u
    LEFT JOIN 
        rol r ON u.id_rol = r.id
    LEFT JOIN 
        estado e ON u.id_estado = e.id
    ORDER BY 
        u.id;
END$$

CREATE DEFINER=`root`@`localhost` PROCEDURE `SP_CrearUsuario` (IN `_nombre_usuario` VARCHAR(255), IN `_nombre` VARCHAR(255), IN `_contrasena_hash` VARCHAR(255), IN `_email` VARCHAR(255))   BEGIN

INSERT INTO usuario(nombre_usuario, nombre, contrasena_hash, email)
VALUES (_nombre_usuario, _nombre, _contrasena_hash, _email);

END$$

DELIMITER ;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `administrador`
--

CREATE TABLE `administrador` (
  `id` int(11) NOT NULL,
  `id_estado` int(11) DEFAULT NULL,
  `nombre_admin` varchar(255) NOT NULL,
  `nombre` varchar(255) NOT NULL,
  `contrasena_hash` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `fecha_creacion` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Volcado de datos para la tabla `administrador`
--

INSERT INTO `administrador` (`id`, `id_estado`, `nombre_admin`, `nombre`, `contrasena_hash`, `email`, `fecha_creacion`) VALUES
(1, 1, 'admin1', 'Administrador Principal', 'e4abae53cc1cebe5fe89ea93882c699a5e71ab0bbf42a83b7d833975b61c4a41', 'admin@example.com', '2024-08-27 20:05:17');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `estado`
--

CREATE TABLE `estado` (
  `id` int(11) NOT NULL,
  `tipo_estado` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Volcado de datos para la tabla `estado`
--

INSERT INTO `estado` (`id`, `tipo_estado`) VALUES
(1, 'Activo'),
(2, 'Inactivo'),
(3, 'Suspendido'),
(4, 'Pendiente');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `grupos`
--

CREATE TABLE `grupos` (
  `id` int(11) NOT NULL,
  `nombre` varchar(255) NOT NULL,
  `descripcion` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Volcado de datos para la tabla `grupos`
--

INSERT INTO `grupos` (`id`, `nombre`, `descripcion`) VALUES
(1, 'Marketing', 'Equipo de marketing y publicidad'),
(2, 'Desarrollo', 'Equipo de desarrollo de software'),
(3, 'Ventas', 'Equipo de ventas y atención al cliente'),
(4, 'Recursos Humanos', 'Equipo de gestión de personal');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `historial_cambio_contrasena`
--

CREATE TABLE `historial_cambio_contrasena` (
  `id` int(11) NOT NULL,
  `id_usuario` int(11) DEFAULT NULL,
  `fecha_cambio` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `historial_sesion_usuario`
--

CREATE TABLE `historial_sesion_usuario` (
  `id` int(11) NOT NULL,
  `usuario_id` int(11) DEFAULT NULL,
  `fecha_inicio_sesion` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `direccion_ip` varchar(255) DEFAULT NULL,
  `dispositivo` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Volcado de datos para la tabla `historial_sesion_usuario`
--

INSERT INTO `historial_sesion_usuario` (`id`, `usuario_id`, `fecha_inicio_sesion`, `direccion_ip`, `dispositivo`) VALUES
(1, 1, '2024-08-26 20:05:17', '192.168.1.100', 'Windows PC'),
(2, 2, '2024-08-25 20:05:17', '192.168.1.101', 'iPhone'),
(3, 3, '2024-08-24 20:05:17', '192.168.1.102', 'Android Phone');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `integrantes_grupo`
--

CREATE TABLE `integrantes_grupo` (
  `id` int(11) NOT NULL,
  `id_grupo` int(11) DEFAULT NULL,
  `id_usuario` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Volcado de datos para la tabla `integrantes_grupo`
--

INSERT INTO `integrantes_grupo` (`id`, `id_grupo`, `id_usuario`) VALUES
(1, 1, 1),
(2, 1, 5),
(3, 1, 9),
(4, 2, 2),
(5, 2, 6),
(6, 2, 10),
(7, 3, 3),
(8, 3, 7),
(9, 3, 11),
(10, 4, 4),
(11, 4, 8),
(12, 4, 12);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `lista_blanca`
--

CREATE TABLE `lista_blanca` (
  `id` int(11) NOT NULL,
  `id_usuario` int(11) DEFAULT NULL,
  `direccion_ip` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `lista_negra`
--

CREATE TABLE `lista_negra` (
  `id` int(11) NOT NULL,
  `id_usuario` int(11) DEFAULT NULL,
  `direccion_ip` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `log_seguridad`
--

CREATE TABLE `log_seguridad` (
  `id` int(11) NOT NULL,
  `usuario_id` int(11) DEFAULT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `tipo_evento` varchar(255) DEFAULT NULL,
  `descripcion` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Volcado de datos para la tabla `log_seguridad`
--

INSERT INTO `log_seguridad` (`id`, `usuario_id`, `timestamp`, `tipo_evento`, `descripcion`) VALUES
(1, 1, '2024-08-27 20:05:17', 'Inicio de sesión', 'Inicio de sesión exitoso'),
(2, 2, '2024-08-27 20:05:17', 'Cambio de contraseña', 'El usuario cambió su contraseña'),
(3, 3, '2024-08-27 20:05:17', 'Intento de acceso fallido', 'Intento de acceso fallido desde IP desconocida');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `politica_seguridad`
--

CREATE TABLE `politica_seguridad` (
  `id` int(11) NOT NULL,
  `longitud_minima_contrasena` int(11) DEFAULT NULL,
  `intentos_fallidos_permitidos` int(11) DEFAULT NULL,
  `tiempo_expiracion_sesion` int(11) DEFAULT NULL,
  `autenticacion_dos_factores_obligatoria` tinyint(1) DEFAULT NULL,
  `intervalos_cambio_contrasena` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Volcado de datos para la tabla `politica_seguridad`
--

INSERT INTO `politica_seguridad` (`id`, `longitud_minima_contrasena`, `intentos_fallidos_permitidos`, `tiempo_expiracion_sesion`, `autenticacion_dos_factores_obligatoria`, `intervalos_cambio_contrasena`) VALUES
(1, 8, 3, 3600, 1, '2024-08-27 20:05:17');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `pregunta_seguridad`
--

CREATE TABLE `pregunta_seguridad` (
  `id` int(11) NOT NULL,
  `pregunta` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Volcado de datos para la tabla `pregunta_seguridad`
--

INSERT INTO `pregunta_seguridad` (`id`, `pregunta`) VALUES
(1, '¿Cuál es el nombre de tu primera mascota?'),
(2, '¿En qué ciudad naciste?'),
(3, '¿Cuál es el segundo nombre de tu madre?'),
(4, '¿Cuál fue tu primer coche?'),
(5, '¿Cuál es tu comida favorita?');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `respuesta`
--

CREATE TABLE `respuesta` (
  `id` int(11) NOT NULL,
  `id_pregunta` int(11) DEFAULT NULL,
  `id_usuario` int(11) DEFAULT NULL,
  `respuesta` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Volcado de datos para la tabla `respuesta`
--

INSERT INTO `respuesta` (`id`, `id_pregunta`, `id_usuario`, `respuesta`) VALUES
(1, 1, 1, 'Firulais'),
(2, 2, 2, 'Madrid'),
(3, 3, 3, 'María'),
(4, 4, 4, 'Toyota'),
(5, 5, 5, 'Pizza');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `rol`
--

CREATE TABLE `rol` (
  `id` int(11) NOT NULL,
  `nombre` varchar(255) NOT NULL,
  `descripcion` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Volcado de datos para la tabla `rol`
--

INSERT INTO `rol` (`id`, `nombre`, `descripcion`) VALUES
(1, 'Administrador', 'Control total del sistema'),
(2, 'Usuario', 'Acceso básico al sistema'),
(3, 'Moderador', 'Gestión de contenidos y usuarios'),
(4, 'Invitado', 'Acceso limitado solo lectura');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `terminos_condiciones`
--

CREATE TABLE `terminos_condiciones` (
  `descripcion` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `usuario`
--

CREATE TABLE `usuario` (
  `id` int(11) NOT NULL,
  `id_rol` int(11) DEFAULT '2',
  `id_estado` int(11) DEFAULT '1',
  `nombre_usuario` varchar(255) NOT NULL,
  `nombre` varchar(255) NOT NULL,
  `contrasena_hash` varchar(255) NOT NULL,
  `email` varchar(255) NOT NULL,
  `fecha_creacion` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Volcado de datos para la tabla `usuario`
--

INSERT INTO `usuario` (`id`, `id_rol`, `id_estado`, `nombre_usuario`, `nombre`, `contrasena_hash`, `email`, `fecha_creacion`) VALUES
(1, 2, 1, 'juanperez', 'Juan Pérez', 'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f', 'juan@example.com', '2024-08-27 20:05:17'),
(2, 4, 1, 'mariagomez', 'María Gómez', 'fbb4a8a163ffa958b4f02bf9cabb30cfefb40de803f2c4c346a9d39b3be1b544', 'maria@example.com', '2024-08-27 20:05:17'),
(3, 3, 1, 'carlosrodriguez', 'Carlos Rodríguez', '12654c024a4c0926329753cf79d4bb95d617c17684066809cf453b2084a4d5bc', 'carlos@example.com', '2024-08-27 20:05:17'),
(4, 2, 1, 'analopez', 'Ana López', '0877e464d4849257536022d6e42562fa6f5d2001aea605e68e9bd0b51886d22c', 'ana@example.com', '2024-08-27 20:05:17'),
(5, 2, 1, 'pedromartinez', 'Pedro Martínez', 'c0540cad18814f4300c6769b5cc09d8c98b4be70148bd29ab33d0183f9ad57a8', 'pedro@example.com', '2024-08-27 20:05:17'),
(6, 2, 1, 'luisafernandez', 'Luisa Fernández', 'f29e3db205274c7c31edd411f788082022de84f44082786ee76379f98cd9ae95', 'luisa@example.com', '2024-08-27 20:05:17'),
(7, 2, 1, 'robertosilva', 'Roberto Silva', '3e0252b2b3dbe7ca74e50675ed2cd22d3ee4ddc796ea0084bca0e06f591c35ee', 'roberto@example.com', '2024-08-27 20:05:17'),
(8, 2, 1, 'lauragonzalez', 'Laura González', 'f828cbfdf7536d8b23219629263021785f4b48390c7f1cb47449418cff378e9d', 'laura@example.com', '2024-08-27 20:05:17'),
(9, 2, 1, 'diegosanchez', 'Diego Sánchez', '73fef7aada2963e185de67fd44fd10644995b804341a3af0d71dfd2fccbdc0fd', 'diego@example.com', '2024-08-27 20:05:17'),
(10, 2, 1, 'sofiaramirez', 'Sofía Ramírez', 'fbf3e33f8e9df31c8240ee76b2968e37adaa0ec627cd894ca56e26bf632450a4', 'sofia@example.com', '2024-08-27 20:05:17'),
(11, 2, 1, 'andrescastro', 'Andrés Castro', '108bff0cf074171d4cda2d93a0aa28463b1b528ff91f4c67692d889f376efec3', 'andres@example.com', '2024-08-27 20:05:17'),
(12, 2, 1, 'valentinatorres', 'Valentina Torres', '7ec62cb35c0425e461801930b3f00262499a0ce7d549419c2fff59dc4452e09a', 'valentina@example.com', '2024-08-27 20:05:17'),
(13, 2, 1, 'gabrielruiz', 'Gabriel Ruiz', '734c92ff6dbd96447898183ce3191d2160654bf02305c5934b042b79df02f712', 'gabriel@example.com', '2024-08-27 20:05:17'),
(14, 2, 1, 'isabelmendez', 'Isabel Méndez', '47a127091ea5dad935684d238a57aee46ea3253f37b7eb9e10d5cb6d64e6443e', 'isabel@example.com', '2024-08-27 20:05:17'),
(15, 2, 1, 'josehernandez', 'José Hernández', 'afe94159aa9c32528851187034b4387345936ec2463e2b2dcf0c9aa2daecf396', 'jose@example.com', '2024-08-27 20:05:17'),
(16, 2, 1, 'paulajimenez', 'Paula Jiménez', '513727ba3808591eebea9f1ff9873187208cd733ad502cac555d42f8ed703672', 'paula@example.com', '2024-08-27 20:05:17'),
(17, 2, 1, 'felipevera', 'Felipe Vera', 'e9617585d8cb84ad6d689b92a6624f5ed1d63a1b8c4576214e7db2f0de29829e', 'felipe@example.com', '2024-08-27 20:05:17'),
(18, 2, 1, 'danielaortiz', 'Daniela Ortiz', '77405a3bc06098874a109f719d9aa3b7d40e2878a35b7e092f7cd63adaa8a3ac', 'daniela@example.com', '2024-08-27 20:05:17'),
(19, 2, 1, 'emanuelvargas', 'Emanuel Vargas', '20d8b30f813d7205e1d9471c0de75c7dbb54485e9b03c551d10b46399beeedd1', 'emanuel@example.com', '2024-08-27 20:05:17'),
(20, 2, 1, 'carolinarios', 'Carolina Ríos', 'ef74c1f9968feb4bbe440b721c8da8b953c55d0c59fb486de83a72d01db73a5b', 'carolina@example.com', '2024-08-27 20:05:17'),
(21, 2, 1, 'juancho', 'sebastian', '123456', 'sebastinan@gmail.com', '2024-08-28 13:55:06'),
(22, 2, 1, 'esneiderUser', 'esneider', '$2b$10$0uCEhOcu9hugqI5Kq21aw.MKfh/baN4Rfz8/O77TUxQFvIzU/ovvi', 'esneider@gmail.com', '2024-08-28 14:44:27'),
(23, 2, 1, 'esneiderUser', 'esneider', '$2b$10$7oX8qoS9v5WOt9IupQx/IOUR.0/w7sc.HZGxyN7oEL8hebuWzcWLO', 'esneider@gmail.com', '2024-08-28 14:45:00');

--
-- Índices para tablas volcadas
--

--
-- Indices de la tabla `administrador`
--
ALTER TABLE `administrador`
  ADD PRIMARY KEY (`id`),
  ADD KEY `id_estado` (`id_estado`);

--
-- Indices de la tabla `estado`
--
ALTER TABLE `estado`
  ADD PRIMARY KEY (`id`);

--
-- Indices de la tabla `grupos`
--
ALTER TABLE `grupos`
  ADD PRIMARY KEY (`id`);

--
-- Indices de la tabla `historial_cambio_contrasena`
--
ALTER TABLE `historial_cambio_contrasena`
  ADD PRIMARY KEY (`id`),
  ADD KEY `id_usuario` (`id_usuario`);

--
-- Indices de la tabla `historial_sesion_usuario`
--
ALTER TABLE `historial_sesion_usuario`
  ADD PRIMARY KEY (`id`),
  ADD KEY `usuario_id` (`usuario_id`);

--
-- Indices de la tabla `integrantes_grupo`
--
ALTER TABLE `integrantes_grupo`
  ADD PRIMARY KEY (`id`),
  ADD KEY `id_grupo` (`id_grupo`),
  ADD KEY `id_usuario` (`id_usuario`);

--
-- Indices de la tabla `lista_blanca`
--
ALTER TABLE `lista_blanca`
  ADD PRIMARY KEY (`id`),
  ADD KEY `id_usuario` (`id_usuario`);

--
-- Indices de la tabla `lista_negra`
--
ALTER TABLE `lista_negra`
  ADD PRIMARY KEY (`id`),
  ADD KEY `id_usuario` (`id_usuario`);

--
-- Indices de la tabla `log_seguridad`
--
ALTER TABLE `log_seguridad`
  ADD PRIMARY KEY (`id`),
  ADD KEY `usuario_id` (`usuario_id`);

--
-- Indices de la tabla `politica_seguridad`
--
ALTER TABLE `politica_seguridad`
  ADD PRIMARY KEY (`id`);

--
-- Indices de la tabla `pregunta_seguridad`
--
ALTER TABLE `pregunta_seguridad`
  ADD PRIMARY KEY (`id`);

--
-- Indices de la tabla `respuesta`
--
ALTER TABLE `respuesta`
  ADD PRIMARY KEY (`id`),
  ADD KEY `id_pregunta` (`id_pregunta`),
  ADD KEY `id_usuario` (`id_usuario`);

--
-- Indices de la tabla `rol`
--
ALTER TABLE `rol`
  ADD PRIMARY KEY (`id`);

--
-- Indices de la tabla `usuario`
--
ALTER TABLE `usuario`
  ADD PRIMARY KEY (`id`),
  ADD KEY `id_rol` (`id_rol`),
  ADD KEY `id_estado` (`id_estado`);

--
-- AUTO_INCREMENT de las tablas volcadas
--

--
-- AUTO_INCREMENT de la tabla `administrador`
--
ALTER TABLE `administrador`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT de la tabla `estado`
--
ALTER TABLE `estado`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT de la tabla `grupos`
--
ALTER TABLE `grupos`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT de la tabla `historial_cambio_contrasena`
--
ALTER TABLE `historial_cambio_contrasena`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `historial_sesion_usuario`
--
ALTER TABLE `historial_sesion_usuario`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT de la tabla `integrantes_grupo`
--
ALTER TABLE `integrantes_grupo`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=13;

--
-- AUTO_INCREMENT de la tabla `lista_blanca`
--
ALTER TABLE `lista_blanca`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `lista_negra`
--
ALTER TABLE `lista_negra`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `log_seguridad`
--
ALTER TABLE `log_seguridad`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT de la tabla `politica_seguridad`
--
ALTER TABLE `politica_seguridad`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT de la tabla `pregunta_seguridad`
--
ALTER TABLE `pregunta_seguridad`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT de la tabla `respuesta`
--
ALTER TABLE `respuesta`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT de la tabla `rol`
--
ALTER TABLE `rol`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- AUTO_INCREMENT de la tabla `usuario`
--
ALTER TABLE `usuario`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=24;

--
-- Restricciones para tablas volcadas
--

--
-- Filtros para la tabla `administrador`
--
ALTER TABLE `administrador`
  ADD CONSTRAINT `administrador_ibfk_1` FOREIGN KEY (`id_estado`) REFERENCES `estado` (`id`);

--
-- Filtros para la tabla `historial_cambio_contrasena`
--
ALTER TABLE `historial_cambio_contrasena`
  ADD CONSTRAINT `historial_cambio_contrasena_ibfk_1` FOREIGN KEY (`id_usuario`) REFERENCES `usuario` (`id`);

--
-- Filtros para la tabla `historial_sesion_usuario`
--
ALTER TABLE `historial_sesion_usuario`
  ADD CONSTRAINT `historial_sesion_usuario_ibfk_1` FOREIGN KEY (`usuario_id`) REFERENCES `usuario` (`id`);

--
-- Filtros para la tabla `integrantes_grupo`
--
ALTER TABLE `integrantes_grupo`
  ADD CONSTRAINT `integrantes_grupo_ibfk_1` FOREIGN KEY (`id_grupo`) REFERENCES `grupos` (`id`),
  ADD CONSTRAINT `integrantes_grupo_ibfk_2` FOREIGN KEY (`id_usuario`) REFERENCES `usuario` (`id`);

--
-- Filtros para la tabla `lista_blanca`
--
ALTER TABLE `lista_blanca`
  ADD CONSTRAINT `lista_blanca_ibfk_1` FOREIGN KEY (`id_usuario`) REFERENCES `historial_sesion_usuario` (`id`);

--
-- Filtros para la tabla `lista_negra`
--
ALTER TABLE `lista_negra`
  ADD CONSTRAINT `lista_negra_ibfk_1` FOREIGN KEY (`id_usuario`) REFERENCES `historial_sesion_usuario` (`id`);

--
-- Filtros para la tabla `log_seguridad`
--
ALTER TABLE `log_seguridad`
  ADD CONSTRAINT `log_seguridad_ibfk_1` FOREIGN KEY (`usuario_id`) REFERENCES `usuario` (`id`);

--
-- Filtros para la tabla `respuesta`
--
ALTER TABLE `respuesta`
  ADD CONSTRAINT `respuesta_ibfk_1` FOREIGN KEY (`id_pregunta`) REFERENCES `pregunta_seguridad` (`id`),
  ADD CONSTRAINT `respuesta_ibfk_2` FOREIGN KEY (`id_usuario`) REFERENCES `usuario` (`id`);

--
-- Filtros para la tabla `usuario`
--
ALTER TABLE `usuario`
  ADD CONSTRAINT `usuario_ibfk_1` FOREIGN KEY (`id_rol`) REFERENCES `rol` (`id`),
  ADD CONSTRAINT `usuario_ibfk_2` FOREIGN KEY (`id_estado`) REFERENCES `estado` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
