-- MySQL dump 10.13  Distrib 9.0.1, for macos14.4 (arm64)
--
-- Host: bqrj8u6oc4hnnjcd3jwv-mysql.services.clever-cloud.com    Database: bqrj8u6oc4hnnjcd3jwv
-- ------------------------------------------------------
-- Server version	8.0.36-28

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `actividades_sospechosas`
--

DROP TABLE IF EXISTS `actividades_sospechosas`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `actividades_sospechosas` (
  `id` int NOT NULL AUTO_INCREMENT,
  `id_usuario` int NOT NULL,
  `tipo_actividad` varchar(255) DEFAULT NULL,
  `fecha` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `id_usuario` (`id_usuario`),
  CONSTRAINT `actividades_sospechosas_ibfk_1` FOREIGN KEY (`id_usuario`) REFERENCES `usuario` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb3;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `actividades_sospechosas`
--

LOCK TABLES `actividades_sospechosas` WRITE;
/*!40000 ALTER TABLE `actividades_sospechosas` DISABLE KEYS */;
INSERT INTO `actividades_sospechosas` VALUES (1,2,'Intentos fallidos de inicio de sesión','2024-09-14 23:10:23'),(2,2,'Intentos fallidos de inicio de sesión','2024-09-15 01:21:26'),(3,2,'Intentos fallidos de inicio de sesión','2024-09-15 01:25:09');
/*!40000 ALTER TABLE `actividades_sospechosas` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `administrador`
--

DROP TABLE IF EXISTS `administrador`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `administrador` (
  `id` int NOT NULL AUTO_INCREMENT,
  `id_estado` int DEFAULT NULL,
  `nombre_admin` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `nombre` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `contrasena_hash` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `email` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `telefono` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL,
  `fecha_creacion` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `id_estado` (`id_estado`),
  CONSTRAINT `administrador_ibfk_1` FOREIGN KEY (`id_estado`) REFERENCES `estado` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `administrador`
--

LOCK TABLES `administrador` WRITE;
/*!40000 ALTER TABLE `administrador` DISABLE KEYS */;
INSERT INTO `administrador` VALUES (2,NULL,'prueba','prueba','1','leonardo.franco.tangarife@gmail.com','3226347434','2024-09-04 18:53:16'),(3,NULL,'dios mio','a','1','asdfasdf@gmail.com','21654','2024-09-04 23:51:34'),(5,NULL,'prueba2','prueba2','1','leo@gmail.com','3226347434','2024-09-05 15:32:59'),(6,NULL,'prueba2','prueba2','1','leo@gmail.com','3226347434','2024-09-05 15:32:59');
/*!40000 ALTER TABLE `administrador` ENABLE KEYS */;
UNLOCK TABLES;
/*!50003 SET @saved_cs_client      = @@character_set_client */ ;
/*!50003 SET @saved_cs_results     = @@character_set_results */ ;
/*!50003 SET @saved_col_connection = @@collation_connection */ ;
/*!50003 SET character_set_client  = utf8mb4 */ ;
/*!50003 SET character_set_results = utf8mb4 */ ;
/*!50003 SET collation_connection  = utf8mb4_0900_ai_ci */ ;
/*!50003 SET @saved_sql_mode       = @@sql_mode */ ;
/*!50003 SET sql_mode              = 'NO_AUTO_VALUE_ON_ZERO' */ ;
DELIMITER ;;
/*!50003 CREATE*/ /*!50017 DEFINER=`uezbg0bzrvueuhnx`@`%`*/ /*!50003 TRIGGER `creacion_doble_verificacion` AFTER INSERT ON `administrador` FOR EACH ROW BEGIN
    INSERT INTO verificacion_doble (id_admin, estado_v)
    VALUES (NEW.id, 2);
END */;;
DELIMITER ;
/*!50003 SET sql_mode              = @saved_sql_mode */ ;
/*!50003 SET character_set_client  = @saved_cs_client */ ;
/*!50003 SET character_set_results = @saved_cs_results */ ;
/*!50003 SET collation_connection  = @saved_col_connection */ ;

--
-- Table structure for table `certificates`
--

DROP TABLE IF EXISTS `certificates`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `certificates` (
  `id` int NOT NULL AUTO_INCREMENT,
  `domain` varchar(255) NOT NULL,
  `cert_provider` varchar(255) NOT NULL,
  `cert_status` enum('active','expiring_soon','expired') NOT NULL DEFAULT 'active',
  `issue_date` date NOT NULL,
  `expiry_date` date NOT NULL,
  `renewal_reminder` tinyint(1) DEFAULT '0',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb3;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `certificates`
--

LOCK TABLES `certificates` WRITE;
/*!40000 ALTER TABLE `certificates` DISABLE KEYS */;
INSERT INTO `certificates` VALUES (1,'example.com','Let\'s Encrypt','active','2024-09-14','2025-09-14',0,'2024-09-15 01:16:16','2024-09-15 03:29:42'),(2,'mybarbershop.com','Digicert','active','2024-09-14','2025-09-14',0,'2024-09-15 01:16:16','2024-09-15 03:18:22'),(3,'secure-site.com','GoDaddy','expired','2024-09-14','2025-09-14',0,'2024-09-15 01:16:16','2024-09-15 03:22:21'),(4,'personalblog.net','GlobalSign','active','2024-09-14','2025-09-14',0,'2024-09-15 01:16:16','2024-09-15 03:13:53'),(5,'ecommerce-site.org','Comodo','expired','2024-09-14','2025-09-14',0,'2024-09-15 01:16:16','2024-09-15 03:28:36');
/*!40000 ALTER TABLE `certificates` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `estado`
--

DROP TABLE IF EXISTS `estado`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `estado` (
  `id` int NOT NULL AUTO_INCREMENT,
  `tipo_estado` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `estado`
--

LOCK TABLES `estado` WRITE;
/*!40000 ALTER TABLE `estado` DISABLE KEYS */;
INSERT INTO `estado` VALUES (1,'Activo'),(2,'Inactivo\r\n'),(3,'Bloqueado');
/*!40000 ALTER TABLE `estado` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `estado_verificacion_doble`
--

DROP TABLE IF EXISTS `estado_verificacion_doble`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `estado_verificacion_doble` (
  `id` int NOT NULL AUTO_INCREMENT,
  `estado` varchar(200) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `estado_verificacion_doble`
--

LOCK TABLES `estado_verificacion_doble` WRITE;
/*!40000 ALTER TABLE `estado_verificacion_doble` DISABLE KEYS */;
INSERT INTO `estado_verificacion_doble` VALUES (1,'activado'),(2,'desactivado');
/*!40000 ALTER TABLE `estado_verificacion_doble` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `grupos`
--

DROP TABLE IF EXISTS `grupos`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `grupos` (
  `id` int NOT NULL AUTO_INCREMENT,
  `nombre` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `descripcion` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=14 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `grupos`
--

LOCK TABLES `grupos` WRITE;
/*!40000 ALTER TABLE `grupos` DISABLE KEYS */;
INSERT INTO `grupos` VALUES (1,'Grupo 1','Prueba'),(2,'Grupo 2','Prueba'),(3,'Grupo 3','Prueba'),(4,'Grupo 6','Prueba'),(5,'Grupo 7','Prueba'),(6,'dsdfsd','sdfsfsfd'),(7,'sdfsf','sdfsf'),(8,'sdfsdf','sdfdsfsf'),(9,'dfsdf','sdfsdfs'),(10,'sdg','sdgdsg'),(11,'',''),(12,'asdasd','asdasd'),(13,'asdasd','asdadad');
/*!40000 ALTER TABLE `grupos` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `historial_cambio_contrasena`
--

DROP TABLE IF EXISTS `historial_cambio_contrasena`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `historial_cambio_contrasena` (
  `id` int NOT NULL AUTO_INCREMENT,
  `id_usuario` int DEFAULT NULL,
  `fecha_cambio` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `id_usuario` (`id_usuario`),
  CONSTRAINT `historial_cambio_contrasena_ibfk_1` FOREIGN KEY (`id_usuario`) REFERENCES `usuario` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `historial_cambio_contrasena`
--

LOCK TABLES `historial_cambio_contrasena` WRITE;
/*!40000 ALTER TABLE `historial_cambio_contrasena` DISABLE KEYS */;
/*!40000 ALTER TABLE `historial_cambio_contrasena` ENABLE KEYS */;
UNLOCK TABLES;
/*!50003 SET @saved_cs_client      = @@character_set_client */ ;
/*!50003 SET @saved_cs_results     = @@character_set_results */ ;
/*!50003 SET @saved_col_connection = @@collation_connection */ ;
/*!50003 SET character_set_client  = utf8mb4 */ ;
/*!50003 SET character_set_results = utf8mb4 */ ;
/*!50003 SET collation_connection  = utf8mb4_unicode_ci */ ;
/*!50003 SET @saved_sql_mode       = @@sql_mode */ ;
/*!50003 SET sql_mode              = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION' */ ;
DELIMITER ;;
/*!50003 CREATE*/ /*!50017 DEFINER=`uezbg0bzrvueuhnx`@`%`*/ /*!50003 TRIGGER `log_cambio_contrasena` AFTER INSERT ON `historial_cambio_contrasena` FOR EACH ROW BEGIN
    INSERT INTO log_seguridad (usuario_id, timestamp, tipo_evento, descripcion)
    VALUES (NEW.id_usuario, NEW.fecha_cambio, 'Cambio de contraseña', 'El usuario cambió su contraseña.');
END */;;
DELIMITER ;
/*!50003 SET sql_mode              = @saved_sql_mode */ ;
/*!50003 SET character_set_client  = @saved_cs_client */ ;
/*!50003 SET character_set_results = @saved_cs_results */ ;
/*!50003 SET collation_connection  = @saved_col_connection */ ;

--
-- Table structure for table `historial_sesion_usuario`
--

DROP TABLE IF EXISTS `historial_sesion_usuario`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `historial_sesion_usuario` (
  `id` int NOT NULL AUTO_INCREMENT,
  `usuario_id` int DEFAULT NULL,
  `fecha_inicio_sesion` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `direccion_ip` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `dispositivo` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `usuario_id` (`usuario_id`),
  CONSTRAINT `historial_sesion_usuario_ibfk_1` FOREIGN KEY (`usuario_id`) REFERENCES `usuario` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=138 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `historial_sesion_usuario`
--

LOCK TABLES `historial_sesion_usuario` WRITE;
/*!40000 ALTER TABLE `historial_sesion_usuario` DISABLE KEYS */;
INSERT INTO `historial_sesion_usuario` VALUES (11,NULL,'2024-09-05 19:15:47','::1','Windows NT 10.0; Win64; x64'),(12,2,'2024-09-05 19:31:23','::1','Windows NT 10.0; Win64; x64'),(13,2,'2024-09-05 19:33:38','::1','Windows NT 10.0; Win64; x64'),(14,NULL,'2024-09-05 19:43:06',NULL,NULL),(15,2,'2024-09-05 19:43:35','::1','Windows NT 10.0; Win64; x64'),(16,2,'2024-09-05 19:45:09','::1','Windows NT 10.0; Win64; x64'),(17,2,'2024-09-05 19:45:30','::1','Windows NT 10.0; Win64; x64'),(18,2,'2024-09-05 19:46:01','::1','Windows NT 10.0; Win64; x64'),(19,2,'2024-09-05 19:46:52','::1','Windows NT 10.0; Win64; x64'),(20,2,'2024-09-06 17:50:26','::1','Windows NT 10.0; Win64; x64'),(21,2,'2024-09-06 21:44:43','::1','Windows NT 10.0; Win64; x64'),(22,2,'2024-09-06 21:54:09','::1','Windows NT 10.0; Win64; x64'),(23,2,'2024-09-06 21:59:59','::1','Windows NT 10.0; Win64; x64'),(24,2,'2024-09-06 22:04:18','::1','Windows NT 10.0; Win64; x64'),(25,NULL,'2024-09-06 23:56:53',NULL,NULL),(26,NULL,'2024-09-06 23:57:33',NULL,NULL),(27,NULL,'2024-09-06 23:57:49',NULL,NULL),(28,NULL,'2024-09-06 23:58:44',NULL,NULL),(29,NULL,'2024-09-06 23:59:03',NULL,NULL),(30,2,'2024-09-07 00:40:44','::1','Windows NT 10.0; Win64; x64'),(31,NULL,'2024-09-07 00:41:26',NULL,NULL),(32,NULL,'2024-09-07 00:41:42',NULL,NULL),(33,NULL,'2024-09-07 00:41:58',NULL,NULL),(34,2,'2024-09-07 00:45:34','::1','Windows NT 10.0; Win64; x64'),(35,NULL,'2024-09-07 00:46:54',NULL,NULL),(36,2,'2024-09-07 00:47:24','::1','Windows NT 10.0; Win64; x64'),(37,NULL,'2024-09-07 00:48:39',NULL,NULL),(38,NULL,'2024-09-11 01:57:23',NULL,NULL),(39,NULL,'2024-09-11 01:59:57',NULL,NULL),(40,NULL,'2024-09-11 02:32:17',NULL,NULL),(41,2,'2024-09-11 12:41:47','::1','Windows NT 10.0; Win64; x64'),(42,2,'2024-09-11 12:42:09','::1','Windows NT 10.0; Win64; x64'),(43,2,'2024-09-11 12:42:30','::1','Windows NT 10.0; Win64; x64'),(44,2,'2024-09-11 12:47:11','::1','Windows NT 10.0; Win64; x64'),(45,2,'2024-09-11 12:58:42','::1','Windows NT 10.0; Win64; x64'),(46,2,'2024-09-11 13:21:10','::1','Windows NT 10.0; Win64; x64'),(47,2,'2024-09-11 13:26:08','::1','Windows NT 10.0; Win64; x64'),(48,2,'2024-09-11 13:34:33','::1','Windows NT 10.0; Win64; x64'),(49,2,'2024-09-11 14:50:21','::1','Windows NT 10.0; Win64; x64'),(50,2,'2024-09-11 15:52:06','::1','Windows NT 10.0; Win64; x64'),(51,NULL,'2024-09-11 16:18:49',NULL,NULL),(52,NULL,'2024-09-11 16:18:51',NULL,NULL),(53,NULL,'2024-09-11 18:56:20',NULL,NULL),(54,NULL,'2024-09-11 19:00:09','::1','Windows NT 10.0; Win64; x64'),(55,NULL,'2024-09-11 19:24:49','::1','Windows NT 10.0; Win64; x64'),(56,NULL,'2024-09-12 00:50:57',NULL,NULL),(57,NULL,'2024-09-12 15:38:10',NULL,NULL),(58,NULL,'2024-09-12 15:38:28',NULL,NULL),(59,NULL,'2024-09-12 15:40:11',NULL,NULL),(60,NULL,'2024-09-12 15:41:11',NULL,NULL),(61,NULL,'2024-09-12 15:46:51',NULL,NULL),(62,NULL,'2024-09-13 12:18:33',NULL,NULL),(63,NULL,'2024-09-13 12:18:34',NULL,NULL),(64,NULL,'2024-09-13 12:20:58',NULL,NULL),(65,NULL,'2024-09-13 12:20:58',NULL,NULL),(66,NULL,'2024-09-13 12:20:58',NULL,NULL),(67,NULL,'2024-09-13 12:20:58',NULL,NULL),(68,NULL,'2024-09-13 12:21:27',NULL,NULL),(69,NULL,'2024-09-13 12:21:57',NULL,NULL),(70,NULL,'2024-09-13 16:14:20','::1','Windows NT 10.0; Win64; x64'),(71,NULL,'2024-09-13 16:21:03','::1','Windows NT 10.0; Win64; x64'),(72,NULL,'2024-09-13 16:22:36','::1','Windows NT 10.0; Win64; x64'),(73,NULL,'2024-09-13 16:23:59','::1','Windows NT 10.0; Win64; x64'),(74,NULL,'2024-09-13 19:12:26','::1','Windows NT 10.0; Win64; x64'),(75,NULL,'2024-09-13 19:28:01','::1','Windows NT 10.0; Win64; x64'),(76,NULL,'2024-09-13 22:11:33','::1','Windows NT 10.0; Win64; x64'),(77,NULL,'2024-09-13 22:11:41','::1','Windows NT 10.0; Win64; x64'),(78,NULL,'2024-09-13 22:11:43','::1','Windows NT 10.0; Win64; x64'),(79,NULL,'2024-09-13 22:11:43','::1','Windows NT 10.0; Win64; x64'),(80,NULL,'2024-09-13 22:11:43','::1','Windows NT 10.0; Win64; x64'),(81,NULL,'2024-09-13 22:11:59','::1','Windows NT 10.0; Win64; x64'),(82,NULL,'2024-09-13 22:12:00','::1','Windows NT 10.0; Win64; x64'),(83,NULL,'2024-09-13 22:12:06','::1','Windows NT 10.0; Win64; x64'),(84,NULL,'2024-09-13 22:12:08','::1','Windows NT 10.0; Win64; x64'),(85,NULL,'2024-09-13 22:12:15','::1','Windows NT 10.0; Win64; x64'),(86,NULL,'2024-09-13 22:14:41','::1','Windows NT 10.0; Win64; x64'),(87,NULL,'2024-09-13 22:41:45','::1','Windows NT 10.0; Win64; x64'),(88,NULL,'2024-09-13 22:41:46','::1','Windows NT 10.0; Win64; x64'),(89,NULL,'2024-09-13 22:41:47','::1','Windows NT 10.0; Win64; x64'),(90,NULL,'2024-09-13 22:41:47','::1','Windows NT 10.0; Win64; x64'),(91,NULL,'2024-09-13 22:41:48','::1','Windows NT 10.0; Win64; x64'),(92,NULL,'2024-09-13 22:41:53','::1','Windows NT 10.0; Win64; x64'),(93,NULL,'2024-09-13 22:41:53','::1','Windows NT 10.0; Win64; x64'),(94,NULL,'2024-09-13 22:42:06','::1','Windows NT 10.0; Win64; x64'),(95,NULL,'2024-09-13 22:42:06','::1','Windows NT 10.0; Win64; x64'),(96,NULL,'2024-09-13 22:42:06','::1','Windows NT 10.0; Win64; x64'),(97,NULL,'2024-09-13 22:55:46','::1','Windows NT 10.0; Win64; x64'),(98,NULL,'2024-09-13 22:55:47','::1','Windows NT 10.0; Win64; x64'),(99,NULL,'2024-09-14 18:01:22','::1','Windows NT 10.0; Win64; x64'),(100,NULL,'2024-09-14 18:07:10','::1','Windows NT 10.0; Win64; x64'),(101,NULL,'2024-09-14 18:08:53','::1','Windows NT 10.0; Win64; x64'),(102,NULL,'2024-09-14 18:13:10','::1','Macintosh; Intel Mac OS X 10_15_7'),(103,NULL,'2024-09-14 18:37:42','::1','Windows NT 10.0; Win64; x64'),(104,NULL,'2024-09-14 18:44:51','::1','Windows NT 10.0; Win64; x64'),(105,NULL,'2024-09-14 18:49:02','::1','Windows NT 10.0; Win64; x64'),(106,NULL,'2024-09-14 19:04:52','::1','Windows NT 10.0; Win64; x64'),(107,NULL,'2024-09-14 19:05:34','::1','Windows NT 10.0; Win64; x64'),(108,NULL,'2024-09-14 19:10:28',NULL,NULL),(109,NULL,'2024-09-14 19:12:28','::1','Windows NT 10.0; Win64; x64'),(110,NULL,'2024-09-14 21:49:54','::1','Macintosh; Intel Mac OS X 10_15_7'),(111,NULL,'2024-09-14 22:20:30','::1','Macintosh; Intel Mac OS X 10_15_7'),(112,NULL,'2024-09-14 22:22:38',NULL,NULL),(113,NULL,'2024-09-14 22:22:39',NULL,NULL),(114,NULL,'2024-09-14 22:27:31',NULL,NULL),(115,NULL,'2024-09-14 22:29:52',NULL,NULL),(116,NULL,'2024-09-14 22:30:38',NULL,NULL),(117,NULL,'2024-09-14 22:42:54',NULL,NULL),(118,NULL,'2024-09-14 23:05:32',NULL,NULL),(119,NULL,'2024-09-14 23:10:23',NULL,NULL),(120,NULL,'2024-09-14 23:29:30',NULL,NULL),(121,NULL,'2024-09-14 23:40:41',NULL,NULL),(122,NULL,'2024-09-14 23:52:55',NULL,NULL),(123,NULL,'2024-09-15 00:20:44',NULL,NULL),(124,NULL,'2024-09-15 00:51:52',NULL,NULL),(125,NULL,'2024-09-15 00:52:40',NULL,NULL),(126,NULL,'2024-09-15 01:01:56',NULL,NULL),(127,NULL,'2024-09-15 01:04:55',NULL,NULL),(128,NULL,'2024-09-15 01:05:33',NULL,NULL),(129,NULL,'2024-09-15 01:06:33',NULL,NULL),(130,NULL,'2024-09-15 01:09:18',NULL,NULL),(131,NULL,'2024-09-15 01:11:36',NULL,NULL),(132,NULL,'2024-09-15 01:13:38',NULL,NULL),(133,NULL,'2024-09-15 01:15:13',NULL,NULL),(134,NULL,'2024-09-15 01:20:57',NULL,NULL),(135,NULL,'2024-09-15 01:21:26',NULL,NULL),(136,NULL,'2024-09-15 01:24:52',NULL,NULL),(137,NULL,'2024-09-15 01:25:09',NULL,NULL);
/*!40000 ALTER TABLE `historial_sesion_usuario` ENABLE KEYS */;
UNLOCK TABLES;
/*!50003 SET @saved_cs_client      = @@character_set_client */ ;
/*!50003 SET @saved_cs_results     = @@character_set_results */ ;
/*!50003 SET @saved_col_connection = @@collation_connection */ ;
/*!50003 SET character_set_client  = utf8mb4 */ ;
/*!50003 SET character_set_results = utf8mb4 */ ;
/*!50003 SET collation_connection  = utf8mb4_unicode_ci */ ;
/*!50003 SET @saved_sql_mode       = @@sql_mode */ ;
/*!50003 SET sql_mode              = 'STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION' */ ;
DELIMITER ;;
/*!50003 CREATE*/ /*!50017 DEFINER=`uezbg0bzrvueuhnx`@`%`*/ /*!50003 TRIGGER `log_inicio_sesion` AFTER INSERT ON `historial_sesion_usuario` FOR EACH ROW BEGIN
    INSERT INTO log_seguridad (usuario_id, horario, tipo_evento, descripcion)
    VALUES (NEW.usuario_id, NEW.fecha_inicio_sesion, 'Inicio de sesión', CONCAT('Inicio de sesión desde IP: ', NEW.direccion_ip));
END */;;
DELIMITER ;
/*!50003 SET sql_mode              = @saved_sql_mode */ ;
/*!50003 SET character_set_client  = @saved_cs_client */ ;
/*!50003 SET character_set_results = @saved_cs_results */ ;
/*!50003 SET collation_connection  = @saved_col_connection */ ;

--
-- Table structure for table `integrantes_grupo`
--

DROP TABLE IF EXISTS `integrantes_grupo`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `integrantes_grupo` (
  `id` int NOT NULL AUTO_INCREMENT,
  `id_grupo` int DEFAULT NULL,
  `id_usuario` int DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `id_grupo` (`id_grupo`),
  KEY `id_usuario` (`id_usuario`),
  CONSTRAINT `integrantes_grupo_ibfk_1` FOREIGN KEY (`id_grupo`) REFERENCES `grupos` (`id`),
  CONSTRAINT `integrantes_grupo_ibfk_2` FOREIGN KEY (`id_usuario`) REFERENCES `usuario` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=19 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `integrantes_grupo`
--

LOCK TABLES `integrantes_grupo` WRITE;
/*!40000 ALTER TABLE `integrantes_grupo` DISABLE KEYS */;
INSERT INTO `integrantes_grupo` VALUES (1,1,2),(2,1,2),(3,1,2),(4,NULL,2),(5,7,2),(6,8,2),(7,8,2),(8,8,2),(9,8,2),(10,8,2),(11,8,2),(12,9,1),(13,9,2),(14,10,2),(15,10,2),(16,11,2),(17,12,2),(18,13,2);
/*!40000 ALTER TABLE `integrantes_grupo` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `intentos_fallidos`
--

DROP TABLE IF EXISTS `intentos_fallidos`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `intentos_fallidos` (
  `id` int NOT NULL AUTO_INCREMENT,
  `id_usuario` int NOT NULL,
  `fecha` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `ip_address` varchar(45) DEFAULT NULL,
  `platform` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `id_usuario` (`id_usuario`),
  CONSTRAINT `intentos_fallidos_ibfk_1` FOREIGN KEY (`id_usuario`) REFERENCES `usuario` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb3;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `intentos_fallidos`
--

LOCK TABLES `intentos_fallidos` WRITE;
/*!40000 ALTER TABLE `intentos_fallidos` DISABLE KEYS */;
/*!40000 ALTER TABLE `intentos_fallidos` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `lista_blanca`
--

DROP TABLE IF EXISTS `lista_blanca`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `lista_blanca` (
  `id` int NOT NULL AUTO_INCREMENT,
  `id_usuario` int DEFAULT NULL,
  `direccion_ip` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `id_usuario` (`id_usuario`),
  CONSTRAINT `lista_blanca_ibfk_1` FOREIGN KEY (`id_usuario`) REFERENCES `historial_sesion_usuario` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `lista_blanca`
--

LOCK TABLES `lista_blanca` WRITE;
/*!40000 ALTER TABLE `lista_blanca` DISABLE KEYS */;
/*!40000 ALTER TABLE `lista_blanca` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `lista_negra`
--

DROP TABLE IF EXISTS `lista_negra`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `lista_negra` (
  `id` int NOT NULL AUTO_INCREMENT,
  `id_usuario` int DEFAULT NULL,
  `direccion_ip` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `id_usuario` (`id_usuario`),
  CONSTRAINT `lista_negra_ibfk_1` FOREIGN KEY (`id_usuario`) REFERENCES `historial_sesion_usuario` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `lista_negra`
--

LOCK TABLES `lista_negra` WRITE;
/*!40000 ALTER TABLE `lista_negra` DISABLE KEYS */;
/*!40000 ALTER TABLE `lista_negra` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `log_seguridad`
--

DROP TABLE IF EXISTS `log_seguridad`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `log_seguridad` (
  `id` int NOT NULL AUTO_INCREMENT,
  `usuario_id` int DEFAULT NULL,
  `horario` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `tipo_evento` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `descripcion` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `usuario_id` (`usuario_id`)
) ENGINE=InnoDB AUTO_INCREMENT=128 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `log_seguridad`
--

LOCK TABLES `log_seguridad` WRITE;
/*!40000 ALTER TABLE `log_seguridad` DISABLE KEYS */;
INSERT INTO `log_seguridad` VALUES (1,NULL,'2024-09-05 19:15:47','Inicio de sesión','Inicio de sesión desde IP: ::1'),(2,2,'2024-09-05 19:31:23','Inicio de sesión','Inicio de sesión desde IP: ::1'),(3,2,'2024-09-05 19:33:38','Inicio de sesión','Inicio de sesión desde IP: ::1'),(4,NULL,'2024-09-05 19:43:06','Inicio de sesión',NULL),(5,2,'2024-09-05 19:43:35','Inicio de sesión','Inicio de sesión desde IP: ::1'),(6,2,'2024-09-05 19:45:09','Inicio de sesión','Inicio de sesión desde IP: ::1'),(7,2,'2024-09-05 19:45:30','Inicio de sesión','Inicio de sesión desde IP: ::1'),(8,2,'2024-09-05 19:46:01','Inicio de sesión','Inicio de sesión desde IP: ::1'),(9,2,'2024-09-05 19:46:52','Inicio de sesión','Inicio de sesión desde IP: ::1'),(10,2,'2024-09-06 17:50:26','Inicio de sesión','Inicio de sesión desde IP: ::1'),(11,2,'2024-09-06 21:44:43','Inicio de sesión','Inicio de sesión desde IP: ::1'),(12,2,'2024-09-06 21:54:09','Inicio de sesión','Inicio de sesión desde IP: ::1'),(13,2,'2024-09-06 21:59:59','Inicio de sesión','Inicio de sesión desde IP: ::1'),(14,2,'2024-09-06 22:04:18','Inicio de sesión','Inicio de sesión desde IP: ::1'),(15,NULL,'2024-09-06 23:56:53','Inicio de sesión',NULL),(16,NULL,'2024-09-06 23:57:33','Inicio de sesión',NULL),(17,NULL,'2024-09-06 23:57:49','Inicio de sesión',NULL),(18,NULL,'2024-09-06 23:58:44','Inicio de sesión',NULL),(19,NULL,'2024-09-06 23:59:03','Inicio de sesión',NULL),(20,2,'2024-09-07 00:40:44','Inicio de sesión','Inicio de sesión desde IP: ::1'),(21,NULL,'2024-09-07 00:41:26','Inicio de sesión',NULL),(22,NULL,'2024-09-07 00:41:42','Inicio de sesión',NULL),(23,NULL,'2024-09-07 00:41:58','Inicio de sesión',NULL),(24,2,'2024-09-07 00:45:34','Inicio de sesión','Inicio de sesión desde IP: ::1'),(25,NULL,'2024-09-07 00:46:54','Inicio de sesión',NULL),(26,2,'2024-09-07 00:47:24','Inicio de sesión','Inicio de sesión desde IP: ::1'),(27,NULL,'2024-09-07 00:48:39','Inicio de sesión',NULL),(28,NULL,'2024-09-11 01:57:23','Inicio de sesión',NULL),(29,NULL,'2024-09-11 01:59:57','Inicio de sesión',NULL),(30,NULL,'2024-09-11 02:32:17','Inicio de sesión',NULL),(31,2,'2024-09-11 12:41:47','Inicio de sesión','Inicio de sesión desde IP: ::1'),(32,2,'2024-09-11 12:42:09','Inicio de sesión','Inicio de sesión desde IP: ::1'),(33,2,'2024-09-11 12:42:30','Inicio de sesión','Inicio de sesión desde IP: ::1'),(34,2,'2024-09-11 12:47:11','Inicio de sesión','Inicio de sesión desde IP: ::1'),(35,2,'2024-09-11 12:58:42','Inicio de sesión','Inicio de sesión desde IP: ::1'),(36,2,'2024-09-11 13:21:10','Inicio de sesión','Inicio de sesión desde IP: ::1'),(37,2,'2024-09-11 13:26:08','Inicio de sesión','Inicio de sesión desde IP: ::1'),(38,2,'2024-09-11 13:34:33','Inicio de sesión','Inicio de sesión desde IP: ::1'),(39,2,'2024-09-11 14:50:21','Inicio de sesión','Inicio de sesión desde IP: ::1'),(40,2,'2024-09-11 15:52:06','Inicio de sesión','Inicio de sesión desde IP: ::1'),(41,NULL,'2024-09-11 16:18:49','Inicio de sesión',NULL),(42,NULL,'2024-09-11 16:18:51','Inicio de sesión',NULL),(43,NULL,'2024-09-11 18:56:20','Inicio de sesión',NULL),(44,NULL,'2024-09-11 19:00:09','Inicio de sesión','Inicio de sesión desde IP: ::1'),(45,NULL,'2024-09-11 19:24:49','Inicio de sesión','Inicio de sesión desde IP: ::1'),(46,NULL,'2024-09-12 00:50:57','Inicio de sesión',NULL),(47,NULL,'2024-09-12 15:38:10','Inicio de sesión',NULL),(48,NULL,'2024-09-12 15:38:28','Inicio de sesión',NULL),(49,NULL,'2024-09-12 15:40:11','Inicio de sesión',NULL),(50,NULL,'2024-09-12 15:41:11','Inicio de sesión',NULL),(51,NULL,'2024-09-12 15:46:51','Inicio de sesión',NULL),(52,NULL,'2024-09-13 12:18:33','Inicio de sesión',NULL),(53,NULL,'2024-09-13 12:18:34','Inicio de sesión',NULL),(54,NULL,'2024-09-13 12:20:58','Inicio de sesión',NULL),(55,NULL,'2024-09-13 12:20:58','Inicio de sesión',NULL),(56,NULL,'2024-09-13 12:20:58','Inicio de sesión',NULL),(57,NULL,'2024-09-13 12:20:58','Inicio de sesión',NULL),(58,NULL,'2024-09-13 12:21:27','Inicio de sesión',NULL),(59,NULL,'2024-09-13 12:21:57','Inicio de sesión',NULL),(60,NULL,'2024-09-13 16:14:20','Inicio de sesión','Inicio de sesión desde IP: ::1'),(61,NULL,'2024-09-13 16:21:03','Inicio de sesión','Inicio de sesión desde IP: ::1'),(62,NULL,'2024-09-13 16:22:36','Inicio de sesión','Inicio de sesión desde IP: ::1'),(63,NULL,'2024-09-13 16:23:59','Inicio de sesión','Inicio de sesión desde IP: ::1'),(64,NULL,'2024-09-13 19:12:26','Inicio de sesión','Inicio de sesión desde IP: ::1'),(65,NULL,'2024-09-13 19:28:01','Inicio de sesión','Inicio de sesión desde IP: ::1'),(66,NULL,'2024-09-13 22:11:33','Inicio de sesión','Inicio de sesión desde IP: ::1'),(67,NULL,'2024-09-13 22:11:41','Inicio de sesión','Inicio de sesión desde IP: ::1'),(68,NULL,'2024-09-13 22:11:43','Inicio de sesión','Inicio de sesión desde IP: ::1'),(69,NULL,'2024-09-13 22:11:43','Inicio de sesión','Inicio de sesión desde IP: ::1'),(70,NULL,'2024-09-13 22:11:43','Inicio de sesión','Inicio de sesión desde IP: ::1'),(71,NULL,'2024-09-13 22:11:59','Inicio de sesión','Inicio de sesión desde IP: ::1'),(72,NULL,'2024-09-13 22:12:00','Inicio de sesión','Inicio de sesión desde IP: ::1'),(73,NULL,'2024-09-13 22:12:06','Inicio de sesión','Inicio de sesión desde IP: ::1'),(74,NULL,'2024-09-13 22:12:08','Inicio de sesión','Inicio de sesión desde IP: ::1'),(75,NULL,'2024-09-13 22:12:15','Inicio de sesión','Inicio de sesión desde IP: ::1'),(76,NULL,'2024-09-13 22:14:41','Inicio de sesión','Inicio de sesión desde IP: ::1'),(77,NULL,'2024-09-13 22:41:45','Inicio de sesión','Inicio de sesión desde IP: ::1'),(78,NULL,'2024-09-13 22:41:46','Inicio de sesión','Inicio de sesión desde IP: ::1'),(79,NULL,'2024-09-13 22:41:47','Inicio de sesión','Inicio de sesión desde IP: ::1'),(80,NULL,'2024-09-13 22:41:47','Inicio de sesión','Inicio de sesión desde IP: ::1'),(81,NULL,'2024-09-13 22:41:48','Inicio de sesión','Inicio de sesión desde IP: ::1'),(82,NULL,'2024-09-13 22:41:53','Inicio de sesión','Inicio de sesión desde IP: ::1'),(83,NULL,'2024-09-13 22:41:53','Inicio de sesión','Inicio de sesión desde IP: ::1'),(84,NULL,'2024-09-13 22:42:06','Inicio de sesión','Inicio de sesión desde IP: ::1'),(85,NULL,'2024-09-13 22:42:06','Inicio de sesión','Inicio de sesión desde IP: ::1'),(86,NULL,'2024-09-13 22:42:06','Inicio de sesión','Inicio de sesión desde IP: ::1'),(87,NULL,'2024-09-13 22:55:46','Inicio de sesión','Inicio de sesión desde IP: ::1'),(88,NULL,'2024-09-13 22:55:47','Inicio de sesión','Inicio de sesión desde IP: ::1'),(89,NULL,'2024-09-14 18:01:22','Inicio de sesión','Inicio de sesión desde IP: ::1'),(90,NULL,'2024-09-14 18:07:10','Inicio de sesión','Inicio de sesión desde IP: ::1'),(91,NULL,'2024-09-14 18:08:53','Inicio de sesión','Inicio de sesión desde IP: ::1'),(92,NULL,'2024-09-14 18:13:10','Inicio de sesión','Inicio de sesión desde IP: ::1'),(93,NULL,'2024-09-14 18:37:42','Inicio de sesión','Inicio de sesión desde IP: ::1'),(94,NULL,'2024-09-14 18:44:51','Inicio de sesión','Inicio de sesión desde IP: ::1'),(95,NULL,'2024-09-14 18:49:02','Inicio de sesión','Inicio de sesión desde IP: ::1'),(96,NULL,'2024-09-14 19:04:52','Inicio de sesión','Inicio de sesión desde IP: ::1'),(97,NULL,'2024-09-14 19:05:34','Inicio de sesión','Inicio de sesión desde IP: ::1'),(98,NULL,'2024-09-14 19:10:28','Inicio de sesión',NULL),(99,NULL,'2024-09-14 19:12:28','Inicio de sesión','Inicio de sesión desde IP: ::1'),(100,NULL,'2024-09-14 21:49:54','Inicio de sesión','Inicio de sesión desde IP: ::1'),(101,NULL,'2024-09-14 22:20:30','Inicio de sesión','Inicio de sesión desde IP: ::1'),(102,NULL,'2024-09-14 22:22:38','Inicio de sesión',NULL),(103,NULL,'2024-09-14 22:22:39','Inicio de sesión',NULL),(104,NULL,'2024-09-14 22:27:31','Inicio de sesión',NULL),(105,NULL,'2024-09-14 22:29:52','Inicio de sesión',NULL),(106,NULL,'2024-09-14 22:30:38','Inicio de sesión',NULL),(107,NULL,'2024-09-14 22:42:54','Inicio de sesión',NULL),(108,NULL,'2024-09-14 23:05:32','Inicio de sesión',NULL),(109,NULL,'2024-09-14 23:10:23','Inicio de sesión',NULL),(110,NULL,'2024-09-14 23:29:30','Inicio de sesión',NULL),(111,NULL,'2024-09-14 23:40:41','Inicio de sesión',NULL),(112,NULL,'2024-09-14 23:52:55','Inicio de sesión',NULL),(113,NULL,'2024-09-15 00:20:44','Inicio de sesión',NULL),(114,NULL,'2024-09-15 00:51:52','Inicio de sesión',NULL),(115,NULL,'2024-09-15 00:52:40','Inicio de sesión',NULL),(116,NULL,'2024-09-15 01:01:56','Inicio de sesión',NULL),(117,NULL,'2024-09-15 01:04:55','Inicio de sesión',NULL),(118,NULL,'2024-09-15 01:05:33','Inicio de sesión',NULL),(119,NULL,'2024-09-15 01:06:33','Inicio de sesión',NULL),(120,NULL,'2024-09-15 01:09:18','Inicio de sesión',NULL),(121,NULL,'2024-09-15 01:11:36','Inicio de sesión',NULL),(122,NULL,'2024-09-15 01:13:38','Inicio de sesión',NULL),(123,NULL,'2024-09-15 01:15:13','Inicio de sesión',NULL),(124,NULL,'2024-09-15 01:20:57','Inicio de sesión',NULL),(125,NULL,'2024-09-15 01:21:26','Inicio de sesión',NULL),(126,NULL,'2024-09-15 01:24:52','Inicio de sesión',NULL),(127,NULL,'2024-09-15 01:25:09','Inicio de sesión',NULL);
/*!40000 ALTER TABLE `log_seguridad` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `permisos`
--

DROP TABLE IF EXISTS `permisos`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `permisos` (
  `id` int NOT NULL AUTO_INCREMENT,
  `nombre` varchar(300) NOT NULL,
  `estado` varchar(10) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `permisos`
--

LOCK TABLES `permisos` WRITE;
/*!40000 ALTER TABLE `permisos` DISABLE KEYS */;
INSERT INTO `permisos` VALUES (1,'Visualizar',''),(2,'Editar','');
/*!40000 ALTER TABLE `permisos` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `permisos_modulo`
--

DROP TABLE IF EXISTS `permisos_modulo`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `permisos_modulo` (
  `id` int NOT NULL AUTO_INCREMENT,
  `modulo` varchar(25) NOT NULL,
  `idPermiso` int NOT NULL,
  `estado` varchar(10) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idPermiso` (`idPermiso`) USING BTREE,
  CONSTRAINT `permisos_modulo_ibfk_1` FOREIGN KEY (`idPermiso`) REFERENCES `permisos` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `permisos_modulo`
--

LOCK TABLES `permisos_modulo` WRITE;
/*!40000 ALTER TABLE `permisos_modulo` DISABLE KEYS */;
INSERT INTO `permisos_modulo` VALUES (1,'Historial',1,'Activo');
/*!40000 ALTER TABLE `permisos_modulo` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `permisos_usuario`
--

DROP TABLE IF EXISTS `permisos_usuario`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `permisos_usuario` (
  `id` int NOT NULL AUTO_INCREMENT,
  `idUsuario` int NOT NULL,
  `idPermiso` int NOT NULL,
  `estado` varchar(10) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idPermiso` (`idPermiso`),
  KEY `idUsuario` (`idUsuario`),
  CONSTRAINT `permisos_usuario_ibfk_1` FOREIGN KEY (`idPermiso`) REFERENCES `permisos` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `permisos_usuario_ibfk_2` FOREIGN KEY (`idUsuario`) REFERENCES `usuario` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `permisos_usuario`
--

LOCK TABLES `permisos_usuario` WRITE;
/*!40000 ALTER TABLE `permisos_usuario` DISABLE KEYS */;
/*!40000 ALTER TABLE `permisos_usuario` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `politica_seguridad`
--

DROP TABLE IF EXISTS `politica_seguridad`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `politica_seguridad` (
  `id` int NOT NULL AUTO_INCREMENT,
  `intentos_fallidos_permitidos` int NOT NULL,
  `longitud_minima_contrasena` int NOT NULL,
  `duracion_token` varchar(50) NOT NULL,
  `tiempo_expiracion_sesion` int NOT NULL,
  `auteticacion_dos_factores` tinyint(1) NOT NULL,
  `intervalos_cambio_contrasena` int NOT NULL,
  `frecuencia_copia_seguridad` varchar(100) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `politica_seguridad`
--

LOCK TABLES `politica_seguridad` WRITE;
/*!40000 ALTER TABLE `politica_seguridad` DISABLE KEYS */;
INSERT INTO `politica_seguridad` VALUES (1,3,2,'2m',60,1,2,'Diaria');
/*!40000 ALTER TABLE `politica_seguridad` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `politicas_bloqueo`
--

DROP TABLE IF EXISTS `politicas_bloqueo`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `politicas_bloqueo` (
  `id` int NOT NULL AUTO_INCREMENT,
  `max_attempts` int NOT NULL,
  `block_duration` int NOT NULL,
  `notify_admins` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb3;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `politicas_bloqueo`
--

LOCK TABLES `politicas_bloqueo` WRITE;
/*!40000 ALTER TABLE `politicas_bloqueo` DISABLE KEYS */;
INSERT INTO `politicas_bloqueo` VALUES (1,3,20,1);
/*!40000 ALTER TABLE `politicas_bloqueo` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `pregunta_seguridad`
--

DROP TABLE IF EXISTS `pregunta_seguridad`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `pregunta_seguridad` (
  `id` int NOT NULL AUTO_INCREMENT,
  `id_usuario` int NOT NULL,
  `pregunta` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `respuesta` varchar(300) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `estado` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  PRIMARY KEY (`id`),
  KEY `id_usuario` (`id_usuario`),
  CONSTRAINT `pregunta_seguridad_ibfk_1` FOREIGN KEY (`id_usuario`) REFERENCES `usuario` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `pregunta_seguridad`
--

LOCK TABLES `pregunta_seguridad` WRITE;
/*!40000 ALTER TABLE `pregunta_seguridad` DISABLE KEYS */;
/*!40000 ALTER TABLE `pregunta_seguridad` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `respuesta`
--

DROP TABLE IF EXISTS `respuesta`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `respuesta` (
  `id` int NOT NULL AUTO_INCREMENT,
  `id_pregunta` int DEFAULT NULL,
  `id_usuario` int DEFAULT NULL,
  `respuesta` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  PRIMARY KEY (`id`),
  KEY `id_pregunta` (`id_pregunta`),
  KEY `id_usuario` (`id_usuario`),
  CONSTRAINT `respuesta_ibfk_1` FOREIGN KEY (`id_pregunta`) REFERENCES `pregunta_seguridad` (`id`),
  CONSTRAINT `respuesta_ibfk_2` FOREIGN KEY (`id_usuario`) REFERENCES `usuario` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `respuesta`
--

LOCK TABLES `respuesta` WRITE;
/*!40000 ALTER TABLE `respuesta` DISABLE KEYS */;
/*!40000 ALTER TABLE `respuesta` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `rol`
--

DROP TABLE IF EXISTS `rol`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `rol` (
  `id` int NOT NULL AUTO_INCREMENT,
  `nombre` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `descripcion` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `rol`
--

LOCK TABLES `rol` WRITE;
/*!40000 ALTER TABLE `rol` DISABLE KEYS */;
INSERT INTO `rol` VALUES (1,'Invitado',NULL),(2,'Moderador',NULL),(3,'Administrador',NULL),(4,'Usuario',NULL);
/*!40000 ALTER TABLE `rol` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `solicitud_exportacion_datos`
--

DROP TABLE IF EXISTS `solicitud_exportacion_datos`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `solicitud_exportacion_datos` (
  `id` int NOT NULL AUTO_INCREMENT,
  `id_usuario` int NOT NULL,
  `estado` varchar(10) NOT NULL DEFAULT 'enviada',
  PRIMARY KEY (`id`),
  KEY `id_usuario` (`id_usuario`),
  CONSTRAINT `solicitud_exportacion_datos_ibfk_1` FOREIGN KEY (`id_usuario`) REFERENCES `usuario` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `solicitud_exportacion_datos`
--

LOCK TABLES `solicitud_exportacion_datos` WRITE;
/*!40000 ALTER TABLE `solicitud_exportacion_datos` DISABLE KEYS */;
/*!40000 ALTER TABLE `solicitud_exportacion_datos` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `terminos_condiciones`
--

DROP TABLE IF EXISTS `terminos_condiciones`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `terminos_condiciones` (
  `id` int NOT NULL AUTO_INCREMENT,
  `estado` varchar(10) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `descripcion` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `terminos_condiciones`
--

LOCK TABLES `terminos_condiciones` WRITE;
/*!40000 ALTER TABLE `terminos_condiciones` DISABLE KEYS */;
/*!40000 ALTER TABLE `terminos_condiciones` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `terminos_contrasena`
--

DROP TABLE IF EXISTS `terminos_contrasena`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `terminos_contrasena` (
  `id` int NOT NULL,
  `cant_caracteres` int NOT NULL,
  `cant_min_minusculas` int NOT NULL,
  `cant_min_mayusculas` int NOT NULL,
  `cant_min_numeros` int NOT NULL,
  `cant_min_caracteres_esp` int NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `terminos_contrasena`
--

LOCK TABLES `terminos_contrasena` WRITE;
/*!40000 ALTER TABLE `terminos_contrasena` DISABLE KEYS */;
/*!40000 ALTER TABLE `terminos_contrasena` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `token_invalidos`
--

DROP TABLE IF EXISTS `token_invalidos`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `token_invalidos` (
  `id` int NOT NULL AUTO_INCREMENT,
  `token` varchar(500) NOT NULL,
  `expiracion` timestamp NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `token_invalidos`
--

LOCK TABLES `token_invalidos` WRITE;
/*!40000 ALTER TABLE `token_invalidos` DISABLE KEYS */;
/*!40000 ALTER TABLE `token_invalidos` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `usuario`
--

DROP TABLE IF EXISTS `usuario`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `usuario` (
  `id` int NOT NULL AUTO_INCREMENT,
  `id_rol` int DEFAULT NULL,
  `id_estado` int DEFAULT NULL,
  `nombre_usuario` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `nombre` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `contrasena_hash` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `email` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `fecha_creacion` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `id_rol` (`id_rol`),
  KEY `id_estado` (`id_estado`),
  CONSTRAINT `usuario_ibfk_1` FOREIGN KEY (`id_rol`) REFERENCES `rol` (`id`),
  CONSTRAINT `usuario_ibfk_2` FOREIGN KEY (`id_estado`) REFERENCES `estado` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `usuario`
--

LOCK TABLES `usuario` WRITE;
/*!40000 ALTER TABLE `usuario` DISABLE KEYS */;
INSERT INTO `usuario` VALUES (1,1,3,'s','q','2','3@gmail.com','2024-08-29 16:27:18'),(2,3,1,'jhoan','lindo','$2b$10$ISB3/EwYK3.o/uhh73ze8etW/RwnAzXQx1bRWcKwnp1riUSRK5gHC','jhoan@gmail.com','2024-08-29 16:27:37'),(3,NULL,1,'exxney','exneyder','$2b$10$eY296e04Z4FWS6npmWmxl.1TQj1jZbUjMLaGhoxftgsvoIjLSiqzW','asdfaf@gmail.com','2024-09-04 12:17:48'),(4,NULL,3,'dfhfdhhd','dfhdfh','$2b$10$ZcyP0/EXSGTIxgrHHpzLBuqmV1zEdcOMh7OQUnHFJwi7S4cUuNa.2','dfhfdhhd@gmail.com','2024-09-11 13:22:27'),(5,NULL,3,'fghfghfh','fghfgh','$2b$10$KkOU6bODHpTLIxgbDjzhPe42UsaRkAesMr11.RZLF3um.X8dNIQTO','dfhfdhhgd@gmail.com','2024-09-11 13:26:25'),(6,NULL,NULL,'gfhdfhdf','klimber','$2b$10$PKLw3zBm4fJsd/eax.tazOIxoCVvZJftJPqYsNifNoif2fe0ye9PO','dfhfdsgsdgdhhd@gmail.com','2024-09-11 13:28:21'),(7,NULL,1,'KEINER SERNA','Keiner','$2b$10$8qjqSk5ZSD0QOQkBNwm4VeftaSP5Lge5SVWKbznE7t6fYmmcjJhj6','gzkeinergmail.com','2024-09-11 15:52:36'),(8,NULL,NULL,'KEINER SERNA','Keiner','$2b$10$ojFF.wBvse3a0nV6wJdgpOjsuBOh1Zid.ILXg6QQXAZkLf4GTtwwK','gzkeiner@gmail.com','2024-09-11 15:52:43'),(9,NULL,3,'Keiner Serna','Keiner','$2b$10$j3HXozAo/zZd0E0vJBsEdeaYOtwpM8nLZV0n0YBXyGeldW4ONa5Ay','gzkeinergmail.com','2024-09-11 15:56:45'),(10,NULL,NULL,'el maestro en cagarla','Jhoan Monsalve','$2b$10$toNhrkrXF3CyY2TmmugQS.RBdPmeMk5hbeTZhJOmkv3uGHTiO3Rky','shrek@gmail.com','2024-09-11 19:02:42'),(11,1,3,'ghjdkl','ghdjskls','$2b$10$anJfjYShcTtmuP6MnCbtRe8H2aL0xw55N5QEliHFvtTd0PfP85kFO','adfa','2024-09-11 19:19:25'),(12,2,3,'asfjalsjfla','mnfasfljkaf','$2b$10$65ECrZMpC8KXBf1J0fu4T.SXUP4PeHkTW8uj4suyNpGMh8gQmvQ0S','a@gmail.com','2024-09-14 19:05:19');
/*!40000 ALTER TABLE `usuario` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `usuario_rol`
--

DROP TABLE IF EXISTS `usuario_rol`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `usuario_rol` (
  `id` int NOT NULL AUTO_INCREMENT,
  `idusuario` int NOT NULL,
  `idRol` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idRol` (`idRol`),
  KEY `idusuario` (`idusuario`),
  CONSTRAINT `usuario_rol_ibfk_1` FOREIGN KEY (`idRol`) REFERENCES `rol` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `usuario_rol_ibfk_2` FOREIGN KEY (`idusuario`) REFERENCES `usuario` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `usuario_rol`
--

LOCK TABLES `usuario_rol` WRITE;
/*!40000 ALTER TABLE `usuario_rol` DISABLE KEYS */;
/*!40000 ALTER TABLE `usuario_rol` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `verificacion_doble`
--

DROP TABLE IF EXISTS `verificacion_doble`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `verificacion_doble` (
  `id` int NOT NULL AUTO_INCREMENT,
  `id_admin` int NOT NULL,
  `estado_v` int NOT NULL,
  PRIMARY KEY (`id`),
  KEY `fabio` (`id_admin`),
  KEY `estado` (`estado_v`),
  CONSTRAINT `estado` FOREIGN KEY (`estado_v`) REFERENCES `estado_verificacion_doble` (`id`),
  CONSTRAINT `fabio` FOREIGN KEY (`id_admin`) REFERENCES `administrador` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `verificacion_doble`
--

LOCK TABLES `verificacion_doble` WRITE;
/*!40000 ALTER TABLE `verificacion_doble` DISABLE KEYS */;
INSERT INTO `verificacion_doble` VALUES (3,5,1),(4,6,2);
/*!40000 ALTER TABLE `verificacion_doble` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2024-09-15 10:06:21
