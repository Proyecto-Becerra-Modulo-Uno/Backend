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
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2024-09-15 16:52:01
