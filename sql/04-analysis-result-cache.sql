-- analysis result cache database
-- ------------------------------------------------------
-- Houses the analysis_result_cache and blob_refs tables in a dedicated
-- database so they can be managed independently of the main ace database.
-- Both tables are partitioned daily by created_at (RANGE COLUMNS) so old
-- data is reclaimed with an instant DROP PARTITION instead of row DELETEs.
-- See bin/manage-analysis-result-cache-partitions.sh.

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

CREATE DATABASE IF NOT EXISTS `analysis-result-cache`;
ALTER DATABASE `analysis-result-cache` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_520_ci;
USE `analysis-result-cache`;

--
-- Table structure for table `analysis_result_cache`
--
-- created_at is DATETIME(6) (not TIMESTAMP) because RANGE COLUMNS partitioning
-- does not support TIMESTAMP. It is part of the primary key because MySQL
-- requires the partitioning column to appear in every unique key; cache_key
-- stays leftmost so lookups by cache_key still use the primary key prefix.
-- Microsecond precision (fsp=6) keeps the (cache_key, created_at) key unique
-- when the same observable is re-analyzed twice inside the same second.

DROP TABLE IF EXISTS `analysis_result_cache`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `analysis_result_cache` (
  `cache_key` VARCHAR(64) NOT NULL,
  `module_name` VARCHAR(512) NOT NULL,
  `module_version` INT NOT NULL,
  `observable_type` VARCHAR(64) NOT NULL,
  `observable_value` TEXT NOT NULL,
  `delta_zstd` LONGBLOB NOT NULL,
  `delta_uncompressed_size` INT NOT NULL,
  `has_blob_refs` TINYINT(1) NOT NULL DEFAULT 0,
  `created_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  `expires_at` DATETIME NOT NULL,
  PRIMARY KEY (`cache_key`, `created_at`),
  KEY `idx_module_expires` (`module_name`, `expires_at`),
  KEY `ix_analysis_result_cache_expires_at` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
PARTITION BY RANGE COLUMNS(created_at) (
  PARTITION p_catchall VALUES LESS THAN (MAXVALUE)
);
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `blob_refs`
--

DROP TABLE IF EXISTS `blob_refs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `blob_refs` (
  `sha256` VARCHAR(64) NOT NULL,
  `referrer_kind` VARCHAR(32) NOT NULL,
  `referrer_id` VARCHAR(128) NOT NULL,
  `created_at` DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (`sha256`, `referrer_kind`, `referrer_id`, `created_at`),
  KEY `idx_by_referrer` (`referrer_kind`, `referrer_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
PARTITION BY RANGE COLUMNS(created_at) (
  PARTITION p_catchall VALUES LESS THAN (MAXVALUE)
);
/*!40101 SET character_set_client = @saved_cs_client */;

/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;
/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;
