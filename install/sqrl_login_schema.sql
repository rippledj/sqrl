# Create and use database sqrl_login
# ------------------------------------------------------------
CREATE DATABASE `sqrl_login`;
USE `sqrl_login`;

# Dump of table sqrl_nonce
# ------------------------------------------------------------

CREATE TABLE `sqrl_nuts` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `nut` char(64) NOT NULL,
  `created` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `ip` int(10) unsigned NOT NULL,
  `action` int(10) unsigned NOT NULL,
  `related_public_key` char(44) DEFAULT NULL,
  `verified` tinyint(4) NOT NULL DEFAULT '0',
  `kill_session` tinyint(4) NOT NULL DEFAULT '0',
  `orig_nut` char(64) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `nut` (`nut`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;



# Dump of table sqrl_pubkey
# ------------------------------------------------------------

CREATE TABLE `sqrl_pubkey` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `public_key` char(44) NOT NULL,
  `vuk` char(44) NOT NULL,
  `suk` char(44) NOT NULL,
  `disabled` tinyint(4) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `public_key` (`public_key`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
