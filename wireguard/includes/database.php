<?php
// ----------------------------------------------------------------------------------------------
// Conexão com banco mkradius e garantia da tabela wg_ramais (REPAIR ALL)
// ----------------------------------------------------------------------------------------------
$dbHost = '127.0.0.1';
$dbUser = 'root';
$dbPass = 'vertrigo';
$dbName = 'mkradius';

$mysqli  = @new mysqli($dbHost, $dbUser, $dbPass, $dbName);
$erro_db = null;
$res_nas = null;

if ($mysqli->connect_errno) {
	$erro_db = 'Erro ao conectar no banco mkradius: ' . $mysqli->connect_error;
} else {
	// 1. Tenta criar a tabela inteira se ela não existir (Instalação Limpa)
	$sqlCreate = "
		CREATE TABLE IF NOT EXISTS wg_ramais (
			id                   INT(11) NOT NULL AUTO_INCREMENT,
			id_nas               INT(11) NOT NULL,
			wg_client_id         VARCHAR(64) NOT NULL,
			peer_name            VARCHAR(128) NOT NULL,
			ip_wg                VARCHAR(64) DEFAULT NULL,
			endpoint             VARCHAR(64) DEFAULT NULL,
			public_key           VARCHAR(255) DEFAULT NULL,
			preshared_key        VARCHAR(255) DEFAULT NULL,
			allowed_ips          VARCHAR(255) DEFAULT NULL,
			persistent_keepalive INT(11) DEFAULT NULL,
			latest_handshake_at  DATETIME DEFAULT NULL,
			transfer_rx          BIGINT DEFAULT 0,
			transfer_tx          BIGINT DEFAULT 0,
			config_text          MEDIUMTEXT DEFAULT NULL,
			interface_text       LONGTEXT NULL,
			downloadable_config  TINYINT(1) DEFAULT 1,
			status               ENUM('enabled','disabled') NOT NULL DEFAULT 'enabled',
			provisionado_em      DATETIME DEFAULT NULL,
			atualizado_em        DATETIME DEFAULT NULL,
			PRIMARY KEY (id),
			UNIQUE KEY uniq_ip_wg       (ip_wg),
			UNIQUE KEY uniq_peer_name   (peer_name),
			UNIQUE KEY uniq_wg_client   (wg_client_id),
			KEY idx_wg_ramais_id_nas    (id_nas),
			KEY idx_wg_ramais_client    (wg_client_id)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8
	";
	
	if (!$mysqli->query($sqlCreate)) {
		$erro_db = 'Erro ao criar/verificar tabela wg_ramais: ' . $mysqli->error;
	} else {
		// ----------------------------------------------------------------------
		// 2. SISTEMA DE REPAIR ALL (Verifica e recria qualquer coluna faltando)
		// ----------------------------------------------------------------------
		
		// Gabarito de como todas as colunas deveriam ser:
		$expected_columns = [
			'id_nas'               => 'INT(11) NOT NULL',
			'wg_client_id'         => 'VARCHAR(64) NOT NULL',
			'peer_name'            => 'VARCHAR(128) NOT NULL',
			'ip_wg'                => 'VARCHAR(64) DEFAULT NULL',
			'endpoint'             => 'VARCHAR(64) DEFAULT NULL',
			'public_key'           => 'VARCHAR(255) DEFAULT NULL',
			'preshared_key'        => 'VARCHAR(255) DEFAULT NULL',
			'allowed_ips'          => 'VARCHAR(255) DEFAULT NULL',
			'persistent_keepalive' => 'INT(11) DEFAULT NULL',
			'latest_handshake_at'  => 'DATETIME DEFAULT NULL',
			'transfer_rx'          => 'BIGINT DEFAULT 0',
			'transfer_tx'          => 'BIGINT DEFAULT 0',
			'config_text'          => 'MEDIUMTEXT DEFAULT NULL',
			'interface_text'       => 'LONGTEXT NULL',
			'downloadable_config'  => 'TINYINT(1) DEFAULT 1',
			'status'               => "ENUM('enabled','disabled') NOT NULL DEFAULT 'enabled'",
			'provisionado_em'      => 'DATETIME DEFAULT NULL',
			'atualizado_em'        => 'DATETIME DEFAULT NULL'
		];

		// Busca quais colunas realmente existem agora no banco
		$result = $mysqli->query("SHOW COLUMNS FROM wg_ramais");
		$existing_columns = [];
		if ($result) {
			while ($row = $result->fetch_assoc()) {
				$existing_columns[] = $row['Field'];
			}
		}

		// Compara o gabarito com o que existe. Se faltar, faz o ALTER TABLE.
		foreach ($expected_columns as $col_name => $col_definition) {
			if (!in_array($col_name, $existing_columns)) {
				$mysqli->query("ALTER TABLE wg_ramais ADD COLUMN `$col_name` $col_definition");
			}
		}
		// ----------------------------------------------------------------------
	}

	// 3. Busca os NAS (Ramais) para a aplicação usar
	if (!$erro_db) {
		$sql = "
			SELECT
				id,
				shortname,
				nasname,
				bairro
			FROM nas
			ORDER BY id ASC
		";
		$res_nas = $mysqli->query($sql);
		if (!$res_nas) {
			$erro_db = 'Erro ao buscar ramais (nas): ' . $mysqli->error;
		}
	}
}
?>
