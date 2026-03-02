<?php
//debug (opcional)
error_reporting(E_ALL);
ini_set('display_errors', 1);

// INCLUI FUNÇÕES DE ADDONS
include('addons.class.php');

// Garantir não duplicidade de post
if (session_status() === PHP_SESSION_NONE) {
	session_start();
}

$msg_sucesso = $_SESSION['wg_msg_sucesso'] ?? '';
unset($_SESSION['wg_msg_sucesso']);

$msg_erro = $_SESSION['wg_msg_erro'] ?? '';
unset($_SESSION['wg_msg_erro']);

// ----------------------------------------------------------------------------------------------
// Configurações básicas
// ----------------------------------------------------------------------------------------------
$socketPath = '/run/wgmkauth.sock';

$msg_erro    = $msg_erro    ?? '';
$msg_sucesso = $msg_sucesso ?? '';

// ----------------------------------------------------------------------------------------------
// Helper: chamada ao socket UNIX do WireGuard
// ----------------------------------------------------------------------------------------------
function wg_call(array $payload, $socketPath)
{
	$errno  = 0;
	$errstr = '';

	$fp = @stream_socket_client("unix://{$socketPath}", $errno, $errstr, 20);
	if (!$fp) {
		return [
			'ok'      => false,
			'error'   => 'connect_failed',
			'message' => $errstr,
			'errno'   => $errno,
		];
	}

	stream_set_timeout($fp, 20);

	$line = json_encode($payload, JSON_UNESCAPED_SLASHES) . "\n";
	fwrite($fp, $line);

	$resp = stream_get_contents($fp);
	$meta = stream_get_meta_data($fp);
	fclose($fp);

	file_put_contents(
		'/tmp/wg_php_debug.log',
		date('c') . " WG_CALL RAW: " . var_export($resp, true) .
		" META: " . var_export($meta, true) . "\n",
		FILE_APPEND
	);

	if ($resp === '' || $resp === false) {
		return [
			'ok'    => false,
			'error' => 'no_response',
			'message' => $meta['timed_out'] ? 'Timeout após 20s' : 'Daemon não respondeu',
		];
	}

	$data = json_decode($resp, true);

	if (!is_array($data)) {
		file_put_contents(
			'/tmp/wg_php_debug.log',
			date('c') . " WG_CALL BAD_JSON: " . var_export($resp, true) . "\n",
			FILE_APPEND
		);

		return [
			'ok'    => false,
			'error' => 'bad_json',
			'raw'   => $resp,
		];
	}

	return $data;
}

// ----------------------------------------------------------------------------------------------
// NORMALIZAR .conf EM UMA STRING WG-IMPORT (RouterOS 7.x)
// ----------------------------------------------------------------------------------------------
function normalizar_conf_para_wg_import(string $conf): string
{
    // 1) quebra em linhas reais (independente de \r\n, \n, \r)
    $linhas = preg_split("/\r\n|\n|\r/", $conf);

    $limpas = [];
    foreach ($linhas as $linha) {
        // mantém a linha original, só tira espaços nas bordas
        $trim = trim($linha);

        // pula só linhas vazias e 100% comentário (# no início)
        if ($trim === '' || strpos($trim, '#') === 0) {
            continue;
        }

        // não mexe em [Interface], [Peer], PresharedKey, AllowedIPs, Endpoint, etc.
        $limpas[] = $trim;
    }

    // 2) junta com \n literal para o MikroTik (uma única barra na string final)
    $conf_limpo = implode('\n', $limpas);

    // 3) escapa aspas duplas para não quebrar o config-string="..."
    $conf_limpo = str_replace('"', '\"', $conf_limpo);

    // 4) monta o comando wg-import completo
    return '/interface wireguard/wg-import config-string="' . $conf_limpo . '"';
}
/**
 * Calcula o endereço de rede a partir de um host/CIDR.
 * Ex.: "10.178.52.1/24" → "10.178.52.0/24"
 *      "172.16.5.33/20" → "172.16.0.0/20"
 */
function cidr_to_network(string $host_cidr): string
{
    $parts = explode('/', $host_cidr, 2);
    if (count($parts) !== 2) {
        return $host_cidr;
    }
    $ip   = $parts[0];
    $bits = (int)$parts[1];
    $long = ip2long($ip);
    if ($long === false) {
        return $host_cidr;
    }
    $mask    = $bits === 0 ? 0 : (~0 << (32 - $bits));
    $network = $long & $mask;
    return long2ip($network) . '/' . $bits;
}

/**
 * Calcula quantos peers cabem numa rede WireGuard.
 * Desconta: endereço de rede + broadcast + server host = 3
 * Ex.: /24 → 253, /22 → 1021, /16 → 65533
 */
function cidr_max_peers(string $cidr): int
{
    $parts = explode('/', $cidr, 2);
    if (count($parts) !== 2) {
        return 0;
    }
    $bits = (int)$parts[1];
    if ($bits < 1 || $bits > 30) {
        return 0;
    }
    return (int)(pow(2, 32 - $bits) - 3);
}

// ----------------------------------------------------------------------------------------------
// Conexão com banco mkradius e garantia da tabela wg_ramais
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
	$sqlCreate = "
		CREATE TABLE IF NOT EXISTS wg_ramais (
			id                   INT(11) NOT NULL AUTO_INCREMENT,
			id_nas               INT(11) NOT NULL,
			wg_client_id         VARCHAR(64) NOT NULL,
			peer_name            VARCHAR(128) NOT NULL,
			ip_wg                VARCHAR(64) DEFAULT NULL,
			endpoint VARCHAR(64) DEFAULT NULL,
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
	}

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

// ----------------------------------------------------------------------------------------------
// Ações (POST) - criar peer / editar / bulk / provisionar
// ----------------------------------------------------------------------------------------------
include __DIR__ . '/wg_actions_post.php';
// ----------------------------------------------------------------------------------------------
// Tabs (GET)
// ----------------------------------------------------------------------------------------------
$tab = isset($_GET['tab']) ? $_GET['tab'] : 'status';

// ----------------------------------------------------------------------------------------------
// Filtros e paginação (apenas na aba peers)
// ----------------------------------------------------------------------------------------------
$page        = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
$per_page    = isset($_GET['per_page']) ? max(5, (int)$_GET['per_page']) : 20;
$search      = isset($_GET['search']) ? trim($_GET['search']) : '';
$status_filt = isset($_GET['status']) ? trim($_GET['status']) : '';

// ----------------------------------------------------------------------------------------------
// Dados para as abas
// ----------------------------------------------------------------------------------------------
$status_data       = null;
$version_data      = null;
$server_cfg_data   = null;
$list_clients_data = null;
$wg_ramais_rows    = [];
$total_rows        = 0;
$ramais_list       = []; // garante que exista
$wg_base_cidr      = '';

// ----------------------------------------------------------------------------------------------
// Gerenciamento de Downloads e Modais de Visualização (conf, rsc, wgimport)
// ----------------------------------------------------------------------------------------------
include __DIR__ . '/wg_downloads.php';

// ----------------------
// Carregar status/versão + dados por aba
// ----------------------
if (!$erro_db) {
    // sempre carrega status/versão para todas as abas
    $status_data  = wg_call(['action' => 'status'],  $socketPath);
    $version_data = wg_call(['action' => 'version'], $socketPath);
    
	// ========================================
	// ✅ VARIÁVEIS GLOBAIS (PARA TODAS AS ABAS)
	// ========================================

	// Daemon OK = socket conectou E recebeu resposta do daemon
	// (wg_call retorna 'connect_failed' quando o socket não existe)
	$daemon_ok = is_array($status_data) 
			  && (!isset($status_data['error']) || $status_data['error'] !== 'connect_failed');
	// Interface UP = status ok:true E if_up == true
	$interface_up = ($daemon_ok && !empty($status_data['ok']) && !empty($status_data['data']['if_up']));

	// Porta atual (só disponível quando interface UP)
	$current_port = 0;
	if ($interface_up && isset($status_data['data']['port'])) {
		$current_port = (int)$status_data['data']['port'];
	}

	// Rede atual (só disponível quando interface UP)
	$current_network = '';
	if ($interface_up && !empty($status_data['data']['wg_address'])) {
		$current_network = $status_data['data']['wg_address'];
	}

	// ========================================
	// server-get-config: ÚNICA CHAMADA, fonte de verdade do Card 2
	// Retorna ok:true + rawText quando wg0.conf existe no disco
	// Retorna ok:false + conf_not_found quando NÃO existe
	// Funciona INDEPENDENTE da interface estar UP ou DOWN
	// ========================================
	$server_cfg_data       = null;
	$wg_conf_raw           = '';
	$interface_configurada = false;

	if ($daemon_ok) {
		$server_cfg_data = wg_call(['action' => 'server-get-config'], $socketPath);

		if (is_array($server_cfg_data) && !empty($server_cfg_data['ok'])) {
			$interface_configurada = true;

			if (!empty($server_cfg_data['data']['rawText'])) {
				$wg_conf_raw = trim($server_cfg_data['data']['rawText']);
			}
		}

		// Se interface UP, pegar porta/rede do status (fallback do server-get-config)
		if (!$current_port && !empty($server_cfg_data['data']['listenPort'])) {
			$current_port = (int)$server_cfg_data['data']['listenPort'];
		}
		if ($current_network === '' && !empty($server_cfg_data['data']['address'])) {
			$current_network = $server_cfg_data['data']['address'];
		}
	}
    
    // ========================================
    // ROTEAMENTO POR ABA
    // ========================================

		if ($tab === 'status') {
			// Tudo já foi carregado no BLOCO 1 (variáveis globais)
			// $server_cfg_data, $wg_conf_raw e $interface_configurada
			// já estão prontos. Zero chamadas extras.

		} elseif ($tab === 'peers') {

        $list_clients_data = wg_call(['action' => 'list-clients'], $socketPath);

        // filtros + paginação (igual você já fazia)
        $where  = '1=1';
        $params = [];
        $types  = '';

        if ($search !== '') {
            $where .= " AND (peer_name LIKE ? OR ip_wg LIKE ?)";
            $like   = '%' . $search . '%';
            $params[] = $like;
            $params[] = $like;
            $types   .= 'ss';
        }

        if ($status_filt !== '' && in_array($status_filt, ['enabled','disabled'], true)) {
            $where   .= " AND status = ?";
            $params[] = $status_filt;
            $types   .= 's';
        }

        $sqlCount = "SELECT COUNT(*) AS total FROM wg_ramais WHERE {$where}";
        $stmtCnt  = $mysqli->prepare($sqlCount);
        if ($stmtCnt) {
            if ($params) {
                $stmtCnt->bind_param($types, ...$params);
            }
            $stmtCnt->execute();
            $resCnt = $stmtCnt->get_result();
            $rowCnt = $resCnt->fetch_assoc();
            $total_rows = (int)$rowCnt['total'];
            $stmtCnt->close();
        }

        $offset = ($page - 1) * $per_page;

        $sqlRamais = "
            SELECT
                id,
                id_nas,
                wg_client_id,
                peer_name,
                ip_wg,
                public_key,
                allowed_ips,
                persistent_keepalive,
                latest_handshake_at,
                transfer_rx,
                transfer_tx,
                downloadable_config,
                status,
                provisionado_em,
                atualizado_em,
                config_text
            FROM wg_ramais
            WHERE {$where}
            ORDER BY id ASC
            LIMIT ?, ?
        ";

        $types_pag  = $types . 'ii';
        $params_pag = $params;
        $params_pag[] = $offset;
        $params_pag[] = $per_page;

        $stmtRam = $mysqli->prepare($sqlRamais);
        if ($stmtRam) {
            $stmtRam->bind_param($types_pag, ...$params_pag);
            $stmtRam->execute();
            $res = $stmtRam->get_result();
            while ($row = $res->fetch_assoc()) {
                $wg_ramais_rows[] = $row;
            }
            $stmtRam->close();
        }

        } elseif ($tab === 'provisionar') {

            // Rede base: usa $current_network
            $wg_server_host = $current_network;
            $wg_base_cidr   = $current_network !== '' ? cidr_to_network($current_network) : '';
            $wg_max_peers   = $wg_base_cidr !== '' ? cidr_max_peers($wg_base_cidr) : 0;
            
            // 🚀 SELECT TURBINADO PARA O OTP DIAGNÓSTICO
            $sqlRamais = "
                SELECT
                    n.id          AS id_nas,
                    n.shortname,
                    n.nasname,
                    n.ipfall,     -- Novo: IP Público
                    n.senha,      -- Novo: Senha MK-AUTH
                    n.secret,     -- Novo: Secret Radius
                    n.portassh,   -- Novo: Porta SSH
                    w.id          AS wg_id,
                    w.peer_name   AS wg_peer_name,
                    w.ip_wg       AS wg_ip,
					w.status      AS wg_status
                FROM nas n
                LEFT JOIN wg_ramais w ON w.id_nas = n.id
                ORDER BY n.id ASC
            ";
        if ($res = $mysqli->query($sqlRamais)) {
            while ($row = $res->fetch_assoc()) {
                $ramais_list[] = $row;
            }
            $res->close();
        } else {
            $erro_db = 'Erro ao carregar ramais para provisionamento: ' . $mysqli->error;
        }
        
        } elseif ($tab === 'criar') {
            
            // 1. Coleta dados da rede atual
            $wg_server_host = $current_network;
            $wg_base_cidr   = $current_network !== '' ? cidr_to_network($current_network) : '';
            $wg_max_peers   = $wg_base_cidr !== '' ? cidr_max_peers($wg_base_cidr) : 0;
            
            $sugestao_ip_seq  = '';
            $sugestao_ip_rand = '';
            
            if ($wg_base_cidr !== '') {
                $used_ips = [];
                // 2. Levanta todos os IPs já em uso no banco
                $rs = $mysqli->query("SELECT ip_wg FROM wg_ramais WHERE ip_wg IS NOT NULL");
                if ($rs) {
                    while ($row = $rs->fetch_assoc()) {
                        $ip_only = explode('/', trim($row['ip_wg']))[0];
                        $used_ips[$ip_only] = true;
                    }
                    $rs->close();
                }
                
                // 3. Trava o IP do próprio servidor para não ser sugerido
                $srv_ip = explode('/', $wg_server_host)[0];
                $used_ips[$srv_ip] = true;
                
                list($net_ip, $mask) = explode('/', $wg_base_cidr);
                $net_long = ip2long($net_ip);
                $mask_int = (int)$mask;
                
                // 4. Invoca a função pronta para sugerir o sequencial inicial
                if (function_exists('wg_pick_free_ip_seq')) {
                    $sugestao_ip_seq = wg_pick_free_ip_seq($net_long, $mask_int, $used_ips);
                }
                
                // 5. MÁGICA: Exporta os dados para o JavaScript fazer o sorteio em tempo real
                $js_used_ips = json_encode(array_keys($used_ips));
                $js_net_ip   = json_encode($net_ip);
                $js_mask_int = json_encode($mask_int);
            }
        } // Fecha o elseif ($tab === 'criar')
    } // <--- ERA ESTA CHAVE AQUI QUE FALTAVA! (Ela fecha o if (!$erro_db) lá do topo)
?>
<!DOCTYPE html>
<html lang="pt-BR" class="has-navbar-fixed-top">
<head>
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<meta charset="iso-8859-1">
	<title>MK-AUTH :: <?php echo $Manifest->{'name'}; ?></title>

	<link href="../../estilos/mk-auth.css" rel="stylesheet" type="text/css" />
	<link href="../../estilos/font-awesome.css" rel="stylesheet" type="text/css" />
	<link href="../../estilos/bi-icons.css" rel="stylesheet" type="text/css" />
	<link href="wg_addon.css" rel="stylesheet" type="text/css" />
	
	<script src="../../scripts/jquery.js"></script>
	<script src="../../scripts/mk-auth.js"></script>
</head>
<body>

<?php include('../../topo.php'); ?>

<nav class="breadcrumb has-bullet-separator is-centered" aria-label="breadcrumbs">
	<ul>
		<li><a href="#">ADDON</a></li>
		<li class="is-active">
			<a href="#" aria-current="page">
				<?php echo strtoupper($Manifest->{'name'} . ' # ' . $Manifest->{'version'} . ' # ' . $Manifest->{'author'}); ?>
			</a>
		</li>
	</ul>
</nav>

<div class="content">
<!-- CABEÇALHO WIREGUARD VPN COMPACTO -->
<div class="mb-4" style="margin-top: -10px;">
    <!-- Colocamos TUDO dentro do h1 com display: flex -->
    <h1 class="title is-4 mb-0" style="font-weight: 800; color: #0f172a; letter-spacing: -0.5px; display: flex; align-items: center; gap: 12px;">
        
        <!-- Logo SVG Oficial -->
        <img src="WireGuard_logo.svg" 
             alt="Logo WireGuard" 
             style="width: 36px; height: 36px; filter: drop-shadow(0 3px 6px rgba(0,0,0,0.15)); margin-top: -2px;">
        
        WIREGUARD VPN
        
        <!-- O SEU botão (i) original mantendo a lógica de abrir o Popup -->
        <a href="#"
           onclick="document.getElementById('about-wg-popup').classList.add('is-active'); return false;"
           title="Sobre o Addon WireGuard"
           style="color: #94a3b8; transition: color 0.2s ease; margin-top: 2px;">
          <span class="icon is-small hover-ciano">
            <i class="bi bi-info-circle"></i>
          </span>
        </a>
    </h1>
</div>

	<?php if ($erro_db): ?>
		<div class="notification is-danger">
			<?php echo htmlspecialchars($erro_db); ?>
		</div>
	<?php endif; ?>

		<?php if ($msg_sucesso): ?>
			<div class="notification is-success is-light">
				<button class="delete" onclick="this.parentElement.remove()"></button>
				<?php echo nl2br(htmlspecialchars($msg_sucesso)); ?>
			</div>
		<?php endif; ?>

		<?php if ($msg_erro): ?>
			<div class="notification is-danger is-light">
				<button class="delete" onclick="this.parentElement.remove()"></button>
				<?php echo nl2br(htmlspecialchars($msg_erro)); ?>
			</div>
		<?php endif; ?>

<div class="tabs is-boxed">
  <ul>
    <!-- ========================================
         ABA STATUS (sempre acessível)
         ======================================== -->
    <li class="<?php echo ($tab === 'status') ? 'is-active' : ''; ?>">
      <a href="?tab=status">
        <span class="icon"><i class="bi bi-server"></i></span>
        <span>Servidor WireGuard</span>
      </a>
    </li>

    <?php if ($daemon_ok): ?>
      <!-- ========================================
           ABAS HABILITADAS (daemon online)
           ======================================== -->
      <li class="<?php echo ($tab === 'peers') ? 'is-active' : ''; ?>">
        <a href="?tab=peers">
          <span class="icon"><i class="bi bi-people-fill"></i></span>
          <span>Peers</span>
        </a>
      </li>
      <li class="<?php echo ($tab === 'provisionar') ? 'is-active' : ''; ?>">
        <a href="?tab=provisionar">
          <span class="icon"><i class="bi bi-hdd-rack-fill"></i></span>
          <span>Provisionar Ramais</span>
        </a>
      </li>
      <li class="<?php echo ($tab === 'criar') ? 'is-active' : ''; ?>">
        <a href="?tab=criar">
          <span class="icon"><i class="bi bi-plus-circle-fill"></i></span>
          <span>Criar Peer</span>
        </a>
      </li>
      
    <?php else: ?>
      <!-- ========================================
           ABAS DESABILITADAS (daemon offline)
           ======================================== -->
      <li class="is-disabled" title="Requer daemon WireGuard online">
        <a>
          <span class="icon"><i class="bi bi-people-fill"></i></span>
          <span>Peers</span>
        </a>
      </li>
      <li class="is-disabled" title="Requer daemon WireGuard online">
        <a>
          <span class="icon"><i class="bi bi-hdd-rack-fill"></i></span>
          <span>Provisionar Ramais</span>
        </a>
      </li>
      <li class="is-disabled" title="Requer daemon WireGuard online">
        <a>
          <span class="icon"><i class="bi bi-plus-circle-fill"></i></span>
          <span>Criar Peer</span>
        </a>
      </li>
    <?php endif; ?>
  </ul>
</div>
<!-- ========================================
     BLOQUEIO: Daemon offline
     ======================================== -->
<?php if ($tab !== 'status' && !$daemon_ok): ?>
    <div class="notification is-warning">
        <p class="title is-5">
            <span class="icon has-text-warning">
                <i class="bi bi-exclamation-triangle-fill"></i>
            </span>
            Daemon WireGuard Offline
        </p>
        <p>
            As funcionalidades de <strong>Peers</strong>, <strong>Provisionar Ramais</strong> 
            e <strong>Criar Peer</strong> requerem que o serviço <code>wg-mkauthd</code> 
            esteja em execução.
        </p>
        <div class="content" style="margin-top: 1.5rem;">
            <p><strong>Diagnóstico (SysVinit):</strong></p>
            <pre style="background: #f5f5f5; padding: 0.75rem; border-radius: 4px;"><code># Verificar se daemon está rodando
ps aux | grep wg-mkauthd | grep -v grep

# Verificar socket
ls -l /run/wgmkauth.sock

# Iniciar daemon
service wg-mkauthd start

# Verificar logs
tail -50 /var/log/wg-mkauthd.log</code></pre>
        </div>
        <p style="margin-top: 1rem;">
            <a href="https://wiki.mk-auth.com.br/doku.php?id=mk-auth_addons" 
               target="_blank" 
               class="button is-info is-light">
                <span class="icon"><i class="bi bi-book"></i></span>
                <span>Documentação</span>
            </a>
        </p>
    </div>
<?php 
    // Força sair do script aqui para não renderizar conteúdo das abas
    include('../../baixo.php'); 
    echo '<script src="../../menu.js.hhvm"></script>';
    echo '<script src="wg_addon.js"></script>';
    echo '</body></html>';
    exit;
endif; 
?>

<!-- ========================================
     CONTEÚDO DAS ABAS (só renderiza se passar pelo bloqueio)
     ======================================== -->
<?php if ($tab === 'status'): ?>

<div class="box" style="border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); padding: 1.5rem; background: #fafafa;">
    
    <!-- GRID 3-4-5 para dar mais espaço ao Backup e menos à Interface -->
    <div class="columns is-align-items-stretch">

        <!-- ========================================
             COLUNA 1: STATUS (is-3 = 25% da tela)
             ======================================== -->
        <div class="column is-3">

<?php
// ========================================
// ANALISAR STATUS E DEFINIR ESTADOS
// ========================================

$state = [
    'icon'         => 'bi-question-circle-fill',
    'icon_color'   => '#999',
    'text'         => 'Status desconhecido',
    'detail'       => '',
    'box_class'    => 'notification is-light',
    'show_buttons' => false,
    'show_details' => false,
    'show_info'    => [],
    'data'         => null
];

// ========================================
// DETECTAR CENÁRIO
// ========================================

if (!is_array($status_data)) {
    // ❌ CENÁRIO 1: Socket inacessível (DAEMON OFFLINE)
    $state = [
        'icon'         => 'bi-x-circle-fill',
        'icon_color'   => '#f14668',
        'text'         => 'Daemon WireGuard OFFLINE',
        'detail'       => 'O serviço wg-mkauthd não está respondendo.',
        'box_class'    => 'notification is-danger is-light',
        'show_buttons' => false,
        'show_details' => false,
        'show_info'    => [
            ['label' => 'Serviço', 'value' => 'wg-mkauthd', 'type' => 'text'],
            ['label' => 'Status', 'value' => 'OFFLINE', 'type' => 'tag-danger'],
            ['label' => 'Socket', 'value' => $socketPath, 'type' => 'code'],
            ['label' => 'Ação', 'value' => '/etc/init.d/wg-mkauthd start', 'type' => 'code'],
            ['label' => 'Logs', 'value' => 'tail -50 /var/log/wg-mkauthd.log', 'type' => 'code'],
        ],
        'data'         => null
    ];
    
} elseif (isset($status_data['ok']) && $status_data['ok'] === false 
          && ($status_data['error'] ?? '') === 'wg_down') {

    if (!$interface_configurada) {
        // ⚠️ CENÁRIO 2A: Daemon OK, wg0.conf NÃO existe no disco
        // Primeira instalação — interface nunca foi criada
        $state = [
            'icon'         => 'bi-info-circle-fill',
            'icon_color'   => '#3298dc',
            'text'         => 'Interface WireGuard não configurada',
            'detail'       => 'Nenhuma configuração encontrada. Use o Card ao lado para criar a interface.',
            'box_class'    => 'notification is-info is-light',
            'show_buttons' => false,
            'show_details' => false,
            'show_info'    => [
                ['label' => 'Interface', 'value' => 'wg0', 'type' => 'text'],
                ['label' => 'Status', 'value' => 'NÃO CONFIGURADA', 'type' => 'tag-info'],
                ['label' => 'Arquivo', 'value' => '/etc/wireguard/wg0.conf não encontrado', 'type' => 'text'],
                ['label' => 'Ação', 'value' => 'Clique em "Ações" no card ao lado para criar', 'type' => 'text'],
            ],
            'data'         => null
        ];
    } else {
        // ⚠️ CENÁRIO 2B: Daemon OK, wg0.conf EXISTE, mas interface está DOWN
        $state = [
            'icon'         => 'bi-exclamation-circle-fill',
            'icon_color'   => '#ff9f43',
            'text'         => 'Interface WireGuard está DOWN',
            'detail'       => 'A interface wg0 não está ativa.',
            'box_class'    => 'notification is-warning is-light',
            'show_buttons' => true,
            'show_details' => false,
            'show_info'    => [
                ['label' => 'Interface', 'value' => 'wg0', 'type' => 'text'],
                ['label' => 'Status', 'value' => 'DOWN', 'type' => 'tag-warning'],
                ['label' => 'Ação', 'value' => 'Clique em "Ligar" para ativar', 'type' => 'text'],
            ],
            'data'         => null
        ];
    }
    
} elseif (empty($status_data['ok']) || empty($status_data['data'])) {
    // ❌ CENÁRIO 3: Resposta inválida do daemon
    $state = [
        'icon'         => 'bi-exclamation-triangle-fill',
        'icon_color'   => '#f14668',
        'text'         => 'Erro de comunicação',
        'detail'       => 'O serviço wg-mkauthd está rodando?',
        'box_class'    => 'notification is-danger is-light',
        'show_buttons' => false,
        'show_details' => false,
        'show_info'    => [
            ['label' => 'Erro', 'value' => 'Sem resposta do daemon wg-mkauthd', 'type' => 'text'],
            ['label' => 'Ação', 'value' => 'Iniciar o serviço / Verificar logs', 'type' => 'text'],
            ['label' => 'Iniciar Serviço', 'value' => 'service wg-mkauthd start', 'type' => 'code'],
            ['label' => 'Logs', 'value' => 'tail -50 /var/log/wg-mkauthd.log', 'type' => 'code'],
        ],
        'data'         => null
    ];
    
} else {
    // ✅ CENÁRIO 4: Daemon OK, analisar dados
    $d = $status_data['data'];
    
    if (empty($d['if_up'])) {
        // ⚠️ Interface existe mas está DOWN (COM DADOS)
        $state = [
            'icon'         => 'bi-exclamation-circle-fill',
            'icon_color'   => '#ff9f43',
            'text'         => 'Interface WireGuard está DOWN',
            'detail'       => 'A interface wg0 não está ativa.',
            'box_class'    => 'notification is-warning is-light',
            'show_buttons' => true,
            'show_details' => true,
            'show_info'    => [],
            'data'         => $d
        ];
    } else {
        // ✅ Interface UP
        $state = [
            'icon'         => 'bi-check-circle-fill',
            'icon_color'   => '#48c774',
            'text'         => 'Interface WireGuard está UP',
            'detail'       => '',
            'box_class'    => 'notification is-success is-light',
            'show_buttons' => true,
            'show_details' => true,
            'show_info'    => [],
            'data'         => $d
        ];
    }
}

// ========================================
// ESTADOS VISUAIS DO PLUG
// ========================================
$visual_states = [
    'offline' => [
        'icon_main'   => 'bi-plug-fill',
        'icon_overlay'=> 'bi-x-lg',
        'bg_gradient' => 'linear-gradient(135deg, #ffe0e0 0%, #ffcccc 100%)',
        'icon_color'  => '#e74c3c',
        'border'      => '4px solid #e74c3c',
        'title_color' => '#c0392b',
    ],
    'down' => [
        'icon_main'   => 'bi-plug-fill',
        'icon_overlay'=> 'bi-exclamation-lg',
        'bg_gradient' => 'linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%)',
        'icon_color'  => '#ff9f43',
        'border'      => '4px solid #f39c12',
        'title_color' => '#d68910',
    ],
    'up' => [
        'icon_main'   => 'bi-plug-fill',
        'icon_overlay'=> 'bi-check-lg',
        'bg_gradient' => 'linear-gradient(135deg, #d4f4dd 0%, #bfe9c9 100%)',
        'icon_color'  => '#48c774',
        'border'      => '4px solid #48c774',
        'title_color' => '#27ae60',
    ],
];

$visual_states['unconfigured'] = [
    'icon_main'   => 'bi-plug-fill',
    'icon_overlay'=> 'bi-question-lg',
    'bg_gradient' => 'linear-gradient(135deg, #d6eaf8 0%, #aed6f1 100%)',
    'icon_color'  => '#3298dc',
    'border'      => '4px solid #3298dc',
    'title_color' => '#2980b9',
];

// Selecionar estado visual do plug
if (!is_array($status_data)) {
    $vs = $visual_states['offline'];
} elseif (isset($status_data['ok']) && $status_data['ok'] === false && !$interface_configurada) {
    $vs = $visual_states['unconfigured'];
} elseif (isset($status_data['ok']) && $status_data['ok'] === false) {
    $vs = $visual_states['down'];
} elseif (!empty($status_data['ok']) && empty($status_data['data']['if_up'])) {
    $vs = $visual_states['down'];
} elseif (!empty($status_data['ok']) && !empty($status_data['data']['if_up'])) {
    $vs = $visual_states['up'];
} else {
    $vs = $visual_states['down'];
}
?>

        <!-- CARD ÚNICO COMPACTO (FLEX ATIVADO) -->
        <div style="height: 100%; display: flex; flex-direction: column; background: <?php echo $vs['bg_gradient']; ?>; 
                    border-left: <?php echo $vs['border']; ?>; 
                    border-radius: 12px; 
                    padding: 1.25rem; 
                    box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
            
            <!-- SEÇÃO SUPERIOR: Plug + Status vertical -->
            <div style="text-align: center; margin-bottom: 0.75rem;">
                <div style="position: relative; display: inline-block;">
                    <i class="<?php echo $vs['icon_main']; ?>" 
                       style="font-size: 2.5rem; color: <?php echo $vs['icon_color']; ?>; filter: drop-shadow(0 3px 6px rgba(0,0,0,0.2));"></i>
                    <?php if ($vs['icon_overlay']): ?>
                        <i class="<?php echo $vs['icon_overlay']; ?>" 
                           style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 1.25rem; color: white; text-shadow: 0 2px 4px rgba(0,0,0,0.5); font-weight: bold;"></i>
                    <?php endif; ?>
                </div>
                <h2 class="title is-6" style="margin-top: 0.25rem; margin-bottom: 0; font-size: 0.95rem; color: <?php echo $vs['title_color']; ?>;">
                    <?php echo htmlspecialchars($state['text']); ?>
                </h2>
                <?php if ($state['detail']): ?>
                    <p style="margin-top: 0.25rem; color: #666; font-size: 0.8rem;"><?php echo htmlspecialchars($state['detail']); ?></p>
                <?php endif; ?>
            </div>
            
            <!-- CONTEÚDO DINÂMICO -->
            <?php if ($state['show_details'] && $state['data']): ?>
                <?php $d = $state['data']; ?>
                <div style="background: rgba(255,255,255,0.4); border-radius: 10px; padding: 0.5rem 0.75rem; margin-bottom: 1rem;">
                    <!-- STATUS -->
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.3rem 0; border-bottom: 1px solid rgba(0,0,0,0.06);">
                        <span style="font-size: 0.85rem; font-weight: 600; color: #1e293b;">Status:</span>
                        <span class="tag <?php echo !empty($d['if_up']) ? 'is-success' : 'is-warning'; ?>" style="font-weight: 700; font-size: 0.7rem; height: 20px; padding: 0 0.5rem;">
                            <?php echo !empty($d['if_up']) ? 'UP' : 'DOWN'; ?>
                        </span>
                    </div>

                    <!-- INTERFACE -->
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.3rem 0; border-bottom: 1px solid rgba(0,0,0,0.06);">
                        <span style="font-size: 0.85rem; font-weight: 600; color: #1e293b;">Interface:</span>
                        <div style="display: flex; align-items: center; gap: 0.4rem;">
                            <span style="font-size: 0.85rem; font-family: monospace; color: #0f172a; font-weight: 700;"><?php echo htmlspecialchars($d['interface'] ?? 'wg0'); ?></span>
                            <a href="#" onclick="copiarTexto('<?php echo htmlspecialchars($d['interface'] ?? 'wg0'); ?>'); return false;" style="color: #64748b; font-size: 0.9rem;" title="Copiar"><i class="bi-clipboard"></i></a>
                        </div>
                    </div>

                    <!-- IP PÚBLICO -->
                    <?php 
                    $ip_forcado = '';
                    $rsCfg = $mysqli->query("SELECT endpoint FROM wg_ramais ORDER BY id ASC LIMIT 1");
                    if ($rsCfg && $rowCfg = $rsCfg->fetch_assoc()) {
                        $ip_forcado = trim($rowCfg['endpoint'] ?? '');
                    }
                    $ip_detectado = $d['public_ip'] ?? 'N/A';
                    $ip_mostrar = ($ip_forcado !== '') ? $ip_forcado : $ip_detectado;
                    $tag_tipo = ($ip_forcado !== '') ? '<span class="tag is-warning is-light" style="font-size: 0.6rem; padding: 0 4px; height: 16px; margin-right: 4px;">NAT Forçado</span>' : '<span class="tag is-info is-light" style="font-size: 0.6rem; padding: 0 4px; height: 16px; margin-right: 4px;">Auto</span>';
                    ?>
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.3rem 0; border-bottom: 1px solid rgba(0,0,0,0.06);">
                        <span style="font-size: 0.85rem; font-weight: 600; color: #1e293b;">IP Público:</span>
                        <div style="display: flex; align-items: center; gap: 0.4rem;">
                            <?php echo $tag_tipo; ?>
                            <span style="font-size: 0.85rem; font-family: monospace; color: #0f172a; font-weight: 700;"><?php echo htmlspecialchars($ip_mostrar); ?></span>
                            <a href="#" onclick="document.getElementById('modal_nat').classList.add('is-active'); return false;" style="color: #0ea5e9; font-size: 0.9rem;" title="Configurar IP de Borda (NAT)">
                                <i class="bi-gear-fill"></i>
                            </a>
                        </div>
                    </div>

                    <!-- PORTA -->
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.3rem 0; <?php echo !empty($d['wg_address']) ? 'border-bottom: 1px solid rgba(0,0,0,0.06);' : ''; ?>">
                        <span style="font-size: 0.85rem; font-weight: 600; color: #1e293b;">Porta:</span>
                        <div style="display: flex; align-items: center; gap: 0.4rem;">
                            <span style="font-size: 0.85rem; font-family: monospace; color: #0f172a; font-weight: 700;"><?php echo isset($d['port']) ? (int)$d['port'] : 'N/A'; ?></span>
                            <a href="#" onclick="copiarTexto('<?php echo isset($d['port']) ? (int)$d['port'] : 'N/A'; ?>'); return false;" style="color: #64748b; font-size: 0.9rem;" title="Copiar"><i class="bi-clipboard"></i></a>
                        </div>
                    </div>

                    <!-- NETWORK -->
                    <?php if (!empty($d['wg_address'])): ?>
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.3rem 0;">
                        <span style="font-size: 0.85rem; font-weight: 600; color: #1e293b;">Network:</span>
                        <div style="display: flex; align-items: center; gap: 0.4rem;">
                            <span style="font-size: 0.85rem; font-family: monospace; color: #0f172a; font-weight: 700;"><?php echo htmlspecialchars($d['wg_address']); ?></span>
                            <a href="#" onclick="copiarTexto('<?php echo htmlspecialchars($d['wg_address']); ?>'); return false;" style="color: #64748b; font-size: 0.9rem;" title="Copiar"><i class="bi-clipboard"></i></a>
                        </div>
                    </div>
                    <?php endif; ?>

                </div>
            
            <!-- INFORMAÇÕES ESTÁTICAS -->
            <?php elseif (!empty($state['show_info'])): ?>
                <div style="background: rgba(255,255,255,0.4); border-radius: 10px; padding: 0.5rem 0.75rem; margin-bottom: 1rem;">
                    <?php $total = count($state['show_info']); $i = 0; ?>
                    <?php foreach ($state['show_info'] as $info): ?>
                        <?php $i++; $is_last = ($i === $total); ?>
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.3rem 0; <?php echo !$is_last ? 'border-bottom: 1px solid rgba(0,0,0,0.06);' : ''; ?>">
                            <span style="font-size: 0.85rem; font-weight: 600; color: #1e293b;"><?php echo htmlspecialchars($info['label']); ?>:</span>
                            <div style="display: flex; align-items: center; gap: 0.4rem;">
                                <?php if ($info['type'] === 'code'): ?>
                                    <span style="font-size: 0.85rem; font-family: monospace; color: #0f172a; font-weight: 700;"><?php echo htmlspecialchars($info['value']); ?></span>
                                    <a href="#" onclick="copiarTexto('<?php echo htmlspecialchars($info['value']); ?>'); return false;" style="color: #64748b; font-size: 0.9rem;" title="Copiar"><i class="bi-clipboard"></i></a>
                                <?php elseif ($info['type'] === 'tag-danger'): ?>
                                    <span class="tag is-danger" style="font-weight: 700; font-size: 0.7rem; height: 20px; padding: 0 0.5rem;"><?php echo htmlspecialchars($info['value']); ?></span>
                                <?php elseif ($info['type'] === 'tag-warning'): ?>
                                    <span class="tag is-warning" style="font-weight: 700; font-size: 0.7rem; height: 20px; padding: 0 0.5rem;"><?php echo htmlspecialchars($info['value']); ?></span>
                                <?php else: ?>
                                    <span style="font-size: 0.85rem; color: #0f172a; font-weight: 500;"><?php echo htmlspecialchars($info['value']); ?></span>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
            
            <!-- BOTÕES -->
            <?php if ($state['show_buttons']): ?>
                <div class="buttons is-centered mt-auto" style="margin-bottom: 0;">
                    <form method="post" style="display:inline; margin: 0;">
                        <input type="hidden" name="acao" value="server-down">
                        <button class="button is-danger is-small" type="submit" style="border-radius: 8px; font-weight: 600;">
                            <span class="icon is-small"><i class="bi bi-power"></i></span><span>Desligar</span>
                        </button>
                    </form>

                    <form method="post" style="display:inline; margin: 0;">
                        <input type="hidden" name="acao" value="server-up">
                        <button class="button is-success is-small" type="submit" style="border-radius: 8px; font-weight: 600;">
                            <span class="icon is-small"><i class="bi bi-play-fill"></i></span><span>Ligar</span>
                        </button>
                    </form>
                </div>
            <?php endif; ?>
        </div>
        </div> <!-- fim da coluna 1 -->

        <!-- ========================================
             COLUNA 2: CONFIGURAÇÃO WG0 (is-4 = 33% da tela)
             ======================================== -->
        <div class="column is-4">
          
          <!-- Card 2.1: wg0.conf snapshot -->
          <div class="box" id="card_wg_conf_view" style="height: 100%; display: flex; flex-direction: column;">
            <div class="level" style="margin-bottom:0.5rem;">
              <div class="level-left">
                <div class="level-item">
                  <h2 class="title is-5" style="margin-bottom:0;">wg0.conf (snapshot)</h2>
                </div>
              </div>

              <div class="level-right">
                <div class="level-item">
                  <?php if ($daemon_ok): ?>
                    <button class="button is-small is-link" type="button"
                            onclick="document.getElementById('card_wg_conf_view').classList.add('is-hidden');
                                     document.getElementById('card_wg_conf_edit').classList.remove('is-hidden');">
                      Ações
                    </button>
                  <?php else: ?>
                    <button class="button is-small is-light" type="button" disabled>
                      <span class="icon"><i class="bi-lock"></i></span><span>Ações</span>
                    </button>
                  <?php endif; ?>
                </div>
              </div>
            </div>

            <?php if (!$daemon_ok): ?>
              <div class="notification is-danger" style="margin-bottom: 0;">
                <p class="has-text-weight-bold mb-2">
                  <span class="icon"><i class="bi bi-x-circle-fill"></i></span>
                  Daemon não está respondendo
                </p>
                <p class="mb-3">
                  Não foi possível conectar ao <code>wg-mkauthd</code> via socket.
                </p>
                <p>💡 <strong>Ação:</strong> Inicie o daemon primeiro:</p>
                <pre style="background:#fff3cd; padding:0.5rem; border-radius:4px; margin-top:0.5rem;"><code>service wg-mkauthd start</code></pre>
              </div>

            <?php elseif ($interface_configurada): ?>
              <!-- CAIXA PRETA MÁGICA -->
              <pre style="flex: 1 1 0%; min-height: 250px; overflow: auto; font-size:0.85rem; background:#111; color:#eee; padding:1rem; border-radius:8px; margin-bottom: 0;"><code><?php echo htmlspecialchars($wg_conf_raw); ?></code></pre>

            <?php else: ?>
              <div class="notification is-info" style="margin-bottom: 0;">
                <p class="has-text-weight-bold mb-2">
                  <span class="icon"><i class="bi bi-info-circle-fill"></i></span>
                  Primeira instalação
                </p>
                <p>
                  A interface <strong>wg0</strong> ainda não está configurada.
                  Clique em <strong>"Ações"</strong> para criar a interface.
                </p>
              </div>
            <?php endif; ?>
          </div> 

          <!-- Card 2.2: AÇÕES -->
          <div class="box is-hidden" id="card_wg_conf_edit" style="height: 100%; display: flex; flex-direction: column;">
            <div class="level" style="margin-bottom:0.5rem;">
              <div class="level-left">
                <div class="level-item"><h2 class="title is-5" style="margin-bottom:0;">Ações wg0</h2></div>
              </div>
              <div class="level-right">
                <div class="level-item">
                  <button class="button is-small" type="button"
                          onclick="document.getElementById('card_wg_conf_edit').classList.add('is-hidden');
                                   document.getElementById('card_wg_conf_view').classList.remove('is-hidden');">
                    Cancelar
                  </button>
                </div>
              </div>
            </div>

            <?php if (!$daemon_ok): ?>
              <div class="notification is-danger" style="margin-bottom: 0;">
                <button class="delete" onclick="location.reload()"></button>
                <p class="is-size-5 has-text-weight-bold mb-3">
                  <span class="icon"><i class="bi bi-x-circle-fill"></i></span>
                  Daemon não está respondendo
                </p>
                <p class="mb-3">
                  O daemon <code>wg-mkauthd</code> não está em execução ou não está acessível via socket.
                </p>
                <p class="mb-3">Inicie o daemon antes de configurar o WireGuard.</p>
                <div class="buttons mt-auto mb-0">
                  <button class="button is-danger is-light" type="button"
                          onclick="document.getElementById('card_wg_conf_edit').classList.add('is-hidden');
                                   document.getElementById('card_wg_conf_view').classList.remove('is-hidden');">
                    <span class="icon"><i class="bi bi-x-lg"></i></span>
                    <span>Fechar</span>
                  </button>
                </div>
              </div>

            <?php elseif (!$interface_configurada): ?>
              <div class="notification is-info">
                <p class="is-size-5 has-text-weight-bold mb-3">
                  <span class="icon"><i class="bi bi-info-circle-fill"></i></span>
                  Primeira instalação
                </p>
                <p class="mb-3">
                  A interface <strong>wg0</strong> ainda não está configurada.
                  Clique em <strong>"Criar"</strong> para gerar a chave do servidor,
                  criar o <code>wg0.conf</code> do zero e iniciar o WireGuard.
                </p>
              </div>

              <form method="post" action="?tab=status" style="display: flex; flex-direction: column; flex-grow: 1;" onsubmit="return confirm('Criar interface wg0 com essa rede/porta?');">
                <input type="hidden" name="acao" value="create_server">
                
                <div class="field">
                  <label class="label">Endereço da Interface (Address)</label>
                  <div class="control is-flex" style="gap:.5rem; flex-wrap:wrap;">
                    <input class="input" style="max-width:260px;" type="text" name="wg_network_v4" value="10.66.66.1/24" required>
                    <button class="button is-small is-info" type="button" onclick="wgRandomPrivate24();" style="height: 40px;">
                      <span class="icon"><i class="bi-shuffle"></i></span>
                      <span>Random /24</span>
                    </button>
                  </div>
                  <p class="help">
                    Endereço IPv4/CIDR da interface wg0 (primeiro host da rede).
                    Ex.: <code>10.50.0.1/24</code>, <code>172.20.10.1/24</code>, <code>192.168.77.1/24</code>
                  </p>
                </div>

                <div class="field">
                  <label class="label">Porta de escuta (ListenPort)</label>
                  <div class="control">
                    <input class="input" type="number" name="wg_port" min="1" max="65535" value="51820" required>
                  </div>
                  <p class="help">Porta UDP para escutar conexões WireGuard (padrão: 51820)</p>
                </div>

                <div class="field mt-auto mb-0">
                  <div class="control">
                    <button class="button is-success is-fullwidth" type="submit">
                      <span class="icon"><i class="bi-plus-circle-fill"></i></span>
                      <span>Criar interface wg0</span>
                    </button>
                  </div>
                </div>
              </form>

            <?php else: ?>
              <div class="notification is-warning">
                <p class="is-size-5 has-text-weight-bold mb-3">
                  <span class="icon"><i class="bi bi-exclamation-triangle-fill"></i></span>
                  RESET DO SERVIDOR WIREGUARD
                </p>
                <p class="mb-3">Esta ação irá:</p>
                <ul>
                  <li><strong>Gerar nova keypair</strong> do servidor</li>
                  <li><strong>Recriar wg0.conf</strong> com os novos parâmetros</li>
                  <li><strong>ZERAR todos os peers</strong> da tabela <code>wg_ramais</code></li>
                </ul>
                <p class="has-text-danger has-text-weight-bold mt-3">
                  ⚠️ Operação irreversível!
                </p>
              </div>

        	  <form method="post" action="?tab=status" style="display: flex; flex-direction: column; flex-grow: 1;" onsubmit="return confirmReset();">
                <input type="hidden" name="acao" value="reset_server">
                
                <div class="field">
                  <label class="label">Nova Rede da Interface (Address)</label>
                  <div class="control is-flex" style="gap:.5rem; flex-wrap:wrap;">
                    <input class="input" style="max-width:260px;" type="text" name="wg_network_v4_reset" value="<?php echo htmlspecialchars($current_network ?: '10.66.66.1/24'); ?>" required>
                    <button class="button is-small is-info" type="button" onclick="wgRandomPrivate24();" style="height: 40px;">
                      <span class="icon"><i class="bi-shuffle"></i></span>
                      <span>Random /24</span>
                    </button>
                  </div>
                </div>

                <div class="field">
                  <label class="label">Nova Porta</label>
                  <div class="control">
                    <input class="input" type="number" name="wg_port_reset" min="1" max="65535" value="<?php echo $current_port ?: 51820; ?>" required>
                  </div>
                </div>

                <div class="field mt-auto mb-0">
                  <div class="control">
                    <button class="button is-warning is-fullwidth" type="submit">
                      <span class="icon"><i class="bi-arrow-clockwise"></i></span>
                      <span>Resetar servidor WireGuard</span>
                    </button>
                  </div>
                </div>
              </form>
            <?php endif; ?>
          </div> 
        </div> <!-- fim da coluna 2 -->

        <!-- ========================================
             COLUNA 3: BACKUPS (is-5 = 42% da tela)
             ======================================== -->
        <div class="column is-5">
          <div class="box" style="height: 100%; display: flex; flex-direction: column;">
            <h2 class="title is-5">
                <span class="icon"><i class="bi bi-clock-history"></i></span>
                <span>Backup & Restore</span>
            </h2>
<?php
// Garante que $snapshots exista para os modais (que ficam fora deste bloco)
if (!isset($snapshots)) {
	$snapshots = [];
}
?>
<?php if (!$daemon_ok): ?>
            <div class="notification is-danger is-light mb-0">
                <p class="has-text-weight-bold mb-2">
                    <span class="icon"><i class="bi bi-x-circle-fill"></i></span>
                    Backups indisponíveis
                </p>
                <p>
                    O daemon <code>wg-mkauthd</code> não está respondendo.
                    Inicie o serviço para acessar backups e restauração.
                </p>
            </div>

<?php elseif (!$interface_configurada): ?>
            <div style="background: linear-gradient(135deg, #d6eaf8 0%, #aed6f1 100%); border-left: 4px solid #3298dc; border-radius: 8px; padding: 1.5rem; box-shadow: 0 4px 12px rgba(0,0,0,0.1); flex-grow: 1; display: flex; flex-direction: column;">
                
                <div style="text-align: center; margin-bottom: 1rem;">
                    <div style="position: relative; display: inline-block;">
                        <i class="bi bi-cloud-upload" style="font-size: 3rem; color: #3298dc; filter: drop-shadow(0 3px 6px rgba(0,0,0,0.15));"></i>
                    </div>
                    <h3 class="title is-5 has-text-info" style="margin-top: 0.5rem; margin-bottom: 0;">Restaurar de Backup</h3>
                </div>

                <div class="content" style="font-size: 0.9rem;">
                    <p>
                        Nenhuma interface WireGuard configurada.
                        Se você possui um <strong>snapshot <code>.json</code></strong>
                        exportado anteriormente pelo sistema, importe-o aqui para
                        restaurar <strong>tudo de uma só vez</strong>:
                    </p>
                    <ul style="margin-top: 0.5rem;">
                        <li>Interface WireGuard (<code>wg0.conf</code>)</li>
                        <li>Banco de dados completo (peers, nomes, IPs, configs)</li>
                        <li>Chaves, AllowedIPs, PresharedKeys</li>
                    </ul>
                </div>

                <form method="post" action="?tab=status" enctype="multipart/form-data" class="mt-auto" onsubmit="return confirmImportBackup();">
                    <input type="hidden" name="acao" value="import_backup_file">
                    <div class="field">
                        <div class="file has-name is-info is-fullwidth">
                            <label class="file-label">
                                <input class="file-input" type="file" name="backup_conf" accept=".json" required
                                       onchange="this.closest('.file').querySelector('.file-name').textContent = this.files[0]?.name || 'Nenhum arquivo';">
                                <span class="file-cta">
                                    <span class="file-icon"><i class="bi bi-folder2-open"></i></span>
                                    <span class="file-label">Escolher .json</span>
                                </span>
                                <span class="file-name" style="background:#fff;">Nenhum arquivo</span>
                            </label>
                        </div>
                    </div>
                    <div class="field mb-0">
                        <button class="button is-info is-fullwidth" type="submit">
                            <span class="icon"><i class="bi bi-arrow-counterclockwise"></i></span>
                            <span>Importar e Restaurar Tudo</span>
                        </button>
                    </div>
                </form>

                <article class="message is-info is-small" style="margin-top: 1rem; margin-bottom: 0;">
                    <div class="message-body" style="padding: 0.75rem;">
                        <strong>💡 Não tem backup?</strong><br>
                        Use o card ao lado (<strong>Ações</strong>) para criar uma interface do zero.
                        O sistema fará snapshots automáticos a cada operação.
                    </div>
                </article>
            </div>

<?php else: ?>
            <?php
            // Lê snapshots do interface_text (FIFO de 5)
            $snapshots = [];
            if (!$erro_db) {
                $rs = $mysqli->query("SELECT interface_text FROM wg_ramais WHERE interface_text IS NOT NULL AND interface_text != '' LIMIT 1");
                if ($rs && ($rowSnap = $rs->fetch_assoc()) && !empty($rowSnap['interface_text'])) {
                    $snapshots = json_decode($rowSnap['interface_text'], true) ?: [];
                }
            }
            ?>

            <!-- BARRA DE FERRAMENTAS -->
            <div class="is-flex is-justify-content-space-between is-align-items-center mb-3">
                <p class="help mb-0" style="font-size: 0.85rem;">
                    Últimos <strong><?php echo count($snapshots); ?></strong> de 5 snapshots.
                </p>
                <div class="buttons are-small mb-0">
                    <form method="post" action="?tab=status" style="display:inline; margin-right: 0.5rem;" onsubmit="return confirm('Criar um snapshot do estado atual agora?');">
                        <input type="hidden" name="acao" value="create_snapshot">
                        <button class="button is-success is-light" type="submit" title="Salvar estado atual">
                            <span class="icon"><i class="bi bi-camera"></i></span><span style="font-weight: 600;">Criar</span>
                        </button>
                    </form>
                    <button class="button is-link is-light" type="button" title="Restaurar de um arquivo .json"
                            onclick="document.getElementById('view_backup_list').classList.add('is-hidden'); 
                                     document.getElementById('view_backup_import').classList.remove('is-hidden');">
                        <span class="icon"><i class="bi bi-upload"></i></span><span style="font-weight: 600;">Importar</span>
                    </button>
                </div>
            </div>

            <!-- TELA 1: IMPORTAÇÃO -->
            <div id="view_backup_import" class="is-hidden" style="animation: fadeIn 0.3s ease; height: 100%;">
                <div class="notification is-info is-light" style="border-radius: 8px; padding: 1.25rem; height: 100%; display: flex; flex-direction: column; margin-bottom: 0;">
                    <div class="is-flex is-justify-content-space-between is-align-items-center mb-2">
                        <strong style="color: #0284c7;"><i class="bi bi-folder2-open mr-1"></i> Importar snapshot (.json)</strong>
                        <button class="delete is-small" type="button" 
                                onclick="document.getElementById('view_backup_import').classList.add('is-hidden'); 
                                         document.getElementById('view_backup_list').classList.remove('is-hidden');"></button>
                    </div>
                    
                    <p style="font-size:0.85rem; margin-bottom: 1rem; color: #0c4a6e;">
                        Restaura a interface wg0 <strong>e</strong> o banco de dados (peers, configs) de uma só vez.<br>
                        <span class="has-text-danger mt-1 is-block">⚠️ Apenas arquivos <code>.json</code> são aceitos.</span>
                    </p>

                    <form method="post" action="?tab=status" enctype="multipart/form-data" class="mt-auto" style="display: flex; flex-direction: column;" onsubmit="return confirmImportBackup();">
                        <input type="hidden" name="acao" value="import_backup_file">
                        <div class="field">
                            <div class="file has-name is-small is-fullwidth is-info">
                                <label class="file-label">
                                    <input class="file-input" type="file" name="backup_conf" accept=".json" required
                                           onchange="this.closest('.file').querySelector('.file-name').textContent = this.files[0]?.name || 'Nenhum arquivo';">
                                    <span class="file-cta">
                                        <span class="file-icon"><i class="bi bi-search"></i></span>
                                        <span class="file-label">Procurar .json</span>
                                    </span>
                                    <span class="file-name" style="background: #fff;">Nenhum arquivo</span>
                                </label>
                            </div>
                        </div>
                        <div class="buttons is-right mt-3 mb-0">
                            <button class="button is-small" type="button" style="border-radius: 6px;"
                                    onclick="document.getElementById('view_backup_import').classList.add('is-hidden'); 
                                             document.getElementById('view_backup_list').classList.remove('is-hidden');">Cancelar</button>
                            <button class="button is-warning is-small" type="submit" style="border-radius: 6px; font-weight: 600;">
                                <span class="icon"><i class="bi bi-cloud-upload"></i></span><span>Restaurar</span>
                            </button>
                        </div>
                    </form>
                </div>
            </div>

            <!-- TELA 2: LISTA DE BACKUPS -->
            <div id="view_backup_list" style="animation: fadeIn 0.3s ease; display: flex; flex-direction: column; flex-grow: 1;">
                <?php if (empty($snapshots)): ?>
                    <div class="notification is-warning is-light mb-0" style="border-radius: 8px;">
                        <span class="icon"><i class="bi bi-exclamation-triangle"></i></span>
                        <span>Nenhum snapshot disponível.</span>
                        <p class="mt-2" style="font-size:0.85rem;">
                            Snapshots são criados automaticamente antes de cada operação ou manualmente pelo botão "Criar" acima.
                        </p>
                    </div>
                <?php else: ?>
                    <?php
                    if (!function_exists('formataDataRelativa')) {
                        function formataDataRelativa($dataString) {
                            if (empty($dataString)) return '-';
                            $ts = strtotime($dataString);
                            if (!$ts) return htmlspecialchars($dataString);
                            $hoje = strtotime('today'); $ontem = strtotime('yesterday'); $data_dia = strtotime(date('Y-m-d', $ts)); $hora = date('H:i', $ts);
                            if ($data_dia == $hoje) return "<strong style='color: #0ea5e9;'>Hoje</strong> às {$hora}";
                            elseif ($data_dia == $ontem) return "Ontem às {$hora}";
                            else return date('d/m/Y H:i', $ts);
                        }
                    }
                    ?>
					<div class="table-container" style="flex: 1 1 auto; max-height: 235px; overflow-y: auto; border: 1px solid #bae6fd; border-radius: 8px; background: #ffffff; margin-bottom: 0;">
                        <table class="table is-fullwidth is-narrow is-hoverable" style="font-size:0.85rem; margin-bottom: 0; background: transparent;">
                            <thead style="position: sticky; top: 0; z-index: 10; background: #f0f9ff; box-shadow: 0 2px 4px rgba(14, 165, 233, 0.08);">
                                <tr>
                                    <th style="border-bottom: none; color: #0284c7; padding-left: 1rem;">Data/Hora</th>
                                    <th style="border-bottom: none; color: #0284c7;">Motivo</th>
                                    <th style="border-bottom: none; color: #0284c7; text-align: center;">Peers</th>
                                    <th style="border-bottom: none; color: #0284c7; text-align: right; padding-right: 1rem;">Ações</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($snapshots as $i => $snap): ?>
                                <?php $is_latest = ($i === 0); $row_bg = $is_latest ? 'background-color: #f0fdfa;' : ''; ?>
                                <tr style="<?= $row_bg ?>">
                                    <td style="vertical-align: middle; white-space: nowrap; padding-left: 1rem;">
                                        <?= formataDataRelativa($snap['at'] ?? '') ?>
                                        <?php if ($is_latest): ?><span class="tag is-success is-light is-rounded ml-1" style="font-size: 0.6rem; height: 18px; font-weight: 700;">ATUAL</span><?php endif; ?>
                                    </td>
                                    <td style="vertical-align: middle; color: #475569;"><span style="<?= $is_latest ? 'font-weight: 600;' : '' ?>"><?= htmlspecialchars($snap['reason'] ?? '') ?></span></td>
                                    <td style="vertical-align: middle; text-align: center; font-weight: 600;"><?= (int)($snap['peers'] ?? 0) ?></td>
                                    <td style="vertical-align: middle; text-align: right; white-space: nowrap; padding-right: 1rem;">
                                        <form method="post" style="display:inline">
                                            <input type="hidden" name="acao" value="download_snapshot"><input type="hidden" name="snapshot_index" value="<?= $i ?>">
                                            <button class="button is-small is-info is-light" type="submit" title="Baixar .json" style="padding: 0.2rem 0.5rem; height: 28px; border-radius: 6px;"><span class="icon is-small"><i class="bi bi-download"></i></span></button>
                                        </form>
                                        <?php if (!empty($snap['sql'])): ?>
                                        <form method="post" style="display:inline" onsubmit="return confirm('⚠️ RESTAURAR backup de <?= htmlspecialchars($snap['at'] ?? '') ?>?\n\nIsso vai:\n• Substituir o wg0.conf\n• Limpar o banco e recriar <?= (int)($snap['peers'] ?? 0) ?> peers\n\nContinuar?')">
                                            <input type="hidden" name="acao" value="restore_snapshot"><input type="hidden" name="snapshot_index" value="<?= $i ?>">
                                            <button class="button is-small is-warning" type="submit" title="Restaurar Backup" style="padding: 0.2rem 0.5rem; height: 28px; border-radius: 6px; margin-left: 0.2rem;"><span class="icon is-small"><i class="bi bi-arrow-counterclockwise"></i></span></button>
                                        </form>
                                        <?php else: ?>
                                        <button class="button is-small is-warning" disabled title="Sem dump SQL" style="padding: 0.2rem 0.5rem; height: 28px; border-radius: 6px; margin-left: 0.2rem; opacity: 0.4;"><span class="icon is-small"><i class="bi bi-arrow-counterclockwise"></i></span></button>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
<?php endif; ?>
          </div>
        </div> <!-- fim da coluna 3 -->

    </div> <!-- fim do div columns principal -->
</div> <!-- fim do div box principal -->

<!-- ========================================
     MODAIS DOS SNAPSHOTS (fora da coluna)
     ======================================== -->
<?php foreach ($snapshots as $i => $snap): ?>
<div class="modal" id="snap_modal_<?php echo $i; ?>">
    <div class="modal-background" onclick="document.getElementById('snap_modal_<?php echo $i; ?>').classList.remove('is-active');"></div>
    <div class="modal-content" style="max-width:700px;">
        <div class="box">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.75rem;">
                <h3 class="title is-5" style="margin-bottom:0;">Snapshot #<?php echo $i + 1; ?> — <?php echo htmlspecialchars($snap['at'] ?? ''); ?></h3>
                <button class="delete" aria-label="close" onclick="document.getElementById('snap_modal_<?php echo $i; ?>').classList.remove('is-active');"></button>
            </div>
            <div class="field">
                <label class="label is-small">
                    Motivo: <span class="tag is-info is-light"><?php echo htmlspecialchars($snap['reason'] ?? '—'); ?></span> &bull;
                    Peers: <span class="tag is-link"><?php echo (int)($snap['peers'] ?? substr_count($snap['conf'] ?? '', '[Peer]')); ?></span>
                </label>
            </div>
            <textarea class="textarea" id="snap_textarea_<?php echo $i; ?>" rows="15" readonly style="font-family:monospace; font-size:0.85rem; background:#111; color:#eee;"><?php echo htmlspecialchars($snap['conf'] ?? ''); ?></textarea>
            <div class="buttons mt-3">
                <button class="button is-link" type="button" onclick="var t=document.getElementById('snap_textarea_<?php echo $i; ?>'); t.select(); document.execCommand('copy'); alert('Copiado!');">
                    <span class="icon"><i class="bi bi-clipboard"></i></span><span>Copiar</span>
                </button>
                <button class="button" type="button" onclick="document.getElementById('snap_modal_<?php echo $i; ?>').classList.remove('is-active');">Fechar</button>
            </div>
        </div>
    </div>
</div>
<?php endforeach; ?>

</div>
<?php elseif ($tab === 'peers'): ?>

	<?php
	// HELPER: Formatar a data de forma amigável (Visual apenas, não afeta o banco)
	if (!function_exists('formataDataRelativa')) {
		function formataDataRelativa($dataString) {
			if (empty($dataString)) return '-';
			$ts = strtotime($dataString);
			if (!$ts) return htmlspecialchars($dataString); // Fallback

			$hoje = strtotime('today');
			$ontem = strtotime('yesterday');
			$data_dia = strtotime(date('Y-m-d', $ts));
			$hora = date('H:i', $ts);

			if ($data_dia == $hoje) {
				return "<strong style='color: #0ea5e9;'>Hoje</strong> às {$hora}";
			} elseif ($data_dia == $ontem) {
				return "Ontem às {$hora}";
			} else {
				return date('d/m/Y H:i', $ts);
			}
		}
	}

	// HELPER: Converter Bytes para KB, MB, GB (Human-like)
	if (!function_exists('humanBytes')) {
		function humanBytes($bytes, $precision = 2) {
			$bytes = (float) $bytes;
			if ($bytes <= 0) return '<span class="has-text-grey-light">0 B</span>';
			$units = array('B', 'KB', 'MB', 'GB', 'TB');
			$pow = floor(log($bytes) / log(1024));
			$pow = min($pow, count($units) - 1);
			$bytes /= pow(1024, $pow);
			return round($bytes, $precision) . ' ' . $units[$pow];
		}
	}
	?>

	<div class="box">
		<h2 class="title is-4">Peers WireGuard</h2>

		<?php
		$clients = [];
		if (
			is_array($list_clients_data)
			&& !empty($list_clients_data['ok'])
			&& isset($list_clients_data['data']['clients'])
			&& is_array($list_clients_data['data']['clients'])
		) {
			$clients = $list_clients_data['data']['clients'];
		}

		$mapRamaisByPub = [];
		foreach ($wg_ramais_rows as $r) {
			if (!empty($r['public_key'])) {
				$mapRamaisByPub[$r['public_key']] = $r;
			}
		}
		
		// --- NOVO: BUSCA OS IPs ATUAIS DO SISTEMA MK-AUTH ---
		$query_nas = $mysqli->query("SELECT id, nasname FROM nas");
		$mapNasIP = [];
		if ($query_nas) {
			while ($row_nas = $query_nas->fetch_assoc()) {
				$mapNasIP[$row_nas['id']] = trim($row_nas['nasname']);
			}
		}
		?>

		<!-- Filtro -->
		<form method="get" class="field is-grouped" style="margin-bottom: 1.5rem;">
			<input type="hidden" name="tab" value="peers">

			<div class="control">
				<input class="input" type="text" name="search"
					   placeholder="Buscar por nome ou IP"
					   value="<?php echo htmlspecialchars($search); ?>">
			</div>

			<div class="control">
				<div class="select">
					<select name="status">
						<option value="">Status (todos)</option>
						<option value="enabled"  <?php echo $status_filt==='enabled'  ? 'selected' : ''; ?>>enabled</option>
						<option value="disabled" <?php echo $status_filt==='disabled' ? 'selected' : ''; ?>>disabled</option>
					</select>
				</div>
			</div>

			<div class="control">
				<div class="select">
					<select name="per_page">
						<option value="10" <?php echo $per_page==10 ? 'selected' : ''; ?>>10</option>
						<option value="20" <?php echo $per_page==20 ? 'selected' : ''; ?>>20</option>
						<option value="50" <?php echo $per_page==50 ? 'selected' : ''; ?>>50</option>
					</select>
				</div>
			</div>

			<div class="control">
				<button class="button is-dark" type="submit">Filtrar</button>
			</div>
		</form>

		<!-- Modais invisíveis -->
		<form method="post" action="?tab=peers" id="form_modal_conf" style="display:none;">
		  <input type="hidden" name="acao_modal" value="show_conf">
		  <input type="hidden" name="id_peer" id="modal_conf_id" value="">
		</form>

		<form method="post" action="?tab=peers" id="form_modal_rsc" style="display:none;">
		  <input type="hidden" name="acao_modal" value="show_rsc">
		  <input type="hidden" name="id_peer" id="modal_rsc_id" value="">
		</form>

		<form method="post" action="?tab=peers" id="form_modal_wgstring" style="display:none;">
		  <input type="hidden" name="acao_modal" value="show_wgstring">
		  <input type="hidden" name="id_peer" id="modal_wgstring_id" value="">
		</form>

		<!-- Tabela Principal -->
		<form method="post" action="?tab=peers" id="form_peers">
			<input type="hidden" name="acao" id="acao_peers" value="bulk_peers">
			<input type="hidden" name="subacao" id="subacao_peers" value="">

			<table class="table is-striped is-fullwidth">
				<thead>
					<tr>
						<th style="width:1%;">
							<input type="checkbox" id="check_all_peers" onclick="toggleAllPeers(this)">
						</th>
						<th>Nome</th>
						<th>IP WireGuard</th>
						<th>Status do Túnel</th>
						<th>Endpoint</th>
						<th>Último Handshake</th>
						<th>Rx</th>
						<th>Tx</th>
						<th>Status do Peer</th>
						<th>Ações</th>
					</tr>
				</thead>
				<tbody>
				<?php if (!$clients): ?>
					<tr>
						<td colspan="11" class="has-text-centered has-text-grey" style="padding: 2rem;">
							Nenhum peer retornado pelo socket.
						</td>
					</tr>
				<?php else: ?>
					<?php foreach ($clients as $c): ?>
						<?php
						$pub   = $c['publicKey'] ?? '';
						$linha = $mapRamaisByPub[$pub] ?? null;
						
						// --- LÓGICA DE COMPARAÇÃO DE IP (MAQUETE) ---
						$is_maquete = false;
						if ($linha && !empty($linha['id_nas'])) {
							$id_nas_atual = $linha['id_nas'];
							$ip_wg_limpo = explode('/', $linha['ip_wg'])[0]; // tira o /32
							$ip_mk_atual = $mapNasIP[$id_nas_atual] ?? '';
							
							if ($ip_wg_limpo !== $ip_mk_atual && $ip_mk_atual !== '') {
								$is_maquete = true;
							}
						}
						
						// --- LÓGICA DE ONLINE INICIAL (3 Minutos) ---
						$is_online = false;
						$dt_handshake = !empty($c['latestHandshakeAt']) ? $c['latestHandshakeAt'] : ($linha['latest_handshake_at'] ?? '');
						
						if (!empty($dt_handshake)) {
							$tempo_passado = time() - strtotime($dt_handshake);
							if ($tempo_passado < 180) { // 180 segundos = 3 min
								$is_online = true;
							}
						}
						?>
						
						<!-- 🎯 ÂNCORA 1: TR recebe a classe 'wg-peer-row' e 'data-pubkey' pro JS achar a linha exata -->
						<tr class="wg-peer-row" data-pubkey="<?php echo htmlspecialchars($pub); ?>">
							
							<td class="is-vcentered">
								<?php if ($linha): ?>
									<input type="checkbox"
										   name="peer_ids[]"
										   value="<?php echo (int)$linha['id']; ?>"
										   class="peer-checkbox">
								<?php endif; ?>
							</td>
							<td class="is-vcentered"><strong><?php echo $linha ? htmlspecialchars($linha['peer_name']) : '-'; ?></strong></td>
							<td class="is-vcentered">
							<?php if ($linha): ?>
								<input class="input ip-input"
									   style="width: 100%; min-width: 140px; height: 28px; font-size: 0.85rem; padding-left: 8px;"
									   type="text"
									   name="address_inline[<?php echo (int)$linha['id']; ?>]"
									   value="<?php echo htmlspecialchars($linha['ip_wg']); ?>"
									   readonly>
							<?php else: ?>
								-
							<?php endif; ?>
							</td>
							
							<!-- 🎯 ÂNCORA 2: STATUS DO TÚNEL - Span ganha 'wg-btn-status' -->
							<td class="is-vcentered" style="white-space: nowrap;">
								<?php if ($linha && !empty($linha['id_nas'])): ?>
									<?php if ($is_maquete): ?>
										<span class="tag wg-btn-status <?php echo $is_online ? 'status-online-glow' : ''; ?>" 
											  title="O IP no cadastro do RAMAL ainda é o antigo e deve ser atualizado, faça isso usando as setas após o termino da integração e vizualiar o handshake do túnel." 
											  style="background-color: #ffedd5; color: #c2410c; border: 1px solid #fb923c; font-weight: 600;">
											<i class="bi bi-diagram-2 mr-1"></i> Em Paralelo
										</span>
									<?php else: ?>
										<span class="tag wg-btn-status <?php echo $is_online ? 'status-online-glow' : ''; ?>" style="background-color: #4ade80; color: #000000; border: 1px solid #22c55e; font-weight: 600;" title="Este IP já é o principal no MK-Auth">
											<i class="bi bi-check-circle-fill mr-1"></i> Operacional
										</span>
									<?php endif; ?>
								<?php else: ?>
									<span class="has-text-grey-light">-</span>
								<?php endif; ?>
							</td>

							<td class="is-vcentered">
								<?php if (!empty($c['endpoint'])): ?>
									<code style="background-color: #f1f5f9; color: #475569; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; border: 1px solid #e2e8f0; white-space: nowrap;">
										<?php echo htmlspecialchars($c['endpoint']); ?>
									</code>
								<?php else: ?>
									<span style="color: #94a3b8;">-</span>
								<?php endif; ?>
							</td>
							
							<!-- 🎯 ÂNCORA 3: ÚLTIMO HANDSHAKE - Mãozinha + Data + Raiozinho -->
							<td class="is-vcentered" style="font-size:0.85rem; color:#475569; white-space: nowrap;">
								<?php if (!empty($dt_handshake)): ?>
									<?php if ($is_online): ?>
										<!-- Mãozinha Azul (Esquerda) -->
										<i class="fa fa-handshake-o mr-1" style="color: #0ea5e9; font-size: 0.95rem;" title="Handshake estabelecido"></i>
										
										<!-- Texto da Data (Centro) -->
										<span><?php echo formataDataRelativa($dt_handshake); ?></span>
										
										<!-- Raiozinho Pulsante Verde (Direita) -->
										<i class="bi bi-activity wg-icon-handshake icon-online ml-2" title="Túnel Ativo e Comunicando!"></i>
									<?php else: ?>
										<!-- Mãozinha Cinza (Esquerda) -->
										<i class="fa fa-handshake-o has-text-grey-light mr-1" style="font-size: 0.95rem;"></i>
										
										<!-- Texto da Data (Centro) -->
										<span class="has-text-grey-light"><?php echo formataDataRelativa($dt_handshake); ?></span>
										
										<!-- Raiozinho Cinza e Parado (Direita) -->
										<i class="bi bi-activity wg-icon-handshake has-text-grey-light ml-2" title="Túnel Parado"></i>
									<?php endif; ?>
								<?php else: ?>
									<span class="has-text-grey-light">-</span>
								<?php endif; ?>
							</td>
														
							<!-- 🎯 ÂNCORA 4: RX (Download) - Ganha 'wg-rx-cell', 'data-bytes' e '.texto-bytes' -->
							<td class="is-vcentered has-text-right" style="white-space: nowrap;">
								<span class="tag is-light is-info wg-rx-cell" data-bytes="<?php echo (int)$c['transferRx']; ?>" style="font-family: 'Consolas', monospace; font-weight: 600; min-width: 90px; justify-content: flex-end;">
									<i class="bi bi-arrow-down mr-1"></i> <span class="texto-bytes"><?php echo humanBytes((int)$c['transferRx']); ?></span>
								</span>
							</td>

							<!-- 🎯 ÂNCORA 5: TX (Upload) - Ganha 'wg-tx-cell', 'data-bytes' e '.texto-bytes' -->
							<td class="is-vcentered has-text-right" style="white-space: nowrap;">
								<span class="tag is-light is-warning wg-tx-cell" data-bytes="<?php echo (int)$c['transferTx']; ?>" style="font-family: 'Consolas', monospace; font-weight: 600; min-width: 90px; justify-content: flex-end;">
									<i class="bi bi-arrow-up mr-1"></i> <span class="texto-bytes"><?php echo humanBytes((int)$c['transferTx']); ?></span>
								</span>
							</td>
							
							<!-- STATUS DO PEER (VPN) -->
							<td class="is-vcentered">
								<?php if ($linha): ?>
									<?php if ($linha['status'] === 'enabled'): ?>
										<span class="tag is-success is-light" style="font-weight: 700; font-size: 0.7rem; height: 20px;">enabled</span>
									<?php else: ?>
										<span class="tag is-danger is-light" style="font-weight: 700; font-size: 0.7rem; height: 20px;">disabled</span>
									<?php endif; ?>
								<?php else: ?>
									<span class="has-text-grey-light">-</span>
								<?php endif; ?>
							</td>

							<!-- AÇÕES -->
							<td class="is-vcentered" style="white-space: nowrap;">
							  <?php if ($linha && !empty($linha['config_text'])): ?>
								
								<!-- 1. BOTÃO .RSC (Sempre visível e seguro) -->
								<div style="display: inline-flex; background: #f0f9ff; border-radius: 6px; border: 1px solid #e0f2fe; margin-right: 0.25rem; overflow: hidden;">
									<a href="?tab=peers&acao=download_rsc&id=<?php echo (int)$linha['id']; ?>" style="padding: 0.2rem 0.5rem; color: #0284c7; font-weight: 600; font-size: 0.75rem; text-decoration: none; border-right: 1px solid #e0f2fe; background: #f0f9ff;" title="Baixar Script Inteligente">.rsc</a>
									<a href="#" onclick="abrirRscModal(<?php echo (int)$linha['id']; ?>); return false;" style="padding: 0.2rem 0.4rem; color: #0ea5e9; background: #f0f9ff; display: flex; align-items: center;" title="Ver Script Inteligente"><i class="bi-files"></i></a>
								</div>

									<!-- 2. BOTÃO GATILHO DO SUSTO -->
									<button type="button" id="btn_nativas_<?php echo (int)$linha['id']; ?>" class="button is-small is-warning is-light wg-btn-perigo" style="border-radius: 6px; font-weight: bold; border: 1px solid #fcd34d; height: 26px; padding: 0 8px; vertical-align: bottom; margin-right: 0.25rem;" onclick="revelarPerigo(<?php echo (int)$linha['id']; ?>)" title="Mostrar funções nativas">
										⚠️ WG Import
									</button>

								<!-- 3. CONTAINER ESCONDIDO DOS BOTÕES PERIGOSOS (.conf e wg-string) -->
								<div id="botoes_perigo_<?php echo (int)$linha['id']; ?>" style="display: none; vertical-align: bottom;">
									
									<!-- Botão .conf (Com tom avermelhado) -->
									<div style="display: inline-flex; background: #fff1f2; border-radius: 6px; border: 1px solid #ffe4e6; margin-right: 0.25rem; overflow: hidden;">
										<a href="?tab=peers&acao=download_conf&id=<?php echo (int)$linha['id']; ?>" style="padding: 0.2rem 0.5rem; color: #e11d48; font-weight: 600; font-size: 0.75rem; text-decoration: none; border-right: 1px solid #ffe4e6; background: #fff1f2;" title="Aviso: Usar fora do sistema requer atenção">.conf</a>
										<a href="#" onclick="abrirConfModal(<?php echo (int)$linha['id']; ?>); return false;" style="padding: 0.2rem 0.4rem; color: #f43f5e; background: #fff1f2; display: flex; align-items: center;" title="Ver .conf"><i class="bi-files"></i></a>
									</div>

									<!-- Botão wg-string (Com tom avermelhado) -->
									<div style="display: inline-flex; background: #fff1f2; border-radius: 6px; border: 1px solid #ffe4e6; overflow: hidden;">
										<a href="?tab=peers&acao=download_wgstring&id=<?php echo (int)$linha['id']; ?>" style="padding: 0.2rem 0.5rem; color: #e11d48; font-weight: 600; font-size: 0.75rem; text-decoration: none; border-right: 1px solid #ffe4e6; background: #fff1f2;" title="Aviso: wg-import nativo é falho">wgimport</a>
										<a href="#" onclick="abrirWgStringModal(<?php echo (int)$linha['id']; ?>); return false;" style="padding: 0.2rem 0.4rem; color: #f43f5e; background: #fff1f2; display: flex; align-items: center;" title="Ver wgimport"><i class="bi-files"></i></a>
									</div>

								</div>

							  <?php else: ?>
								<span class="has-text-grey-light">-</span>
							  <?php endif; ?>
							</td>
						</tr>
					<?php endforeach; ?>
				<?php endif; ?>
				</tbody>
			</table>

			<!-- Barra de ações em massa -->
			<div class="block" id="acao_selecao_peers" style="margin-top: 1.5rem;">
			  <nav class="level is-mobile">
				<div class="level-left" style="gap: 15px;">

				  <div class="level-item" id="wrap_enter_edit_ip">
					<a href="#" id="btn_enter_edit_ip" title="Editar IP dos peers selecionados">
					  <span class="icon has-text-info">
						<i class="bi-pencil-square" style="font-size: 30px"></i>
					  </span>
					</a>
				  </div>

				  <div class="level-item" id="wrap_save_ip_bulk" style="display:none;">
					<a href="#" id="btn_save_ip_bulk" title="Confirmar novo IP">
					  <span class="icon has-text-success">
						<i class="bi-check-circle-fill" style="font-size: 30px"></i>
					  </span>
					</a>
				  </div>

				  <div class="level-item" id="wrap_cancel_edit_ip" style="display:none;">
					<a href="#" id="btn_cancel_edit_ip" title="Cancelar edição">
					  <span class="icon has-text-danger">
						<i class="bi-x-circle-fill" style="font-size: 30px"></i>
					  </span>
					</a>
				  </div>
				  
				  <div class="level-item">
					<a href="#" title="Efetivar Rota (Atualizar IP dos NAS selecionados no MK-Auth)" onclick="if(confirm('Tem certeza que deseja EFETIVAR os peers selecionados?\nIsso atualizará o IP no cadastro do MK-Auth, fazendo a comunicação ocorrer exclusivamente pelo WireGuard.')) { return submitPeersBulk('efetivar_ip'); } return false;">
					  <span class="icon" style="color: #8b5cf6;">
						<i class="bi-arrow-left-right" style="font-size: 30px"></i>
					  </span>
					</a>
				  </div>
				  
				  <div class="level-item">
					<a href="#" title="Habilitar peers selecionados" onclick="return submitPeersBulk('enable');">
					  <span class="icon has-text-success">
						<i class="bi-power" style="font-size: 30px"></i>
					  </span>
					</a>
				  </div>

				  <div class="level-item">
					<a href="#" title="Desabilitar peers selecionados" onclick="return submitPeersBulk('disable');">
					  <span class="icon has-text-danger">
						<i class="bi-power" style="font-size: 30px"></i>
					  </span>
					</a>
				  </div>

				  <div class="level-item">
					<a href="#" title="Excluir peers selecionados" onclick="return submitPeersBulk('delete');">
					  <span class="icon has-text-danger">
						<i class="bi-trash3-fill" style="font-size: 30px"></i>
					  </span>
					</a>
				  </div>

				</div>
			  </nav>

			  <select name="bulk_action" id="bulk_action_peers" style="display:none;">
				<option value="">-</option>
				<option value="disable">disable</option>
				<option value="enable">enable</option>
				<option value="delete">delete</option>
				<option value="efetivar_ip">efetivar_ip</option>
			  </select>
			</div>
			
		</form>

		<!-- Lógica de Paginação -->
		<?php
		$total_pages = ($per_page > 0) ? (int)ceil($total_rows / $per_page) : 1;
		if ($total_pages < 1) {
			$total_pages = 1;
		}

		function build_peer_url($page_target) {
			$qs = [
				'tab'      => 'peers',
				'page'     => $page_target,
				'per_page' => isset($_GET['per_page']) ? (int)$_GET['per_page'] : null,
				'search'   => $_GET['search']  ?? null,
				'status'   => $_GET['status']  ?? null,
			];
			$qs = array_filter($qs, fn($v) => $v !== null && $v !== '');
			return '?' . http_build_query($qs);
		}
		?>

		<?php if ($total_pages > 1): ?>
			<nav class="pagination" role="navigation" aria-label="pagination" style="margin-top: 1.5rem;">
				<a class="pagination-previous <?php echo $page <= 1 ? 'is-disabled' : ''; ?>"
				   href="<?php echo $page <= 1 ? '#' : build_peer_url(max(1, $page - 1)); ?>">
					Anterior
				</a>
				<a class="pagination-next <?php echo $page >= $total_pages ? 'is-disabled' : ''; ?>"
				   href="<?php echo $page >= $total_pages ? '#' : build_peer_url(min($total_pages, $page + 1)); ?>">
					Próxima
				</a>
				<ul class="pagination-list">
					<?php for ($p = 1; $p <= $total_pages; $p++): ?>
						<li>
							<a class="pagination-link <?php echo $p == $page ? 'is-current' : ''; ?>"
							   href="<?php echo build_peer_url($p); ?>">
								<?php echo $p; ?>
							</a>
						</li>
					<?php endfor; ?>
				</ul>
			</nav>
		<?php endif; ?>
	</div>

<!-- Os mesmos Modais -->
<?php if (!empty($_SESSION['wg_last_conf'])): ?>
<div class="modal is-active" id="modal_conf">
  <div class="modal-background" onclick="fecharConfModal();"></div>
  <div class="modal-content">
    <div class="box">
      <h3 class="title is-5">Config .conf WireGuard</h3>
      <textarea class="textarea" id="conf_textarea" rows="12" readonly><?php
        echo htmlspecialchars($_SESSION['wg_last_conf']);
        unset($_SESSION['wg_last_conf']);
      ?></textarea>
      <br>
      <button class="button is-link" type="button" onclick="copiarConf();">Copiar</button>
      <button class="button" type="button" onclick="fecharConfModal();">Fechar</button>
    </div>
  </div>
  <button class="modal-close is-large" aria-label="close" onclick="fecharConfModal();"></button>
</div>
<?php endif; ?>

<?php if (!empty($_SESSION['wg_last_rsc'])): ?>
<div class="modal is-active" id="modal_rsc">
  <div class="modal-background" onclick="fecharRscModal();"></div>
  <div class="modal-content">
    <div class="box">
      <h3 class="title is-5">Script .rsc Mikrotik</h3>
      <textarea class="textarea" id="rsc_textarea" rows="12" readonly><?php
        echo htmlspecialchars($_SESSION['wg_last_rsc']);
        unset($_SESSION['wg_last_rsc']);
      ?></textarea>
      <br>
      <button class="button is-link" type="button" onclick="copiarRsc();">Copiar</button>
      <button class="button" type="button" onclick="fecharRscModal();">Fechar</button>
    </div>
  </div>
  <button class="modal-close is-large" aria-label="close" onclick="fecharRscModal();"></button>
</div>
<?php endif; ?>

<?php if (!empty($_SESSION['wg_last_wgstring'])): ?>
<div class="modal is-active" id="modal_wgstring">
  <div class="modal-background" onclick="fecharWgStringModal();"></div>
  <div class="modal-content">
    <div class="box">
      <h3 class="title is-5">Comando wg-import (RouterOS 7.x)</h3>
      <p class="help">
        Copie e execute no MikroTik:
        <code>/interface wireguard/wg-import config-string="..."</code>
      </p>
      <textarea class="textarea" id="wgstring_textarea" rows="8" readonly><?php
        echo htmlspecialchars($_SESSION['wg_last_wgstring']);
        unset($_SESSION['wg_last_wgstring']);
      ?></textarea>
      <br>
      <button class="button is-link" type="button" onclick="copiarWgString();">Copiar</button>
      <button class="button" type="button" onclick="fecharWgStringModal();">Fechar</button>
    </div>
  </div>
  <button class="modal-close is-large" aria-label="close" onclick="fecharWgStringModal();"></button>
</div>
<?php endif; ?>

<?php elseif ($tab === 'provisionar'): ?>

<div class="box custom-card" style="border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); padding: 2rem; background: #fafafa;">
    
    <form id="form_provisionar" method="POST" action="?tab=provisionar">
        
        <!-- Ação exata que o Backend espera -->
        <input type="hidden" name="acao" value="provisionar_ramais">

        <!-- NOVO LAYOUT EM 3 CARDS (Intro, Rede, Integração) -->
        <div class="columns is-multiline mb-5">
            
            <!-- CARD 1: Título e Explicação -->
            <div class="column is-4">
                <div class="box" style="height: 100%; border-radius: 10px; border: 1px solid #eef0f3; box-shadow: 0 2px 8px rgba(0,0,0,0.02); background: #ffffff;">
                    <div class="mb-4">
                        <span class="icon is-large has-text-link" style="background: #eff5fb; border-radius: 12px; height: 3.5rem; width: 3.5rem;">
                            <i class="bi bi-hdd-network-fill" style="font-size: 1.8rem;"></i>
                        </span>
                    </div>
                    <h2 class="title is-4 mb-2" style="color: #1e293b;">Provisionar NAS</h2>
                    <p class="has-text-grey is-size-6" style="line-height: 1.5;">
                        Crie peers WireGuard para as RouterBoards. Use <strong>OTP (One Touch Provisioning)</strong> se elegível para injetar as configurações diretamente na MikroTik via SSH, automatizando a implantação.
                    </p>
                </div>
            </div>

            <!-- CARD 2: Rede Base e Estratégia de IP -->
            <div class="column is-4">
                <div class="box" style="height: 100%; display: flex; flex-direction: column; border-radius: 10px; border: 1px solid #eef0f3; box-shadow: 0 2px 8px rgba(0,0,0,0.02); background: #ffffff;">
                    <h3 class="subtitle is-6 has-text-grey-dark mb-3 font-weight-bold">
                        <i class="bi bi-diagram-3 mr-1"></i> Rede WG e Alocação
                    </h3>
                    
                    <div class="is-size-3 has-text-weight-bold has-text-dark mb-1" style="letter-spacing: -1px;">
                        <?php echo htmlspecialchars($wg_base_cidr); ?>
                    </div>
                    <input type="hidden" name="wg_base_cidr" value="<?php echo htmlspecialchars($wg_base_cidr); ?>">
                    
                    <div class="mb-4">
                        <?php if (isset($wg_server_host) && $wg_server_host !== '' && isset($wg_max_peers) && $wg_max_peers > 0): ?>
                            <span class="tag is-info is-light">Host: <?php echo htmlspecialchars($wg_server_host); ?></span>
                        <?php elseif (isset($wg_server_host) && $wg_server_host !== ''): ?>
                            <span class="tag is-info is-light">Host: <?php echo htmlspecialchars($wg_server_host); ?></span>
                        <?php else: ?>
                            <span class="tag is-danger is-light"><i class="bi bi-exclamation-triangle mr-1"></i> Configure wg0 primeiro</span>
                        <?php endif; ?>
                    </div>

                    <div class="mt-auto">
                        <p class="is-size-7 has-text-grey mb-2" style="font-weight: 600;">ESTRATÉGIA DE IP (/32)</p>
                        <div class="control is-flex" style="gap: 10px;">
                            <label class="radio is-flex-grow-1 m-0 p-2 has-text-centered" style="border: 1px solid #ddd; border-radius: 6px; cursor: pointer; transition: 0.2s; background: #fafafa;">
                                <input type="radio" name="alloc_mode" value="seq" checked>
                                <br><strong class="is-size-7">Sequencial</strong>
                            </label>
                            <label class="radio is-flex-grow-1 m-0 p-2 has-text-centered" style="border: 1px solid #ddd; border-radius: 6px; cursor: pointer; transition: 0.2s; background: #fafafa;">
                                <input type="radio" name="alloc_mode" value="rand">
                                <br><strong class="is-size-7">Aleatório</strong>
                            </label>
                        </div>
                    </div>
                </div>
            </div>

            <!-- CARD 3: O Dado Mais Importante (Integração de Rota) -->
            <div class="column is-4">
                <div class="box" style="height: 100%; display: flex; flex-direction: column; border-radius: 10px; border: 2px solid #e0f2fe; background: #f8fafc; box-shadow: 0 4px 12px rgba(14, 165, 233, 0.05);">
                    <h3 class="subtitle is-6 has-text-link-dark mb-3" style="font-weight: 700;">
                        <i class="bi bi-arrow-left-right mr-1"></i> Ação no MK-Auth
                    </h3>
                    
                    <div class="field mt-auto">
                        <!-- RADIUS 1: Instalação Limpa -->
                        <label class="radio" style="display: block; background: #ffffff; padding: 12px 14px; border-radius: 8px; border: 1px solid #bae6fd; cursor: pointer; margin-bottom: 10px; margin-left: 0; box-shadow: 0 1px 3px rgba(0,0,0,0.02);">
                            <div class="is-flex is-align-items-center mb-1">
                                <input type="radio" name="atualizar_ip_nas" value="1" checked class="mr-2" style="transform: scale(1.2);">
                                <strong class="has-text-dark" style="font-size: 0.95rem;">Instalação Direta (Novo)</strong>
                            </div>
                            <p class="has-text-grey" style="font-size: 0.75rem; padding-left: 26px; line-height: 1.4;">
                                Atualiza o IP da RB no sistema imediatamente. Ideal para instalações limpas sem VPN (PPTP/SSTP) prévia.
                            </p>
                        </label>

                        <!-- RADIUS 2: Migração Segura -->
                        <label class="radio" style="display: block; background: #ffffff; padding: 12px 14px; border-radius: 8px; border: 1px solid #e2e8f0; cursor: pointer; margin-left: 0; box-shadow: 0 1px 3px rgba(0,0,0,0.02);">
                            <div class="is-flex is-align-items-center mb-1">
                                <input type="radio" name="atualizar_ip_nas" value="0" class="mr-2" style="transform: scale(1.2);">
                                <strong class="has-text-dark" style="font-size: 0.95rem;">Migração de Protocolo</strong>
                            </div>
                            <p class="has-text-grey" style="font-size: 0.75rem; padding-left: 26px; line-height: 1.4;">
                                Mantém o IP de cadastro intacto. Suba o túnel WG em paralelo com segurança e depois use o botão <strong>"Efetivar Rota"</strong> na aba Peers para virar a chave!
                            </p>
                        </label>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- A TABELA DE RAMAIS MESTRA -->
        <div class="table-container">
            <table class="table is-fullwidth is-hoverable is-striped" style="background: white; border-radius: 8px; overflow: hidden; font-size: 0.9rem;">
                <thead style="background-color: #f1f5f9;">
                    <tr>
                        <th width="3%" class="has-text-centered"><input type="checkbox" onchange="toggleAllRamais(this)"></th>
                        <th width="5%">ID</th>
                        <th width="15%">Nome do Ramal</th>
                        <th width="12%">IP do MK</th>
                        <!-- COLUNA INTELIGENTE -->
                        <th width="14%" class="has-text-centered" title="Status de operação do Túnel">Tunnel Wireguard</th>
                        <th width="14%">IP Fallback (Acesso)</th>
                        <th width="8%" class="has-text-centered">Porta SSH</th>
                        <th width="12%">Senha mkauth</th>
                        <th width="17%" class="has-text-centered">Status OTP (SSH)</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($ramais_list)): ?>
                        <tr><td colspan="9" class="has-text-centered py-5">Nenhum NAS cadastrado no MK-AUTH.</td></tr>
                    <?php else: ?>
                        <?php foreach ($ramais_list as $row): 
                            
                            $ja_provisionado = !empty($row['wg_id']);
                            $has_ip    = !empty($row['ipfall']);
                            $has_pass  = !empty($row['senha']);
                            $porta_ssh = !empty($row['portassh']) ? $row['portassh'] : '22';
                            
                            $otp_pronto = ($has_ip && $has_pass);

                            $ip_wg_limpo = $ja_provisionado ? explode('/', $row['wg_ip'])[0] : '';
                            $ip_mk_atual = trim($row['nasname']);
                            
                            // Lógica inteligente dos cards
                            $ip_espelhado_ok = ($ja_provisionado && $ip_wg_limpo === $ip_mk_atual);
                            $is_disabled     = ($ja_provisionado && isset($row['wg_status']) && $row['wg_status'] === 'disabled');
                        ?>
                        <tr>
                            <!-- 1. CHECKBOX -->
                            <td class="is-vcentered has-text-centered">
								<input type="checkbox" class="ramal-checkbox" name="ramal_ids[]" value="<?= $row['id_nas'] ?>" data-otp="<?= $otp_pronto ? '1' : '0' ?>" data-prov="<?= $ja_provisionado ? '1' : '0' ?>">
                            </td>
                            
                            <!-- 2. ID -->
                            <td class="is-vcentered has-text-weight-bold"><?= $row['id_nas'] ?></td>
                            
                            <!-- 3. NOME DO RAMAL -->
                            <td class="is-vcentered">
                                <strong><?= htmlspecialchars($row['shortname']) ?></strong>
                            </td>

                            <!-- 4. IP DO SISTEMA (MK-AUTH) -->
                            <td class="is-vcentered">
                                <span class="tag is-info is-light has-text-weight-bold"><?= htmlspecialchars($ip_mk_atual) ?></span>
                            </td>

                            <!-- 5. TUNNEL WIREGUARD (NOVA LÓGICA DE STATUS) -->
                            <td class="is-vcentered has-text-centered">
                                <?php if (!$ja_provisionado): ?>
                                    <!-- Caso 1: Ramal virgem sem peer -->
                                    <span class="tag has-text-grey-dark" style="background-color: #e2e8f0; font-weight: 600;">Não configurado</span>
                                
                                <?php elseif ($is_disabled): ?>
                                    <!-- Caso 4: Peer existe mas está Disabled -->
                                    <span class="tag is-danger" style="font-weight: 600;"><i class="bi bi-x-circle mr-1"></i> Disabled</span>
                                
                                <?php elseif ($ip_espelhado_ok): ?>
                                    <!-- Caso 2: IP WG = IP MK (Oficial) -->
                                    <span class="tag is-success" style="font-weight: 600;"><i class="bi bi-check-circle mr-1"></i> Oficial</span>
                                
                                <?php else: ?>
                                    <!-- Caso 3: IP WG != IP MK (Em Paralelo) -->
                                    <span class="tag is-warning" style="font-weight: 600; background-color: #fde047; color: #854d0e;"><i class="bi bi-exclamation-circle mr-1"></i> Em paralelo</span>
                                <?php endif; ?>
                            </td>
                            
                            <!-- 6. IP FALLBACK -->
                            <td class="is-vcentered">
                                <?php if($has_ip): ?>
                                    <span class="has-text-weight-bold" style="color: #363636;"><?= htmlspecialchars($row['ipfall']) ?></span>
                                <?php else: ?>
                                    <span class="tag is-danger is-light"><i class="bi bi-exclamation-circle mr-1"></i> Faltando</span>
                                <?php endif; ?>
                            </td>

                            <!-- 7. PORTA SSH -->
                            <td class="is-vcentered has-text-centered">
                                <span class="has-text-grey"><?= htmlspecialchars($porta_ssh) ?></span>
                            </td>

                            <!-- 8. SENHA MKAUTH -->
                            <td class="is-vcentered">
                                <?php if($has_pass): ?>
                                    <div class="is-flex is-align-items-center">
                                        <span id="senha_txt_<?= $row['id_nas'] ?>" class="has-text-weight-bold is-family-monospace mr-2" data-senha="<?= htmlspecialchars($row['senha']) ?>" style="font-size: 1.1rem; color: #363636;">••••••</span>
                                        <a class="has-text-grey" onclick="toggleSenhaSpan('senha_txt_<?= $row['id_nas'] ?>', this)" style="cursor: pointer;" title="Ver Senha"><i class="bi bi-eye"></i></a>
                                    </div>
                                <?php else: ?>
                                    <span class="tag is-danger is-light"><i class="bi bi-exclamation-circle mr-1"></i> Faltando</span>
                                <?php endif; ?>
                            </td>

							<!-- 9. STATUS OTP (SSH) -->
							<td class="is-vcentered has-text-centered cell-ssh-status" data-id="<?= $row['id_nas'] ?>">
								<?php if ($otp_pronto): ?>
									<button type="button" class="button is-small is-light is-info" onclick="testarConexaoSsh(this, <?= $row['id_nas'] ?>)" style="font-weight: 600; transition: all 0.2s;">
										<span class="icon is-small"><i class="bi bi-arrow-repeat"></i></span>
										<span>Validar Acesso</span>
									</button>
								<?php else: ?>
									<span class="tag is-danger is-light" title="Faltam credenciais (IP ou Senha)"><i class="bi bi-x-circle mr-1"></i> Faltam Dados</span>
								<?php endif; ?>
							</td>
						</tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>

		<div class="mt-4">
			<div class="field is-grouped">
				<p class="control">
					<button type="button" class="button is-success" onclick="submitProvisionarRamais()" style="font-weight: 600;">
						<span class="icon is-small"><i class="bi bi-plus-lg"></i></span>
						<span>Provisionar Rb</span>
					</button>
				</p>
				<p class="control">
					<button type="button" class="button is-link" onclick="submitOtpEmMassa()" style="font-weight: 600;" title="Conectar via SSH e configurar a VPN">
						<span class="icon is-small"><i class="bi bi-magic"></i></span>
						<span>OTP (SSH)</span>
					</button>
				</p>
			</div>
			
			<div class="is-size-7 has-text-grey mt-2">
				<i class="bi bi-info-circle"></i> <strong>Provisionar Rb:</strong> Cria o peer WireGuard VPN para RouterBoard no servidor MK-Auth. | <strong>OTP:</strong> Conecta via SSH e aplica as configurações diretamente nas RouterBoards.
			</div>
		</div>
    </form>
</div>

    <!-- ========================================
         ABA: CRIAR PEER (VPS / INFRA)
         ======================================== -->
    <?php elseif ($tab === 'criar'): ?>

        <!-- CARD AZUL GRANDÃO: REDE ATUAL -->
        <div class="notification" style="background: linear-gradient(135deg, #0ea5e9 0%, #0284c7 100%); border: none; color: white; border-radius: 12px; box-shadow: 0 4px 12px rgba(14,165,233,0.3); display: flex; align-items: center; gap: 1.5rem; padding: 1.5rem; margin-bottom: 1.5rem;">
            <div style="font-size: 3rem; opacity: 0.9;">
                <i class="bi bi-diagram-3-fill"></i>
            </div>
            <div>
                <h3 class="title is-4" style="color: white; margin-bottom: 0.25rem;">
                    Rede WireGuard: <span style="font-family: monospace; background: rgba(255,255,255,0.2); padding: 2px 8px; border-radius: 6px; letter-spacing: 1px;"><?php echo htmlspecialchars($wg_base_cidr ?: 'Não configurada'); ?></span>
                </h3>
                <p style="opacity: 0.95; font-size: 1rem; margin-top: 0.5rem;">
                    IP do Servidor: <strong><?php echo htmlspecialchars($wg_server_host); ?></strong> &nbsp;|&nbsp; 
                    Capacidade: <strong><?php echo $wg_max_peers; ?> peers</strong>
                </p>
            </div>
        </div>

        <div class="columns is-desktop">
            <!-- COLUNA ESQUERDA: FORMULÁRIO (60%) -->
            <div class="column is-7">
                <div class="box" style="border-radius: 12px; border: 1px solid #e2e8f0; box-shadow: 0 4px 15px rgba(0,0,0,0.05); padding: 2rem; height: 100%;">
                    
                    <h4 class="title is-5" style="color: #334155; margin-bottom: 1.5rem; border-bottom: 2px solid #f1f5f9; padding-bottom: 0.5rem;">
                        <i class="bi bi-plus-circle-dotted" style="color: #0ea5e9; margin-right: 8px;"></i> Novo Cliente VPN
                    </h4>

                    <form action="?tab=status" method="POST">
                        <input type="hidden" name="acao" value="criar_peer">
                        <input type="hidden" name="id_nas" value="0"> <!-- Foco Infra/VPS, NAS=0 -->
                        
                        <!-- NOME DO PEER -->
                        <div class="field mb-5">
                            <label class="label" style="color: #475569;">Nome da Conexão <span class="has-text-danger">*</span></label>
                            <div class="control has-icons-left">
                                <input class="input is-medium" type="text" name="peer_name" required 
                                       placeholder="Ex: banco_dados, api_externa, filial_sp" 
                                       pattern="[a-zA-Z0-9_-]+" title="Apenas letras, números, traços e underlines" 
                                       style="border-radius: 8px; box-shadow: inset 0 1px 2px rgba(0,0,0,0.05);">
                                <span class="icon is-left">
                                    <i class="bi bi-person-badge"></i>
                                </span>
                            </div>
                            <p class="help">Nome amigável de identificação (sem espaços). Serve para organizar o painel.</p>
                        </div>

                        <!-- ENDEREÇO IP -->
                        <div class="field mb-5">
                            <label class="label" style="color: #475569;">Endereço IP (Address) <span class="has-text-danger">*</span></label>
                            <div class="control has-icons-left">
                                <input class="input is-medium" type="text" name="address" id="peer_address" required 
                                       placeholder="Ex: 10.10.10.2/32" 
                                       value="<?php echo $sugestao_ip_seq ? $sugestao_ip_seq.'/32' : ''; ?>" 
                                       style="border-radius: 8px; font-family: monospace; font-size: 1.1rem; font-weight: 600; color: #0f172a; box-shadow: inset 0 1px 2px rgba(0,0,0,0.05); transition: all 0.2s ease;">
                                <span class="icon is-left">
                                    <i class="bi bi-ethernet"></i>
                                </span>
                            </div>
                            
                            <!-- BOTÕES INTERATIVOS DE IP -->
                            <div class="buttons are-small mt-2" style="margin-bottom: 0;">
                                <?php if ($sugestao_ip_seq): ?>
                                    <button type="button" class="button is-info is-light" onclick="sortearIpPeerJS();" style="border-radius: 6px; border: 1px solid #3298dc;" title="Clique várias vezes para sortear um novo IP livre">
                                        <span class="icon"><i class="bi bi-dice-5-fill"></i></span>
                                        <span style="font-weight: 600;">Sortear Aleatório</span>
                                    </button>
                                    <button type="button" class="button is-success is-light" onclick="restaurarSequencialJS();" style="border-radius: 6px; border: 1px solid #48c774;" title="Voltar para o menor IP disponível">
                                        <span class="icon"><i class="bi bi-sort-numeric-up"></i></span>
                                        <span>Voltar Sequencial</span>
                                    </button>
                                <?php else: ?>
                                    <span class="tag is-danger is-light"><i class="bi bi-x-circle" style="margin-right: 5px;"></i> Rede lotada ou não detectada</span>
                                <?php endif; ?>
                            </div>
                            <p class="help mt-2">Clique em <strong>"Sortear Aleatório"</strong> para mudar o IP acima. Nós só sugerimos IPs vazios na rede.</p>
                        </div>

                        <div class="field mt-6">
                            <div class="control">
                                <button type="submit" class="button is-success is-medium is-fullwidth" style="border-radius: 8px; font-weight: 600; box-shadow: 0 4px 6px rgba(72,199,116,0.3);">
                                    <span class="icon"><i class="bi bi-cloud-plus-fill"></i></span>
                                    <span>Criar Cliente VPN</span>
                                </button>
                            </div>
                        </div>
                    </form>
				</div>
            </div>

            <!-- COLUNA DIREITA: HELP / INFORMAÇÕES (40%) -->
            <div class="column is-5">
                <div class="box has-background-info-light" style="border-radius: 12px; border: 1px solid #cce5ff; height: 100%;">
                    
                    <h4 class="title is-5" style="color: #0c5460; margin-bottom: 1.5rem; display: flex; align-items: center; gap: 10px;">
                        <span class="icon has-text-info"><i class="bi bi-info-circle-fill"></i></span>
                        Como Funciona?
                    </h4>
                    
                    <div class="content" style="color: #1d2124; font-size: 0.95rem;">
                        <p>Esta aba cria conexões <strong>independentes</strong> (Peers Standalone). Ideal para:</p>
                        
                        <ul style="margin-top: 0.5rem; margin-bottom: 1.5rem;">
                            <li>Conectar servidores remotos (VPS)</li>
                            <li>Acesso de Desenvolvedores / Suporte Técnico</li>
                            <li>Integração com APIs externas protegidas</li>
                            <li>Smartphones ou Notebooks isolados</li>
                        </ul>
                        
                        <div class="notification is-white" style="border-left: 4px solid #3298dc; padding: 1rem;">
                            <p class="mb-2"><strong>Dicas de Preenchimento:</strong></p>
                            <ul style="margin-top: 0; font-size: 0.9rem;">
                                <li class="mb-1"><strong>Nome:</strong> Não use espaços. Use algo descritivo como <code>webserver_01</code>.</li>
                                <li><strong>Address:</strong> Mantenha a máscara <code>/32</code>. Isso garante que este IP seja exclusivo deste cliente na tabela de roteamento do servidor.</li>
                            </ul>
                        </div>
                        
                        <p style="font-size: 0.85rem; color: #666; margin-top: 1.5rem;">
                            <i class="bi bi-lightbulb text-warning mr-1"></i> <strong>Nota:</strong> As chaves criptográficas (Pública, Privada e Preshared Key) serão geradas automaticamente pelo Daemon no momento da criação.
                        </p>
                    </div>

                </div>
            </div>
        </div>

    <?php endif; ?>
</div>
<div class="modal" id="about-wg-popup">
  <div class="modal-background"
       onclick="document.getElementById('about-wg-popup').classList.remove('is-active');"></div>

  <div class="modal-content" style="max-width: 420px;">
    <div class="box">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
        <h2 class="title is-5" style="margin-bottom:0;">Sobre WireGuard</h2>
        <button class="delete" aria-label="close"
                onclick="document.getElementById('about-wg-popup').classList.remove('is-active');"></button>
      </div>

      <?php if (!is_array($version_data) || empty($version_data['ok']) || empty($version_data['data'])): ?>
        <p>Não foi possível obter informações de versão via socket.</p>
      <?php else: ?>
        <?php $v = $version_data['data']; ?>

        <figure class="image" style="max-width: 320px; margin: 0 auto 0.5rem auto;">
          <img src="wireguard-logo.png" alt="WireGuard">
        </figure>

        <p><strong>WireGuard tools:</strong><br>
          <small><?php echo nl2br(htmlspecialchars($v['wgVersion'] ?? '')); ?></small>
        </p>

        <p><strong>Daemon addon:</strong>
          wg-mkauthd <?php echo htmlspecialchars($v['daemonVersion'] ?? ''); ?>
        </p>

        <p><strong>Socket:</strong>
          <?php echo htmlspecialchars($v['socketPath'] ?? ''); ?>
        </p>

        <p><strong>Daemon iniciado em:</strong>
          <?php echo htmlspecialchars($v['daemonStartedAt'] ?? ''); ?>
        </p>

        <p><strong>Kernel com WireGuard:</strong>
          <?php echo !empty($v['kernelHasWireguard']) ? 'Sim' : 'Não'; ?>
        </p>

        <hr style="margin:0.5rem 0;">
        <p style="font-size:0.85em;">
          Addon WireGuard para MK-AUTH – daemon em Go inspirado em wireguard-tools.
        </p>
      <?php endif; ?>
    </div>
  </div>
</div>
<!-- MODAL DE CONFIGURAÇÃO DE NAT / ENDPOINT -->
<div class="modal" id="modal_nat">
    <div class="modal-background" onclick="this.parentElement.classList.remove('is-active')"></div>
    <div class="modal-card" style="max-width: 450px;">
        <header class="modal-card-head" style="background-color: #f8fafc; border-bottom: 1px solid #e2e8f0;">
            <p class="modal-card-title is-size-5" style="font-weight: 700; color: #0f172a;">
                <i class="bi bi-globe" style="color: #0ea5e9;"></i> IP Público / NAT
            </p>
            <button class="delete" aria-label="close" onclick="document.getElementById('modal_nat').classList.remove('is-active')"></button>
        </header>
        <section class="modal-card-body">
            <div class="notification is-warning is-light" style="font-size: 0.85rem; padding: 1rem;">
                <i class="bi bi-exclamation-triangle-fill"></i> 
                <strong>Aviso:</strong> O Daemon detectou o IP <code><?php echo htmlspecialchars($ip_detectado); ?></code> automaticamente.<br><br>
                Só force um IP/Domínio manual se o seu servidor estiver atrás de um firewall (NAT/CGNAT) e você tiver uma regra de encaminhamento válida.
            </div>

            <form method="post" action="?tab=status">
                <input type="hidden" name="acao" value="salvar_nat">
                
                <div class="field">
                    <label class="label is-small">IP Fixo ou DDNS (Opcional)</label>
                    <div class="control has-icons-left">
                        <input class="input" type="text" name="ip_nat" placeholder="Ex: 200.20.20.5 ou vpn.provedor.com" value="<?php echo htmlspecialchars($ip_forcado); ?>">
                        <span class="icon is-small is-left"><i class="bi bi-hdd-network"></i></span>
                    </div>
                    <p class="help">Deixe o campo <strong>em branco</strong> para voltar ao modo de Detecção Automática.</p>
                </div>
                
                <div class="field mt-4">
                    <button type="submit" class="button is-info is-fullwidth" style="font-weight: 600;">
                        <i class="bi bi-save mr-2"></i> Salvar Configuração
                    </button>
                </div>
            </form>
        </section>
    </div>
</div>
<!-- MODAL OTP PROGRESSO -->
<div id="modal_otp_progress" class="modal">
  <div class="modal-background" style="background-color: rgba(15, 23, 42, 0.85);"></div>
  <div class="modal-card" style="border-radius: 16px; overflow: hidden; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5);">
    <header class="modal-card-head" style="background-color: #f8fafc; border-bottom: 1px solid #e2e8f0; padding: 1.25rem;">
      <p class="modal-card-title" style="font-weight: 800; color: #0f172a; font-size: 1.1rem; display: flex; align-items: center; gap: 10px;">
        <span class="icon" style="color: #0ea5e9;"><i class="bi bi-magic"></i></span>
        Auto OTP (One Touch Provisioning)
      </p>
    </header>
    <section class="modal-card-body" style="background-color: #ffffff; padding: 1.5rem;">
      <div id="otp_log_container" style="background: #0f172a; color: #f8fafc; padding: 1.25rem; border-radius: 12px; font-family: 'Courier New', Courier, monospace; font-size: 0.9rem; line-height: 1.6; height: 350px; overflow-y: auto; box-shadow: inset 0 4px 10px rgba(0,0,0,0.5);">
          <!-- Logs aparecerão aqui via JS -->
      </div>
    </section>
    <footer class="modal-card-foot" style="background-color: #f8fafc; border-top: 1px solid #e2e8f0; padding: 1.25rem; justify-content: flex-end;">
      <button id="btn_fechar_otp" class="button is-info" disabled style="border-radius: 10px; font-weight: 700; padding: 0.5rem 1.5rem; transition: all 0.3s ease;">
        Aguarde o Processo...
      </button>
    </footer>
  </div>
</div>

<?php include('../../baixo.php'); ?>
<!-- DADOS EXPORTADOS PARA O WG_ADDON.JS -->
<script>
    window.wgIpConfig = {
        usedIps: <?php echo isset($js_used_ips) ? $js_used_ips : '[]'; ?>,
        netIp: <?php echo isset($js_net_ip) ? $js_net_ip : '""'; ?>,
        mask: <?php echo isset($js_mask_int) ? $js_mask_int : '0'; ?>,
        seqIp: "<?php echo isset($sugestao_ip_seq) ? $sugestao_ip_seq : ''; ?>"
    };
</script>
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
<script src="../../menu.js.hhvm"></script>
<script src="wg_addon.js"></script>
</body>
</html>
