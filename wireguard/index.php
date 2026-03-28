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

// Verifica se o status do Root NÃO é 'vermelho' (Ou seja, ele fez o login)
$is_root = (isset($_SESSION['MKA_LoginRoot']) && $_SESSION['MKA_LoginRoot'] !== 'vermelho');

// ----------------------------------------------------------------------------------------------
// Configurações básicas
// ----------------------------------------------------------------------------------------------
$socketPath = '/run/wgmkauth.sock';

$msg_erro    = $msg_erro    ?? '';
$msg_sucesso = $msg_sucesso ?? '';

// Funções de Ajuda (Helpers)
include __DIR__ . '/includes/helpers.php';

// Conexão e Banco de Dados
include __DIR__ . '/includes/database.php';

// ----------------------------------------------------------------------------------------------
// Ações (POST) - criar peer / editar / bulk / provisionar
// ----------------------------------------------------------------------------------------------
include __DIR__ . '/includes/wg_actions_post.php';
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
include __DIR__ . '/includes/wg_downloads.php';

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
    <div class="mb-4" style="margin-top: -10px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
        
        <!-- Colocamos TUDO dentro do h1 com display: flex -->
        <h1 class="title is-4 mb-0" style="font-weight: 800; color: #0f172a; letter-spacing: -0.5px; display: flex; align-items: center; gap: 12px;">
            <!-- Logo SVG Oficial -->
            <img src="WireGuard_logo.svg" alt="Logo WireGuard" style="width: 36px; height: 36px; filter: drop-shadow(0 3px 6px rgba(0,0,0,0.15)); margin-top: -2px;">
            WIREGUARD VPN
            <!-- O SEU botão (i) original -->
            <a href="#" onclick="document.getElementById('about-wg-popup').classList.add('is-active'); return false;" title="Sobre o Addon WireGuard" style="color: #94a3b8; transition: color 0.2s ease; margin-top: 2px;">
              <span class="icon is-small hover-ciano"><i class="bi bi-info-circle"></i></span>
            </a>
        </h1>

        <!-- BOTÃO DE STATUS DO ROOT -->
        <div>
		<?php if (!$is_root): ?>
			<!-- Botão vermelho chamando o popup JS -->
			<a href="#" onclick="abrirLoginRoot(); return false;" class="button is-danger is-small" style="border-radius: 6px; font-weight: bold; box-shadow: 0 4px 6px rgba(220, 38, 38, 0.2);">
				<span class="icon"><i class="bi bi-lock-fill"></i></span>
				<span>Modo Leitura (Desbloquear)</span>
			</a>
            <?php else: ?>
                <!-- Indicador verde de root ativo -->
                <div class="tags has-addons mb-0">
                    <span class="tag is-dark is-medium"><i class="bi bi-shield-check" style="color: #4ade80;"></i></span>
                    <span class="tag is-success is-light is-medium" style="font-weight: bold;">Root Ativo</span>
                </div>
            <?php endif; ?>
        </div>

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

<?php include 'includes/menu_abas.php'; ?>

		<!-- ========================================
			 CONTEÚDO DAS ABAS (Roteamento Dinâmico)
			 ======================================== -->
		<div class="tabs-content">
			<?php 
				if ($tab === 'status') {
					include 'tabs/tab_status.php';
				} elseif ($tab === 'peers') {
					include 'tabs/tab_peers.php';
				} elseif ($tab === 'provisionar') {
					include 'tabs/tab_provisionar.php';
				} elseif ($tab === 'criar') {
					include 'tabs/tab_criar.php';
				}
			?>
		</div>
</div>
<?php include 'includes/modais.php'; ?>
<?php include('../../baixo.php'); ?>
<!-- DADOS EXPORTADOS PARA O WG_ADDON.JS -->
<script>
	window.wgIpConfig = {
		usedIps: <?php echo isset($js_used_ips) ? $js_used_ips : '[]'; ?>,
		netIp: <?php echo isset($js_net_ip) ? $js_net_ip : '""'; ?>,
		mask: <?php echo isset($js_mask_int) ? $js_mask_int : '0'; ?>,
		seqIp: "<?php echo isset($sugestao_ip_seq) ? $sugestao_ip_seq : ''; ?>"
	};

	// Injetando o Status do Root no JS
	window.isRoot = <?php echo $is_root ? 'true' : 'false'; ?>;

	// FUNÇÃO PARA ABRIR O POP-UP NATIVO DO MK-AUTH
	function abrirLoginRoot() {
		var width = 450;
		var height = 350;
		var left = (window.screen.width / 2) - (width / 2);
		var top = (window.screen.height / 2) - (height / 2);
		
		// Abre a telinha vermelha num popup pequeno
		var popup = window.open('/admin/login_root.hhvm', 'MKAuthRootLogin', 'width=' + width + ',height=' + height + ',top=' + top + ',left=' + left + ',resizable=no,scrollbars=no,status=no,toolbar=no,menubar=no');
		
		// "Espião" que fica checando se o usuário fechou o popup (no "X")
		var checkPopup = setInterval(function() {
			if (!popup || popup.closed || popup.closed === undefined) {
				clearInterval(checkPopup);
				// Quando o popup fecha, recarrega a página automaticamente pra aplicar o verde!
				window.location.reload();
			}
		}, 500);
	}

	// FUNÇÃO GLOBAL DE BARREIRA (SWEETALERT)
	function verificarRoot(event, nomeDaAcao) {
		if (!window.isRoot) {
			if (event) event.preventDefault(); // Trava o clique/submit na hora
			
			Swal.fire({
				icon: 'warning',
				title: 'Acesso Restrito',
				html: `Você está no <b>Modo Leitura</b>.<br>É necessário privilégio de Root para <b>${nomeDaAcao}</b>.`,
				showCancelButton: true,
				confirmButtonText: '<i class="bi bi-unlock-fill"></i> Fazer Login Root',
				cancelButtonText: 'Cancelar',
				confirmButtonColor: '#dc2626',
				cancelButtonColor: '#64748b'
			}).then((result) => {
				if (result.isConfirmed) {
					// Chama a nossa nova função de Pop-up
					abrirLoginRoot();
				}
			});
			return false; // Retorna falso pra garantir que a função chamadora aborte
		}
		return true; // Se for root, deixa passar!
	}
</script>
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
<script src="../../menu.js.hhvm"></script>
<script src="wg_addon.js"></script>
</body>
</html>
