<?php
// ==============================================================================================
// 🔌 DEPARTAMENTO 1: COMUNICAÇÃO CORE (DAEMON)
// ==============================================================================================

/**
 * Chamada ao socket UNIX do WireGuard (Daemon em Go)
 */
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

	file_put_contents('/tmp/wg_php_debug.log', date('c') . " WG_CALL RAW: " . var_export($resp, true) . " META: " . var_export($meta, true) . "\n", FILE_APPEND);

	if ($resp === '' || $resp === false) {
		return ['ok' => false, 'error' => 'no_response', 'message' => $meta['timed_out'] ? 'Timeout após 20s' : 'Daemon não respondeu'];
	}

	$data = json_decode($resp, true);

	if (!is_array($data)) {
		file_put_contents('/tmp/wg_php_debug.log', date('c') . " WG_CALL BAD_JSON: " . var_export($resp, true) . "\n", FILE_APPEND);
		return ['ok' => false, 'error' => 'bad_json', 'raw' => $resp];
	}

	return $data;
}

// ==============================================================================================
// 💾 DEPARTAMENTO 2: BACKUP E SNAPSHOTS
// ==============================================================================================

if (!defined('WG_MAX_SNAPSHOTS')) {
    define('WG_MAX_SNAPSHOTS', 5);
}

/**
 * Captura o wg0.conf atual via daemon + dump SQL de wg_ramais.
 * Grava como snapshot FIFO de 5 no campo interface_text.
 */
function wg_snapshot_interface(mysqli $db, string $socketPath, string $reason = 'manual'): bool
{
    $resp = wg_call(['action' => 'server-get-config'], $socketPath);
    if (empty($resp['ok']) || empty($resp['data']['rawText'])) {
        error_log("[wg_backup] snapshot falhou: daemon não retornou rawText. reason=$reason");
        return false;
    }
    $confAtual = $resp['data']['rawText'];

    $sqlDump = '';
    $peerCount = 0;
    $rs = $db->query("SELECT * FROM wg_ramais ORDER BY id");
    if ($rs) {
        while ($row = $rs->fetch_assoc()) {
            unset($row['interface_text'], $row['id']);
            if (isset($row['wg_client_id']) && $row['wg_client_id'] !== 'SERVER_MASTER') {
                $peerCount++;
            }
            $cols = [];
            $vals = [];
            foreach ($row as $col => $val) {
                $cols[] = "`{$col}`";
                $vals[] = ($val === null) ? 'NULL' : "'" . $db->real_escape_string($val) . "'";
            }
            $sqlDump .= "INSERT INTO wg_ramais (" . implode(', ', $cols) . ") VALUES (" . implode(', ', $vals) . ");\n";
        }
        $rs->close();
    }

    $novoSnapshot = ['at' => date('Y-m-d H:i:s'), 'reason' => $reason, 'conf' => $confAtual, 'sql' => $sqlDump, 'peers' => $peerCount];

    $row = $db->query("SELECT interface_text FROM wg_ramais WHERE interface_text IS NOT NULL AND interface_text != '' LIMIT 1");
    $snapshots = [];
    if ($row && ($r = $row->fetch_assoc()) && !empty($r['interface_text'])) {
        $snapshots = json_decode($r['interface_text'], true) ?: [];
    }

    array_unshift($snapshots, $novoSnapshot);
    $snapshots = array_slice($snapshots, 0, WG_MAX_SNAPSHOTS);
    $jsonText = json_encode($snapshots, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

    $stmt = $db->prepare("UPDATE wg_ramais SET interface_text = ?");
    if (!$stmt) return false;
    
    $stmt->bind_param('s', $jsonText);
    $ok = $stmt->execute();
    $stmt->close();
    return $ok;
}

// ==============================================================================================
// 🧮 DEPARTAMENTO 3: MATEMÁTICA DE REDES E IPS
// ==============================================================================================

function isValidIPv4Cidr($str) {
    $str = trim($str);
    $parts = explode('/', $str);
    if (count($parts) !== 2) return false;
    [$ip, $cidr] = $parts;
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return false;
    if (!ctype_digit($cidr)) return false;
    $cidr = (int)$cidr;
    return $cidr >= 0 && $cidr <= 32;
}

function ipInSubnet($ipWithCidr, $netip, $netmask) {
    $parts = explode('/', trim($ipWithCidr));
    if (count($parts) != 2) return false;
    $ip = $parts[0];
    $ipLong = ip2long($ip);
    $netLong = ip2long($netip);
    $maskBits = (int)$netmask;
    if ($ipLong === false || $netLong === false) return false;
    if ($maskBits < 0 || $maskBits > 32) return false;
    $mask = -1 << (32 - $maskBits);
    return (($ipLong & $mask) === ($netLong & $mask));
}

function wg_get_net_from_daemon($socketPath) {
    $status_data = wg_call(['action' => 'status'], $socketPath);
    $wg_base_cidr = $status_data['data']['wg_address'] ?? '';
    if ($wg_base_cidr === '' || strpos($wg_base_cidr, '/') === false) return [null, null];
    [$net_ip, $net_mask] = explode('/', $wg_base_cidr, 2);
    $net_long = ip2long($net_ip);
    $mask = (int)$net_mask;
    if ($net_long === false || $mask < 0 || $mask > 32) return [null, null];
    return [$net_ip, $mask];
}

function cidr_to_network(string $host_cidr): string {
    $parts = explode('/', $host_cidr, 2);
    if (count($parts) !== 2) return $host_cidr;
    $ip = $parts[0];
    $bits = (int)$parts[1];
    $long = ip2long($ip);
    if ($long === false) return $host_cidr;
    $mask = $bits === 0 ? 0 : (~0 << (32 - $bits));
    $network = $long & $mask;
    return long2ip($network) . '/' . $bits;
}

function cidr_max_peers(string $cidr): int {
    $parts = explode('/', $cidr, 2);
    if (count($parts) !== 2) return 0;
    $bits = (int)$parts[1];
    if ($bits < 1 || $bits > 30) return 0;
    return (int)(pow(2, 32 - $bits) - 3);
}

function wg_pick_free_ip_seq($net_long, $mask, array $used_ips) {
    $host_bits = 32 - $mask;
    $max_hosts = ($host_bits > 0) ? (1 << $host_bits) : 1;
    $mask_long = ($mask === 0) ? 0 : ((-1 << (32 - $mask)) & 0xFFFFFFFF);
    $network_long = $net_long & $mask_long;
    for ($offset = 1; $offset < $max_hosts - 1; $offset++) {
        $ip_long = $network_long + $offset;
        $ip = long2ip($ip_long);
        if (!isset($used_ips[$ip])) return $ip;
    }
    return null;
}

function wg_pick_free_ip_rand($net_long, $mask, array $used_ips) {
    $host_bits = 32 - $mask;
    $max_hosts = ($host_bits > 0) ? (1 << $host_bits) : 1;
    $mask_long = ($mask === 0) ? 0 : ((-1 << (32 - $mask)) & 0xFFFFFFFF);
    $network_long = $net_long & $mask_long;
    $tries = 0;
    while ($tries < 1000) {
        $offset = mt_rand(1, $max_hosts - 2);
        $ip_long = $network_long + $offset;
        $ip = long2ip($ip_long);
        if (!isset($used_ips[$ip])) return $ip;
        $tries++;
    }
    return null;
}

// ==============================================================================================
// 🛠️ DEPARTAMENTO 4: FERRAMENTAS MIKROTIK
// ==============================================================================================

function normalizar_conf_para_wg_import(string $conf): string {
    $linhas = preg_split("/\r\n|\n|\r/", $conf);
    $limpas = [];
    foreach ($linhas as $linha) {
        $trim = trim($linha);
        if ($trim === '' || strpos($trim, '#') === 0) continue;
        $limpas[] = $trim;
    }
    $conf_limpo = implode('\n', $limpas);
    $conf_limpo = str_replace('"', '\"', $conf_limpo);
    return '/interface wireguard/wg-import config-string="' . $conf_limpo . '"';
}
// HELPER: GERADOR DE SCRIPT MIKROTIK (.RSC) IDEMPOTENTE
if (!function_exists('wg_gerar_script_mikrotik')) {
    function wg_gerar_script_mikrotik(string $config_text, int $id_nas, int $id_peer, string $safe_name): string {
        $lines = preg_split("/\r\n|\r|\n/", $config_text);

        $ifacePrivate = ''; $ifaceAddress = ''; $peerPublic = ''; $peerPsk = ''; 
        $peerEndpoint = ''; $peerAllowed = ''; $peerKeep = '';

        $section = '';
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || strpos($line, '#') === 0) continue;
            
            if (strcasecmp($line, '[Interface]') === 0) { $section = 'iface'; continue; } 
            elseif (strcasecmp($line, '[Peer]') === 0) { $section = 'peer'; continue; }

            $parts = explode('=', $line, 2);
            if (count($parts) !== 2) continue;
            
            $k = strtolower(trim($parts[0]));
            $v = trim($parts[1]);

            if ($section === 'iface') {
                if ($k === 'privatekey') $ifacePrivate = $v;
                elseif ($k === 'address') $ifaceAddress = $v;
            } elseif ($section === 'peer') {
                if ($k === 'publickey') $peerPublic = $v;
                elseif ($k === 'presharedkey') $peerPsk = $v;
                elseif ($k === 'endpoint') $peerEndpoint = $v;
                elseif ($k === 'allowedips') $peerAllowed = $v;
                elseif ($k === 'persistentkeepalive') $peerKeep = $v;
            }
        }

		$mtIfName       = 'wg-mkauth';
		$mtComment      = 'mkauth-wireguard';
		$mtRouteComment = 'mkauth-wireguard-route';

        $rsc  = "";
        $rsc .= "# WireGuard cliente gerado pelo MK-AUTH para " . $safe_name . "\n";
        $rsc .= "# Ajuste nomes/endereços/conectividade conforme necessário antes de aplicar.\n\n";

        $rsc .= "# 1. Limpeza de regras antigas (Idempotencia)\n";
        $rsc .= ":do { /interface wireguard peers remove [find comment=\"" . $mtComment . "\"] } on-error={}\n";
        $rsc .= ":do { /interface wireguard remove [find name=\"" . $mtIfName . "\"] } on-error={}\n";
        $rsc .= ":do { /ip address remove [find comment=\"" . $mtComment . "\"] } on-error={}\n";
		$rsc .= ":do { /ip route remove [find comment=\"" . $mtRouteComment . "\"] } on-error={}\n\n";

        $rsc .= "# 2. Criacao da Interface\n";
        $rsc .= "/interface wireguard add name=\"" . $mtIfName . "\" private-key=\"" . $ifacePrivate . "\" listen-port=0 comment=\"" . $mtComment . "\"\n\n";

        if ($ifaceAddress !== '') {
            $rsc .= "# 3. Configuracao de IP\n";
            $rsc .= "/ip address add address=" . $ifaceAddress . " interface=" . $mtIfName . " comment=\"" . $mtComment . "\"\n\n";
        }

        $rsc .= "# 4. Configuracao do Peer (Servidor MK-Auth)\n";
        $rsc .= "/interface wireguard peers add interface=" . $mtIfName . " public-key=\"" . $peerPublic . "\"";
        if ($peerPsk !== '') $rsc .= " preshared-key=\"" . $peerPsk . "\"";
        $rsc .= " allowed-address=" . $peerAllowed;
        
        if ($peerEndpoint !== '') {
            $hp = explode(':', $peerEndpoint, 2);
            if (count($hp) === 2) $rsc .= " endpoint-address=" . $hp[0] . " endpoint-port=" . (int)$hp[1];
            else $rsc .= " endpoint-address=" . $peerEndpoint;
        }
        if ($peerKeep !== '') $rsc .= " persistent-keepalive=" . (int)$peerKeep;
        $rsc .= " comment=\"" . $mtComment . "\"\n\n";

        if ($ifaceAddress !== '' && $peerAllowed !== '') {
            $ipParts = explode('/', $ifaceAddress, 2);
            $ipOnly  = trim($ipParts[0]);

            $serverIp = null;
            $allowedParts = explode(',', $peerAllowed);
            foreach ($allowedParts as $p) {
                $p = trim($p);
                if ($p === '' || strpos($p, ':') !== false) continue; 
                $hp = explode('/', $p, 2);
                if (!empty($hp[0])) {
                    $serverIp = trim($hp[0]); 
                    break;
                }
            }

            if ($ipOnly !== '' && $serverIp !== null) {
                $rsc .= "# 5. Rota Estatica\n";
				$rsc .= "/ip route add dst-address=" . $serverIp . "/32 gateway=" . $mtIfName . " comment=\"" . $mtRouteComment . "\"\n";
            }
        }

        return $rsc;
    }
}

// ==============================================================================================
// 🎨 DEPARTAMENTO 5: AJUDANTES VISUAIS (UI / BULMA)
// ==============================================================================================

function formataDataRelativa($dataString) {
    if (empty($dataString)) return '-';
    $ts = strtotime($dataString);
    if (!$ts) return htmlspecialchars($dataString); 
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

function humanBytes($bytes, $precision = 2) {
    $bytes = (float) $bytes;
    if ($bytes <= 0) return '<span class="has-text-grey-light">0 B</span>';
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    $pow = floor(log($bytes) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= pow(1024, $pow);
    return round($bytes, $precision) . ' ' . $units[$pow];
}
