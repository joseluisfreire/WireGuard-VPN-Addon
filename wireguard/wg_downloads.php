<?php
// =========================================================================
// HELPER: GERADOR DE SCRIPT MIKROTIK (.RSC) IDEMPOTENTE
// =========================================================================
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

        $ifaceId   = ($id_nas > 0) ? $id_nas : (($id_peer > 0) ? $id_peer : 1);
        $mtIfName  = 'wg-nas' . $ifaceId;
        $mtComment = 'WG-' . $safe_name;

        $rsc  = "";
        $rsc .= "# WireGuard cliente gerado pelo MK-AUTH para " . $safe_name . "\n";
        $rsc .= "# Ajuste nomes/endereços/conectividade conforme necessário antes de aplicar.\n\n";

        $rsc .= "# 1. Limpeza de regras antigas (Idempotencia)\n";
        $rsc .= ":do { /interface wireguard peers remove [find comment=\"" . $mtComment . "\"] } on-error={}\n";
        $rsc .= ":do { /interface wireguard remove [find name=\"" . $mtIfName . "\"] } on-error={}\n";
        $rsc .= ":do { /ip address remove [find comment=\"" . $mtComment . "\"] } on-error={}\n";
        $rsc .= ":do { /ip route remove [find comment=\"Rota MK-Auth WG " . $mtComment . "\"] } on-error={}\n\n";

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
                $rsc .= "/ip route add dst-address=" . $serverIp . "/32 gateway=" . $mtIfName . " comment=\"Rota MK-Auth WG " . $mtComment . "\"\n";
            }
        }

        return $rsc;
    }
}

// =========================================================================
// MODAIS DE VISUALIZAÇÃO (.conf, .rsc, wgimport string)
// =========================================================================
if (!$erro_db && isset($_POST['acao_modal']) && in_array($_POST['acao_modal'], ['show_conf', 'show_rsc', 'show_wgstring'], true)) {
    $id = isset($_POST['id_peer']) ? (int)$_POST['id_peer'] : 0;

    if ($id > 0) {
        $stmt = $mysqli->prepare("SELECT peer_name, config_text, id_nas, ip_wg FROM wg_ramais WHERE id = ? LIMIT 1");
        if ($stmt) {
            $stmt->bind_param('i', $id);
            $stmt->execute();
            $stmt->bind_result($peer_name, $config_text, $id_nas, $ip_wg);

            if ($stmt->fetch() && $config_text !== null && $config_text !== '') {
                $safe_name = preg_replace('/[^a-zA-Z0-9_-]+/', '_', $peer_name) ?: 'peer';

                if ($_POST['acao_modal'] === 'show_conf') {
                    $_SESSION['wg_last_conf'] = $config_text;

                } elseif ($_POST['acao_modal'] === 'show_wgstring') {
                    $wg_string_cmd = normalizar_conf_para_wg_import($config_text);
                    $wg_string_cmd .= "\n\n# ATENÇÃO: após importar, crie a rota estática para o servidor\n";
                    $wg_string_cmd .= "# /ip route add dst-address=<SERVER_IP>/32 gateway=<WG_INTERFACE>\n";
                    $_SESSION['wg_last_wgstring'] = $wg_string_cmd;

                } elseif ($_POST['acao_modal'] === 'show_rsc') {
                    $_SESSION['wg_last_rsc'] = wg_gerar_script_mikrotik($config_text, (int)$id_nas, (int)$id, $safe_name);
                }
            }
            $stmt->close();
        }
    }

    // Sempre volta pra aba peers após fechar o modal
    header('Location: ?tab=peers');
    exit;
}

// =========================================================================
// DOWNLOADS (.conf, wgimport string e .rsc)
// =========================================================================
if (!$erro_db && isset($_GET['acao']) && in_array($_GET['acao'], ['download_conf', 'download_wgstring', 'download_rsc'], true)) {
    $id = isset($_GET['id']) ? (int)$_GET['id'] : 0;

    if ($id > 0) {
        $stmt = $mysqli->prepare("SELECT peer_name, config_text, id_nas, ip_wg FROM wg_ramais WHERE id = ? LIMIT 1");
        if ($stmt) {
            $stmt->bind_param('i', $id);
            $stmt->execute();
            $stmt->bind_result($peer_name, $config_text, $id_nas, $ip_wg);

            if ($stmt->fetch() && $config_text !== null && $config_text !== '') {
                $stmt->close();

                $safe_name = preg_replace('/[^a-zA-Z0-9_-]+/', '_', $peer_name) ?: 'peer';
                $acao = $_GET['acao'];

                if ($acao === 'download_conf') {
                    header('Content-Type: application/x-wg-config');
                    header('Content-Disposition: attachment; filename="wg-' . $safe_name . '.conf"');
                    echo $config_text;
                    exit;

                } elseif ($acao === 'download_wgstring') {
                    $wg_string_cmd = normalizar_conf_para_wg_import($config_text);
                    $wg_string_cmd .= "\n\n# ATENÇÃO: após importar, crie a rota estática para o servidor\n";
                    $wg_string_cmd .= "# /ip route add dst-address=<SERVER_IP>/32 gateway=<WG_INTERFACE>\n";

                    header('Content-Type: text/plain');
                    header('Content-Disposition: attachment; filename="wgimport-' . $safe_name . '.txt"');
                    echo $wg_string_cmd;
                    exit;

                } elseif ($acao === 'download_rsc') {
                    $rsc = wg_gerar_script_mikrotik($config_text, (int)$id_nas, (int)$id, $safe_name);

                    header('Content-Type: text/plain');
                    header('Content-Disposition: attachment; filename="wg-' . $safe_name . '.rsc"');
                    echo $rsc;
                    exit;
                }
            } else {
                $stmt->close();
            }
        }
    }
}
?>
