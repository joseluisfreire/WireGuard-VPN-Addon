<?php
// Garante que a sessão tá rodando
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// =========================================================================
// BLOCO PRINCIPAL DE AÇÕES POST
// =========================================================================
if (!$erro_db && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $acao = isset($_POST['acao']) ? trim($_POST['acao']) : '';
    
    // --- TRAVA DE SEGURANÇA BACKEND (BLINDAGEM) ---
    // Ações permitidas no Modo Leitura (não exigem senha de root)
	$acoes_leitura = [
		'get_live_stats', 
		'check_tunnel_unitario', 
		'download_snapshot', 
		'show_conf', 
		'show_rsc', 
		'show_wgstring'
	];

    // Se a ação NÃO estiver na lista de leitura E o usuário NÃO tiver o root verde, bloqueia!
    if (!in_array($acao, $acoes_leitura) && (!isset($_SESSION['MKA_LoginRoot']) || $_SESSION['MKA_LoginRoot'] === 'vermelho')) {
        
        // Se a requisição bloqueada esperava um JSON (AJAX), devolve um erro em JSON para não quebrar o JS
        if (isset($_SERVER['HTTP_ACCEPT']) && strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false) {
            header('Content-Type: application/json');
            echo json_encode(['ok' => false, 'error' => 'Acesso Negado! Login de root necessário.']);
            exit;
        }

        // Se for uma requisição normal (formulário), redireciona com a mensagem vermelha
        $_SESSION['wg_msg_erro'] = "Acesso Negado pelo Servidor! É necessário fazer o Login de Root.";
        header("Location: ?tab=status"); 
        exit;
    }
    // ----------------------------------------------

    $msg_erro = '';
    
    file_put_contents(
        '/tmp/wg_flow.log',
        date('c') . " POST ACAO={$acao} RAW=" . http_build_query($_POST) . "\n",
        FILE_APPEND
    );
    // =========================================================================
    // VALIDADOR OTP: ENVIANDO PARA O DAEMON GO (SOCKET UNIX)
    // =========================================================================
    if ($acao === 'testar_ssh_otp') {
        header('Content-Type: application/json');
        $id_nas = isset($_POST['id_nas']) ? (int)$_POST['id_nas'] : 0;
        
        $q = $mysqli->query("SELECT nasname, ipfall, portassh, senha FROM nas WHERE id = $id_nas");
        if (!$q || $q->num_rows === 0) {
            echo json_encode(['status' => 'error', 'msg' => 'NAS não encontrado no BD']);
            exit;
        }
        $nas = $q->fetch_assoc();
        
        $ips_to_test = [];
        if (!empty(trim($nas['nasname']))) $ips_to_test[] = trim($nas['nasname']);
        if (!empty(trim($nas['ipfall']))) $ips_to_test[] = trim($nas['ipfall']);
        $ips_to_test = array_unique($ips_to_test); 
        
        if (empty($ips_to_test)) {
            echo json_encode(['status' => 'error', 'msg' => 'Sem IP cadastrado']);
            exit;
        }
        
        // Payload para o Daemon agir
        $payload = json_encode([
            'action' => 'testar-ssh',
            'ips'    => array_values($ips_to_test),
            'port'   => !empty($nas['portassh']) ? (int)$nas['portassh'] : 22,
            'pass'   => trim($nas['senha']),
            'user'   => 'mkauth'
        ]);
        
        // Atirando no Socket Unix do Go!
        $socket_path = '/run/wgmkauth.sock'; // Caminho real do seu Daemon
        $fp = fsockopen("unix://$socket_path", -1, $errno, $errstr, 5);
        
        if (!$fp) {
            echo json_encode(['status' => 'error', 'msg' => "Falha no Socket do Go: $errstr"]);
            exit;
        }
        
        fwrite($fp, $payload . "\n");
        $resposta_daemon = stream_get_contents($fp);
        fclose($fp);
        
        // Formata a resposta do Go para o Frontend do MK-Auth
        $resp = json_decode($resposta_daemon, true);
        if (isset($resp['ok']) && $resp['ok'] === true) {
            echo json_encode([
                'status' => 'ok',
                'ip'     => $resp['data']['ip'],
                'metodo' => $resp['data']['metodo'],
                'user'   => $resp['data']['user']
            ]);
        } else {
            echo json_encode([
                'status' => 'error',
                'msg'    => $resp['message'] ?? 'Falha desconhecida no Go Daemon',
                'debug'  => $resp['data']['debug'] ?? []
            ]);
        }
        exit;
    }

    // =========================================================================
    // EXECUTAR OTP: INJEÇÃO DIRETA VIA SSH NO MIKROTIK
    // =========================================================================
    if ($acao === 'executar_otp_unitario') {
        header('Content-Type: application/json');
        $id_nas = isset($_POST['id_nas']) ? (int)$_POST['id_nas'] : 0;
        if ($id_nas <= 0) {
			echo json_encode(['status' => 'error', 'msg' => 'ID do NAS inválido.']);
			exit;
		}
		
        $q = $mysqli->query("
            SELECT n.nasname, n.ipfall, n.portassh, n.senha,
                   w.id as id_wg, w.peer_name, w.config_text, w.ip_wg
            FROM nas n
            JOIN wg_ramais w ON w.id_nas = n.id
            WHERE n.id = $id_nas
            LIMIT 1
        ");
        
        if (!$q || $q->num_rows === 0) {
            echo json_encode(['status' => 'error', 'msg' => 'NAS sem túnel provisionado.']);
            exit;
        }
        
        $row = $q->fetch_assoc();
        
        if (empty($row['config_text'])) {
            echo json_encode(['status' => 'error', 'msg' => 'Configuração .conf ausente no BD.']);
            exit;
        }
        
		$safe_name = preg_replace('/[^a-zA-Z0-9_-]+/', '_', $row['peer_name']) ?: 'peer';
		$rsc = wg_gerar_script_mikrotik(
			$row['config_text'],
			(int)$id_nas,
			(int)$row['id_wg'],
			$safe_name
		);
        
        // --- MANDAR PRO DAEMON GO ---
        $ips_to_test = [];
        if (!empty(trim($row['nasname']))) $ips_to_test[] = trim($row['nasname']);
        if (!empty(trim($row['ipfall']))) $ips_to_test[] = trim($row['ipfall']);
        $ips_to_test = array_unique($ips_to_test);
        
        $payload = json_encode([
            'action' => 'executar-otp',
            'ips'    => array_values($ips_to_test),
            'port'   => !empty($row['portassh']) ? (int)$row['portassh'] : 22,
            'pass'   => trim($row['senha']),
            'user'   => 'mkauth',
            'script' => $rsc
        ]);
        
        // Conexão com o Daemon - Voltando pro fsockopen que sabemos que funciona!
        $fp = @fsockopen("unix:///run/wgmkauth.sock", -1, $errno, $errstr, 5);
        if (!$fp) { echo json_encode(['status' => 'error', 'msg' => "Falha Socket Go"]); exit; }
        
        fwrite($fp, $payload . "\n");
        $resposta = json_decode(stream_get_contents($fp), true);
        fclose($fp);
        
        // --- RELATÓRIO DE AUDITORIA BLINDADO (Estilo Terminal) ---
        if (isset($resposta['ok']) && $resposta['ok'] === true) {
            
            $rsc_seguro = $rsc ?? '';
            $qtd_linhas = count(explode("\n", trim($rsc_seguro)));
            
            $ip_usado = $resposta['data']['ip'] ?? 'Desconhecido';
            $metodo   = isset($resposta['data']['metodo']) ? strtoupper($resposta['data']['metodo']) : 'SSH';
            
            $ipfall_seguro = isset($row['ipfall']) ? trim($row['ipfall']) : '';
            $tipo_ip = ($ip_usado === $ipfall_seguro && $ipfall_seguro !== '') ? 'IP Fallback' : 'IP Túnel';

            // Monta o visual em HTML (Estilo Terminal Hacker)
            $msg_html  = "<div style='padding-left: 15px; margin-top: 5px; color: #cbd5e1; font-family: monospace; font-size: 0.9em; line-height: 1.5;'>";
            $msg_html .= "<span style='color: #38bdf8;'>❯</span> <b>Ramal:</b> {$row['peer_name']}<br>";
            $msg_html .= "<span style='color: #38bdf8;'>❯</span> <b>Conexão:</b> {$tipo_ip} (<span style='color: #fbbf24;'>{$ip_usado}</span>)<br>";
            $msg_html .= "<span style='color: #38bdf8;'>❯</span> <b>Método:</b> Injeção via {$metodo}<br>";
            $msg_html .= "<span style='color: #4ade80;'>✔</span> <span style='color: #94a3b8;'>Script idempotente de {$qtd_linhas} linhas processado.</span>";
            $msg_html .= "</div>";

            echo json_encode([
                'status'   => 'ok',
                'msg_html' => $msg_html
            ]);
        } else {
            echo json_encode(['status' => 'error', 'msg' => $resposta['message'] ?? 'Falha RB', 'debug' => $resposta['data']['debug'] ?? []]);
        }
        exit;
    }

    // =========================================================================
    // RADAR LIVE STATS - Retorna tráfego e Status em tempo real para o JS
    // =========================================================================
    if ($acao === 'get_live_stats') {
        header('Content-Type: application/json');
        
        // Faz a chamada no socket usando o caminho que você confirmou
        $resp = wg_call(['action' => 'list-clients'], '/run/wgmkauth.sock');
        
        if (!empty($resp['ok']) && !empty($resp['data']['clients'])) {
            $dados_limpos = [];
            $agora = time(); // Pega a hora exata de agora no PHP
            
            foreach ($resp['data']['clients'] as $c) {
                $pk = $c['publicKey'] ?? '';
                if ($pk !== '') {
                    
                    // Pega a data exata que o Go devolveu no seu teste
                    $handshake_str = $c['latestHandshakeAt'] ?? '';
                    $handshake_ts = 0;
                    $is_online = false; // Começa assumindo que está offline
                    
                    // O Go manda a data com "Z" no final (UTC). O PHP entende isso nativamente.
                    if (!empty($handshake_str) && $handshake_str !== '0001-01-01T00:00:00Z') {
                        $handshake_ts = strtotime($handshake_str);
                        
                        // A MÁGICA ACONTECE AQUI:
                        // Se o último aperto de mão foi há menos de 180 segundos (3 minutos),
                        // o PHP define que o cliente está ONLINE!
                        if ($handshake_ts > 0 && ($agora - $handshake_ts) <= 180) {
                            $is_online = true;
                        }
                    }
                    
                    // Empacota tudo e CRIA a variável "online" para o JavaScript ler
                    $dados_limpos[$pk] = [
                        'rx'        => (int)($c['transferRx'] ?? 0),
                        'tx'        => (int)($c['transferTx'] ?? 0),
                        'endpoint'  => $c['endpoint'] ?? '',
                        'handshake' => $handshake_ts,
                        'online'    => $is_online // <-- Aqui o PHP manda o true/false pro JS!
                    ];
                }
            }
            // Devolve pro JS o JSON mastigadinho
            echo json_encode(['status' => 'ok', 'peers' => $dados_limpos]);
        } else {
            echo json_encode(['status' => 'error']);
        }
        exit;
    }
    // =========================================================================
    // CHECK TUNNEL UNITÁRIO (Ping Assíncrono para o JS)
    // =========================================================================
    if ($acao === 'check_tunnel_unitario') {
        header('Content-Type: application/json');
        
        $target_ip = trim($_POST['target_ip'] ?? '');
        if (empty($target_ip)) {
            echo json_encode(['ok' => false, 'error' => 'IP não fornecido']);
            exit;
        }

        // Bate no Daemon Go
        $resp = wg_call([
            'action' => 'check-tunnel',
            'target_ip' => $target_ip
        ], '/run/wgmkauth.sock');

        echo json_encode($resp);
        exit;
    }

    // ------------------------------------------------------------------
    // salvar_nat: Configura o IP Global e atualiza os .conf
    // ------------------------------------------------------------------
    if ($acao === 'salvar_nat') {
        $ip_nat = trim($_POST['ip_nat'] ?? '');

        if ($ip_nat === '') {
            // PASSO 1: O cara limpou o campo. Zera a coluna no banco inteiro.
            $mysqli->query("UPDATE wg_ramais SET endpoint = NULL");
            $_SESSION['wg_msg_sucesso'] = "✅ Configuração removida. Retornado para Detecção Automática de IP.";
            
            // Nota: Quando remove, não precisamos mexer nos .conf existentes, 
            // eles continuam com o IP que estava. Os novos ramais voltarão a 
            // usar o IP detectado automaticamente.
        } else {
            // PASSO 2: VALIDAÇÃO CEGA (Regra de Ouro: Só IPv4 puro)
            if (!filter_var($ip_nat, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $_SESSION['wg_msg_erro'] = "❌ Inválido! Digite APENAS um endereço IPv4 puro (Ex: 177.10.20.30). Domínios ou portas não são permitidos.";
                header('Location: ?tab=status');
                exit;
            }

            // PASSO 3: Atualiza a coluna "endpoint" de TODO MUNDO (inclusive da Linha Mestra)
            $stmt = $mysqli->prepare("UPDATE wg_ramais SET endpoint = ?");
            $stmt->bind_param('s', $ip_nat);
            $stmt->execute();
            $stmt->close();

            // PASSO 4: MÁGICA DO PREG_REPLACE (Estilo AWK)
            // Vamos varrer todos os ramais reais e reescrever o texto do .conf
            $rs = $mysqli->query("
                SELECT id, config_text 
                FROM wg_ramais 
                WHERE wg_client_id != 'SERVER_MASTER' 
                  AND config_text IS NOT NULL 
                  AND config_text != ''
            ");
            
            if ($rs) {
                while ($row = $rs->fetch_assoc()) {
                    $id_peer = (int)$row['id'];
                    $conf    = $row['config_text'];
                    
                    // Regex cirúrgica:
                    // $1 = Captura "Endpoint = "
                    // [^:]+ = Ignora tudo até achar os dois pontos (O IP Velho)
                    // $2 = Captura ":51820" (A porta existente e o resto da linha)
                    $novo_conf = preg_replace(
                        '/^(Endpoint\s*=\s*)[^:]+(:\d+.*)$/mi', 
                        '${1}' . $ip_nat . '${2}', 
                        $conf
                    );
                    
                    // Se o regex rodou bem e o texto mudou, grava no banco
                    if ($novo_conf !== null && $novo_conf !== $conf) {
                        $stmtUp = $mysqli->prepare("UPDATE wg_ramais SET config_text = ? WHERE id = ?");
                        if ($stmtUp) {
                            $stmtUp->bind_param('si', $novo_conf, $id_peer);
                            $stmtUp->execute();
                            $stmtUp->close();
                        }
                    }
                }
                $rs->close();
            }

            $_SESSION['wg_msg_sucesso'] = "✅ IP Público fixado para: {$ip_nat}. Arquivos .conf atualizados com sucesso!";
        }
        header('Location: ?tab=status');
        exit;
    }
    // =========================================================================
    // MODAIS DE VISUALIZAÇÃO (.conf, .rsc, wgimport string)
    // =========================================================================
    if (in_array($acao, ['show_conf', 'show_rsc', 'show_wgstring'])) {
        $id = isset($_POST['id_peer']) ? (int)$_POST['id_peer'] : 0;
    
        if ($id > 0) {
            $stmt = $mysqli->prepare("SELECT peer_name, config_text, id_nas, ip_wg FROM wg_ramais WHERE id = ? LIMIT 1");
            if ($stmt) {
                $stmt->bind_param('i', $id);
                $stmt->execute();
                $stmt->bind_result($peer_name, $config_text, $id_nas, $ip_wg);
    
                if ($stmt->fetch() && $config_text !== null && $config_text !== '') {
                    $safe_name = preg_replace('/[^a-zA-Z0-9_-]+/', '_', $peer_name) ?: 'peer';
    
                    if ($acao === 'show_conf') {
                        $_SESSION['wg_last_conf'] = $config_text;
    
                    } elseif ($acao === 'show_wgstring') {
                        // Certifique-se de que a função normalizar_conf_para_wg_import está acessível aqui
                        $wg_string_cmd = normalizar_conf_para_wg_import($config_text);
                        $wg_string_cmd .= "\n\n# ATENÇÃO: após importar, crie a rota estática para o servidor\n";
                        $wg_string_cmd .= "# /ip route add dst-address=<SERVER_IP>/32 gateway=<WG_INTERFACE>\n";
                        $_SESSION['wg_last_wgstring'] = $wg_string_cmd;
    
                    } elseif ($acao === 'show_rsc') {
                        $_SESSION['wg_last_rsc'] = wg_gerar_script_mikrotik($config_text, (int)$id_nas, (int)$id, $safe_name);
                    }
                }
                $stmt->close();
            }
        }
    
        // Sempre volta pra aba peers após preencher a sessão do modal
        header('Location: ?tab=peers');
        exit;
    }

    // ------------------------------------------------------------------
    // download_snapshot: baixar snapshot COMPLETO (JSON: conf + banco)
    // ------------------------------------------------------------------
    if ($acao === 'download_snapshot' && isset($_POST['snapshot_index'])) {
        $idx = (int) $_POST['snapshot_index'];

        $rs = $mysqli->query(
            "SELECT interface_text FROM wg_ramais WHERE interface_text IS NOT NULL AND interface_text != '' LIMIT 1"
        );

        $snapshots = [];
        if ($rs && ($r = $rs->fetch_assoc()) && !empty($r['interface_text'])) {
            $snapshots = json_decode($r['interface_text'], true) ?: [];
        }

        if (isset($snapshots[$idx]) && !empty($snapshots[$idx]['conf'])) {
            $snap = $snapshots[$idx];
            $at   = preg_replace('/[^0-9\-]/', '_', $snap['at'] ?? 'unknown');

            header('Content-Type: application/json; charset=utf-8');
            header('Content-Disposition: attachment; filename="wg_snapshot_' . $at . '.json"');
            echo json_encode($snap, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            exit;
        }

        $_SESSION['wg_msg_erro'] = "Snapshot #" . ($idx + 1) . " não encontrado para download.";
        header('Location: ?tab=status');
        exit;
    }
    // ------------------------------------------------------------------
    // create_snapshot: criar backup manual do estado atual
    // ------------------------------------------------------------------
    if ($acao === 'create_snapshot') {
        // Chama a função nativa que já existe no topo do seu arquivo
        $ok = wg_snapshot_interface($mysqli, $socketPath, 'backup_manual_usuario');
        
        if ($ok) {
            $_SESSION['wg_msg_sucesso'] = "✅ Backup manual criado com sucesso!";
        } else {
            $_SESSION['wg_msg_erro'] = "❌ Falha ao criar o backup manual.";
        }
        
        header('Location: ?tab=status');
        exit;
    }
    // ------------------------------------------------------------------
    // import_backup_file: importar snapshot JSON (conf + banco completo)
    // Aceita SOMENTE .json exportado pelo sistema. Rejeita .conf puro.
    // ------------------------------------------------------------------
    if ($acao === 'import_backup_file') {

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // 1. Validar upload
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        if (!isset($_FILES['backup_conf']) || $_FILES['backup_conf']['error'] !== UPLOAD_ERR_OK) {
            $_SESSION['wg_msg_erro'] = '❌ Nenhum arquivo enviado ou erro no upload.';
            header('Location: ?tab=status');
            exit;
        }

        $tmpFile  = $_FILES['backup_conf']['tmp_name'];
        $fileName = basename($_FILES['backup_conf']['name']);
        $raw      = file_get_contents($tmpFile);

        if ($raw === false || trim($raw) === '') {
            $_SESSION['wg_msg_erro'] = '❌ Arquivo vazio ou não pôde ser lido.';
            header('Location: ?tab=status');
            exit;
        }

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // 2. Validar formato: DEVE ser JSON de snapshot
        //    Rejeita .conf puro para evitar desalinhamento
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        $jsonData = json_decode($raw, true);

        if (!is_array($jsonData) || empty($jsonData['conf']) || empty($jsonData['sql'])) {
            $_SESSION['wg_msg_erro'] = '❌ Formato inválido. Envie apenas arquivo .json exportado pelo sistema (snapshot com conf + banco). Arquivos .conf puros não são aceitos para evitar desalinhamento com o banco de dados.';
            header('Location: ?tab=status');
            exit;
        }

        $confText   = $jsonData['conf'];
        $sqlDump    = $jsonData['sql'];
        $snapPeers  = (int)($jsonData['peers'] ?? 0);
        $snapAt     = $jsonData['at'] ?? 'desconhecido';
        $snapReason = $jsonData['reason'] ?? '';

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // 3. Validar que o conf tem [Interface]
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        if (stripos($confText, '[Interface]') === false) {
            $_SESSION['wg_msg_erro'] = '❌ JSON corrompido: campo "conf" não contém [Interface] WireGuard.';
            header('Location: ?tab=status');
            exit;
        }

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // 4. Snapshot do estado atual (se houver algo)
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
		if (!empty($interface_configurada)) {
			wg_snapshot_interface($mysqli, $socketPath, 'before_import_json');
		}
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // 5. Contar peers antes
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        $rsCount    = $mysqli->query("SELECT COUNT(*) AS total FROM wg_ramais");
        $peersAntes = ($rsCount && ($rc = $rsCount->fetch_assoc())) ? (int)$rc['total'] : 0;

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // 6. Enviar .conf pro daemon (disco + wg-quick)
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        $resp = wg_call([
            'action' => 'restore-wg-conf',
            'conf'   => $confText,
        ], $socketPath);

        if (empty($resp['ok'])) {
            $errMsg = $resp['message'] ?? $resp['error'] ?? 'erro desconhecido';
            $_SESSION['wg_msg_erro'] = "❌ Daemon rejeitou o .conf: " . $errMsg;
            header('Location: ?tab=status');
            exit;
        }

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // 7. Restaurar banco via SQL dump
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        $mysqli->query("DELETE FROM wg_ramais");

        $sqlOk     = true;
        $sqlErrors = [];

        $mysqli->multi_query($sqlDump);

        do {
            if ($result = $mysqli->store_result()) {
                $result->free();
            }
            if ($mysqli->errno) {
                $sqlOk       = false;
                $sqlErrors[] = $mysqli->error;
            }
        } while ($mysqli->next_result());

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // 8. Contar peers depois
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        $rsCount     = $mysqli->query("SELECT COUNT(*) AS total FROM wg_ramais");
        $peersDepois = ($rsCount && ($rc = $rsCount->fetch_assoc())) ? (int)$rc['total'] : 0;

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // 9. Conferência: WireGuard runtime vs banco
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        $warnings = [];

        $respList = wg_call(['action' => 'list-clients'], $socketPath);
        $wgPeers  = [];
        if (!empty($respList['ok']) && !empty($respList['data'])) {
            $clientList = $respList['data']['clients'] ?? $respList['data'];
            if (is_array($clientList)) {
                foreach ($clientList as $c) {
                    $pk = $c['publicKey'] ?? $c['public_key'] ?? '';
                    if ($pk !== '') {
                        $wgPeers[$pk] = true;
                    }
                }
            }
        }

        $dbPeers = [];
        $rsCheck = $mysqli->query("SELECT public_key FROM wg_ramais WHERE status = 'enabled'");
        if ($rsCheck) {
            while ($row = $rsCheck->fetch_assoc()) {
                if (!empty($row['public_key'])) {
                    $dbPeers[$row['public_key']] = true;
                }
            }
            $rsCheck->close();
        }

        $onlyInWg = array_diff_key($wgPeers, $dbPeers);
        $onlyInDb = array_diff_key($dbPeers, $wgPeers);

        if (count($onlyInWg) > 0) {
            $warnings[] = count($onlyInWg) . " peer(s) no WireGuard mas ausente(s) no banco";
        }
        if (count($onlyInDb) > 0) {
            $warnings[] = count($onlyInDb) . " peer(s) no banco mas ausente(s) no WireGuard";
        }

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // 10. Mensagem
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        $msgParts   = [];
        $msgParts[] = "✅ Snapshot JSON importado com sucesso!";
        $msgParts[] = "📁 Arquivo: {$fileName}";
        $msgParts[] = "📅 Snapshot original: {$snapAt}" . ($snapReason ? " ({$snapReason})" : '');
        $msgParts[] = "📊 Banco: {$peersAntes} antes → {$peersDepois} agora (snapshot tinha {$snapPeers})";

        if ($sqlOk) {
            $msgParts[] = "💾 SQL executado sem erros";
        } else {
            $msgParts[] = "❌ Erros no SQL: " . implode(' | ', $sqlErrors);
        }

        if (empty($warnings)) {
            $msgParts[] = "🔒 Conferência: banco e WireGuard 100% sincronizados";
        } else {
            $msgParts[] = "⚠️ " . implode(' | ', $warnings);
        }

        $msgParts[] = "🔑 Nomes, IPs, id_nas, configs — tudo restaurado do snapshot!";

        $msgFinal = implode("\n", $msgParts);

        if ($sqlOk && empty($warnings)) {
            $_SESSION['wg_msg_sucesso'] = $msgFinal;
        } elseif (!$sqlOk) {
            $_SESSION['wg_msg_erro'] = $msgFinal;
        } else {
            $_SESSION['wg_msg_sucesso'] = $msgFinal;
        }

        // Log
        file_put_contents(
            '/tmp/wg_import_backup.debug',
            date('c') . " IMPORT_JSON file={$fileName} snapAt={$snapAt}"
            . " antes={$peersAntes} depois={$peersDepois} snapPeers={$snapPeers}"
            . " sqlOk=" . ($sqlOk ? 'true' : 'false')
            . " warnings=" . json_encode($warnings) . "\n",
            FILE_APPEND
        );

        header('Location: ?tab=status');
        exit;
    }
	// ------------------------------------------------------------------
	// restore_snapshot: restaurar wg0.conf + banco via SQL bruto + conferir
	// ------------------------------------------------------------------
	if ($acao === 'restore_snapshot' && isset($_POST['snapshot_index'])) {
		$idx = (int) $_POST['snapshot_index'];

		// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
		// 1. Buscar o snapshot solicitado
		// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
		$rs = $mysqli->query(
			"SELECT interface_text FROM wg_ramais WHERE interface_text IS NOT NULL AND interface_text != '' LIMIT 1"
		);

		$snapshots = [];
		if ($rs && ($r = $rs->fetch_assoc()) && !empty($r['interface_text'])) {
			$snapshots = json_decode($r['interface_text'], true) ?: [];
		}

		if (!isset($snapshots[$idx]) || empty(trim($snapshots[$idx]['conf'] ?? ''))) {
			$_SESSION['wg_msg_erro'] = "Snapshot #" . ($idx + 1) . " não encontrado ou vazio.";
			header('Location: ?tab=status');
			exit;
		}

		$snapshot  = $snapshots[$idx];
		$conf      = $snapshot['conf'];
		$sqlDump   = $snapshot['sql'] ?? '';
		$snapPeers = (int)($snapshot['peers'] ?? 0);

		// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
		// 2. Validação: snapshot tem SQL?
		// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
		if ($sqlDump === '') {
			$_SESSION['wg_msg_erro'] = "❌ Snapshot #" . ($idx + 1) . " não contém dump SQL (snapshot antigo, anterior à atualização). Restauração cancelada.";
			header('Location: ?tab=status');
			exit;
		}

		// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
		// 3. Guardar snapshots em memória ANTES de limpar
		//    (senão perdemos o interface_text)
		// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
		$snapshotsJson = json_encode($snapshots, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

		// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
		// 4. SNAPSHOT do estado ATUAL (antes de restaurar)
		// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
		wg_snapshot_interface($mysqli, $socketPath, 'before_restore_snapshot_' . ($idx + 1));

		// Recarrega os snapshots atualizados (agora com o novo snapshot pré-restore)
		$rsSnap = $mysqli->query(
			"SELECT interface_text FROM wg_ramais WHERE interface_text IS NOT NULL AND interface_text != '' LIMIT 1"
		);
		if ($rsSnap && ($rSnap = $rsSnap->fetch_assoc()) && !empty($rSnap['interface_text'])) {
			$snapshotsJson = $rSnap['interface_text'];
		}

		// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
		// 5. Contar peers ANTES (pra mensagem)
		// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
		$rsCount    = $mysqli->query("SELECT COUNT(*) AS total FROM wg_ramais");
		$peersAntes = ($rsCount && ($rc = $rsCount->fetch_assoc())) ? (int)$rc['total'] : 0;

		// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
		// 6. Restaurar o .conf via daemon (disco + wg-quick)
		// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
		$resp = wg_call([
			'action' => 'restore-wg-conf',
			'conf'   => $conf,
		], $socketPath);

		file_put_contents(
			'/tmp/wg_restore_snapshot.debug',
			date('c') . " RESTORE idx={$idx} at={$snapshot['at']} RESP=" . var_export($resp, true) . "\n",
			FILE_APPEND
		);

		if (empty($resp['ok'])) {
			$errMsg = $resp['message'] ?? $resp['error'] ?? 'erro desconhecido';
			$_SESSION['wg_msg_erro'] = "❌ Falha ao restaurar .conf no daemon: " . $errMsg;
			header('Location: ?tab=status');
			exit;
		}

		// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
		// 7. RESTAURAR O BANCO: limpa + executa SQL bruto
		// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
		$mysqli->query("DELETE FROM wg_ramais");
		$deletados = $mysqli->affected_rows;

		$sqlOk     = true;
		$sqlErrors = [];

		if ($sqlDump !== '') {
			$mysqli->multi_query($sqlDump);

			do {
				if ($result = $mysqli->store_result()) {
					$result->free();
				}
				if ($mysqli->errno) {
					$sqlOk       = false;
					$sqlErrors[] = $mysqli->error;
				}
			} while ($mysqli->next_result());
		}

		// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
		// 8. Restaurar os snapshots no interface_text
		//    (foram perdidos no DELETE)
		// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
		$stmtSnap = $mysqli->prepare("UPDATE wg_ramais SET interface_text = ?");
		if ($stmtSnap) {
			$stmtSnap->bind_param('s', $snapshotsJson);
			$stmtSnap->execute();
			$stmtSnap->close();
		}

		// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
		// 9. Contar peers DEPOIS
		// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
		$rsCount     = $mysqli->query("SELECT COUNT(*) AS total FROM wg_ramais");
		$peersDepois = ($rsCount && ($rc = $rsCount->fetch_assoc())) ? (int)$rc['total'] : 0;

		// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
		// 10. CONFERÊNCIA: WireGuard runtime vs banco
		// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
		$warnings = [];

		// 10a) Peers ativos no WireGuard
		$respList = wg_call(['action' => 'list-clients'], $socketPath);
		$wgPeers  = [];
		if (!empty($respList['ok']) && !empty($respList['data'])) {
			$clientList = $respList['data']['clients'] ?? $respList['data'];
			if (is_array($clientList)) {
				foreach ($clientList as $c) {
					$pk = $c['publicKey'] ?? $c['public_key'] ?? '';
					if ($pk !== '') {
						$wgPeers[$pk] = true;
					}
				}
			}
		}

		// 10b) Peers enabled no banco
		$dbPeers = [];
		$rsCheck = $mysqli->query("SELECT public_key FROM wg_ramais WHERE status = 'enabled'");
		if ($rsCheck) {
			while ($row = $rsCheck->fetch_assoc()) {
				if (!empty($row['public_key'])) {
					$dbPeers[$row['public_key']] = true;
				}
			}
			$rsCheck->close();
		}

		// 10c) Comparação
		$onlyInWg = array_diff_key($wgPeers, $dbPeers);
		$onlyInDb = array_diff_key($dbPeers, $wgPeers);

		if (count($onlyInWg) > 0) {
			$warnings[] = count($onlyInWg) . " peer(s) no WireGuard mas ausente(s) no banco";
		}
		if (count($onlyInDb) > 0) {
			$warnings[] = count($onlyInDb) . " peer(s) no banco mas ausente(s) no WireGuard";
		}

		// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
		// 11. MENSAGEM NA CARA DO OPERADOR
		// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
		$msgParts = [];
		$msgParts[] = "✅ Backup #" . ($idx + 1) . " de {$snapshot['at']} restaurado!";
		$msgParts[] = "📊 Banco: {$peersAntes} peers antes → {$peersDepois} peers agora (snapshot tinha {$snapPeers})";

		if ($sqlOk) {
			$msgParts[] = "💾 SQL bruto executado sem erros";
		} else {
			$msgParts[] = "❌ Erros no SQL: " . implode(' | ', $sqlErrors);
		}

		if (empty($warnings)) {
			$msgParts[] = "🔒 Conferência: banco e WireGuard 100% sincronizados";
		} else {
			$msgParts[] = "⚠️ " . implode(' | ', $warnings);
		}

		$msgFinal = implode("\n", $msgParts);

		// Log completo
		file_put_contents(
			'/tmp/wg_restore_snapshot.debug',
			date('c') . " RESTORE COMPLETO idx={$idx}"
			. " antes={$peersAntes} depois={$peersDepois} snapPeers={$snapPeers}"
			. " sqlOk=" . ($sqlOk ? 'true' : 'false')
			. " warnings=" . json_encode($warnings)
			. " sqlErrors=" . json_encode($sqlErrors) . "\n",
			FILE_APPEND
		);

		// Sucesso ou erro?
		if ($sqlOk && empty($warnings)) {
			$_SESSION['wg_msg_sucesso'] = $msgFinal;
		} elseif (!$sqlOk) {
			$_SESSION['wg_msg_erro'] = $msgFinal;
		} else {
			$_SESSION['wg_msg_sucesso'] = $msgFinal;
		}

		header('Location: ?tab=status');
		exit;
	}

    // ------------------------------------------------------------------
    // server-up / server-down: controlar wg-quick via daemon
    // ------------------------------------------------------------------
    if ($acao === 'server-up' || $acao === 'server-down') {
        $resp = wg_call(['action' => $acao], $socketPath);

        file_put_contents(
            '/tmp/wg_server_control.debug',
            date('c') . " SERVER_CTRL ACAO={$acao} RESP=" . var_export($resp, true) . "\n",
            FILE_APPEND
        );

        if (!empty($resp['ok'])) {
            $_SESSION['wg_msg_sucesso'] = ($acao === 'server-up')
                ? 'Interface WireGuard ligada com sucesso.'
                : 'Interface WireGuard desligada com sucesso.';
        } else {
            $msg = $resp['message'] ?? ($resp['error'] ?? 'erro desconhecido');
            $_SESSION['wg_msg_erro'] = 'Falha ao ' .
                ($acao === 'server-up' ? 'ligar' : 'desligar') .
                " a interface: {$msg}";
        }

        header('Location: ?tab=status');
        exit;
    }

    // ------------------------------------------------------------------
    // create_server: criar a interface wg0 via daemon
    // (NÃO precisa snapshot — wg0.conf não existe ainda)
    // ------------------------------------------------------------------
    if ($acao === 'create_server') {
        $netv4      = isset($_POST['wg_network_v4']) ? trim($_POST['wg_network_v4']) : '';
        $listenPort = isset($_POST['wg_port']) ? (int)$_POST['wg_port'] : 0;

        if (!isValidIPv4Cidr($netv4)) {
            $_SESSION['wg_msg_erro'] = 'IPv4/CIDR inválido. Ex.: 10.66.66.1/24.';
            header('Location: ?tab=status');
            exit;
        }

        [$ipOnly, $cidrStr] = explode('/', $netv4, 2);

        if (!ctype_digit($cidrStr)) {
            $_SESSION['wg_msg_erro'] = 'CIDR inválido.';
            header('Location: ?tab=status');
            exit;
        }
        $cidr = (int)$cidrStr;

        $ipLong = ip2long($ipOnly);
        if ($ipLong === false) {
            $_SESSION['wg_msg_erro'] = 'IP inválido no Address informado.';
            header('Location: ?tab=status');
            exit;
        }

        $maskLong = ($cidr === 0) ? 0 : ((-1 << (32 - $cidr)) & 0xFFFFFFFF);
        $netLong  = $ipLong & $maskLong;

        $broadcastLong = null;
        if ($cidr >= 1 && $cidr <= 30) {
            $invMask       = (~$maskLong) & 0xFFFFFFFF;
            $broadcastLong = $netLong | $invMask;
        }

        if ($cidr <= 30 && $ipLong === $netLong) {
            $_SESSION['wg_msg_erro'] = 'Address não pode ser o endereço de rede. Use um IP de host dentro da rede (ex.: 10.66.66.1/' . $cidr . ').';
            header('Location: ?tab=status');
            exit;
        }

        if ($broadcastLong !== null && $ipLong === $broadcastLong) {
            $_SESSION['wg_msg_erro'] = 'Address não pode ser o broadcast da rede. Use um IP de host dentro da rede.';
            header('Location: ?tab=status');
            exit;
        }

        if (preg_match('/^(127\.|169\.254\.)/', $ipOnly)) {
            $_SESSION['wg_msg_erro'] = 'Address inválido (loopback/link-local). Use uma rede privada RFC1918.';
            header('Location: ?tab=status');
            exit;
        }

        if ($listenPort < 1 || $listenPort > 65535) {
            $_SESSION['wg_msg_erro'] = 'Porta inválida (1-65535).';
            header('Location: ?tab=status');
            exit;
        }

        $payload = [
            'action' => 'server-create',
            'wgIPv4' => $netv4,
            'wgPort' => $listenPort,
        ];

        $resp = wg_call($payload, $socketPath);

        file_put_contents(
            '/tmp/wg_server_create.debug',
            date('c') . ' CREATE_SERVER PAYLOAD=' . json_encode($payload) .
            ' RESP=' . var_export($resp, true) . "\n",
            FILE_APPEND
        );

        if (empty($resp['ok'])) {
            $msg = $resp['message'] ?? ($resp['error'] ?? 'erro desconhecido');
            $_SESSION['wg_msg_erro'] = 'Falha ao criar interface wg0: ' . $msg;
        } else {
            // ==============================================================
            // A VONTADE DO CHEFE: CRIAR A LINHA MESTRA DA INTERFACE NO BANCO
            // ==============================================================
            // Essa linha garante que a tabela nunca fique vazia. 
            // Ela vai guardar o endpoint (IP Forçado) e o interface_text (Snapshots)
            $mysqli->query("
                INSERT INTO wg_ramais (
                    id_nas, wg_client_id, peer_name, ip_wg, public_key, 
                    allowed_ips, status, provisionado_em, atualizado_em
                ) VALUES (
                    0, 'SERVER_MASTER', 'INTERFACE_WG0', '{$netv4}', 'MASTER_KEY_SYSTEM', 
                    '{$netv4}', 'system', NOW(), NOW()
                )
            ");
            
            $_SESSION['wg_msg_sucesso'] = 'Interface wg0 criada e iniciada com sucesso. Registro Mestre criado no banco!';
        }

        header('Location: ?tab=status');
        exit;
    } // Fim create_server

    // ------------------------------------------------------------------
    // reset_server: recria wg0.conf do zero com novos parâmetros
    // ⚡ SNAPSHOT ANTES
    // ------------------------------------------------------------------
    if ($acao === 'reset_server') {
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // SNAPSHOT antes de destruir tudo
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        wg_snapshot_interface($mysqli, $socketPath, 'before_server_reset');

        $netv4_reset = isset($_POST['wg_network_v4_reset']) ? trim($_POST['wg_network_v4_reset']) : '';
        $port_reset  = isset($_POST['wg_port_reset']) ? (int)$_POST['wg_port_reset'] : 0;

        if ($netv4_reset !== '' && !isValidIPv4Cidr($netv4_reset)) {
            $_SESSION['wg_msg_erro'] = 'IPv4/CIDR inválido. Ex.: 10.66.66.1/24.';
            header('Location: ?tab=status');
            exit;
        }

        if ($netv4_reset !== '') {
            [$ipOnly, $cidrStr] = explode('/', $netv4_reset, 2);

            if (!ctype_digit($cidrStr)) {
                $_SESSION['wg_msg_erro'] = 'CIDR inválido.';
                header('Location: ?tab=status');
                exit;
            }
            $cidr = (int)$cidrStr;

            $ipLong = ip2long($ipOnly);
            if ($ipLong === false) {
                $_SESSION['wg_msg_erro'] = 'IP inválido no Address informado.';
                header('Location: ?tab=status');
                exit;
            }

            $maskLong = ($cidr === 0) ? 0 : ((-1 << (32 - $cidr)) & 0xFFFFFFFF);
            $netLong  = $ipLong & $maskLong;

            $broadcastLong = null;
            if ($cidr >= 1 && $cidr <= 30) {
                $invMask = (~$maskLong) & 0xFFFFFFFF;
                $broadcastLong = $netLong | $invMask;
            }

            if ($cidr <= 30 && $ipLong === $netLong) {
                $_SESSION['wg_msg_erro'] = 'Address não pode ser o endereço de rede. Use um IP de host (ex.: 10.66.66.1/' . $cidr . ').';
                header('Location: ?tab=status');
                exit;
            }

            if ($broadcastLong !== null && $ipLong === $broadcastLong) {
                $_SESSION['wg_msg_erro'] = 'Address não pode ser o broadcast da rede.';
                header('Location: ?tab=status');
                exit;
            }

            if (preg_match('/^(127\.|169\.254\.)/', $ipOnly)) {
                $_SESSION['wg_msg_erro'] = 'Address inválido (loopback/link-local). Use uma rede privada RFC1918.';
                header('Location: ?tab=status');
                exit;
            }
        }

        if ($port_reset > 0 && ($port_reset < 1 || $port_reset > 65535)) {
            $_SESSION['wg_msg_erro'] = 'Porta inválida (1-65535).';
            header('Location: ?tab=status');
            exit;
        }

        $payload = ['action' => 'server-reset'];

        if ($port_reset > 0) {
            $payload['wgPort'] = $port_reset;
        }

        if ($netv4_reset !== '') {
            $payload['wgIPv4'] = $netv4_reset;
        }

        $resp = wg_call($payload, $socketPath);

        if (!$resp['ok']) {
            $erro = $resp['error'] ?? 'unknown';
            $msg  = $resp['message'] ?? '';
            $_SESSION['wg_msg_erro'] = "Falha ao resetar servidor: $erro - $msg";
            header('Location: ?tab=status');
            exit;
        }

        $mysqli->query("DELETE FROM wg_ramais");
        $deletados = $mysqli->affected_rows;

        // ==============================================================
        // RECRIAR A LINHA MESTRA APÓS O RESET
        // ==============================================================
        $rede_mestra = ($netv4_reset !== '') ? $netv4_reset : '0.0.0.0/0';
        $mysqli->query("
            INSERT INTO wg_ramais (
                id_nas, wg_client_id, peer_name, ip_wg, public_key, 
                allowed_ips, status, provisionado_em, atualizado_em
            ) VALUES (
                0, 'SERVER_MASTER', 'INTERFACE_WG0', '{$rede_mestra}', 'MASTER_KEY_SYSTEM', 
                '{$rede_mestra}', 'system', NOW(), NOW()
            )
        ");

        file_put_contents(
            '/tmp/wg_server_reset.log',
            date('c') . " RESET OK: $deletados peers deletados | Rede: $netv4_reset | Porta: $port_reset\n",
            FILE_APPEND
        );

        $msgRede  = ($netv4_reset !== '') ? " Nova rede: $netv4_reset." : '';
        $msgPorta = ($port_reset > 0) ? " Porta: $port_reset." : '';

        $_SESSION['wg_msg_sucesso'] =
            "✅ Servidor WireGuard resetado com sucesso!" .
            $msgRede . $msgPorta .
            " Todos os peers foram removidos ($deletados). Reprovisione os ramais.";

        header('Location: ?tab=status');
        exit;
    }

    // ------------------------------------------------------------------
    // criar_peer: cria peer novo via socket e grava em wg_ramais (Foco VPS/Infra)
    // ⚡ SNAPSHOT ANTES
    // ------------------------------------------------------------------
    if ($acao === 'criar_peer') {
        $id_nas      = isset($_POST['id_nas']) ? (int)$_POST['id_nas'] : 0;
        $peer_name   = isset($_POST['peer_name']) ? trim($_POST['peer_name']) : '';
        $address_raw = isset($_POST['address']) ? trim($_POST['address']) : '';
        
        $address = '';
        if ($address_raw !== '') {
            // 🛑 A BRONCA DIDÁTICA: Se tem barra e NÃO é /32, bate no peito e devolve o erro!
            if (strpos($address_raw, '/') !== false && substr(trim($address_raw), -3) !== '/32') {
                $ip_sugerido = explode('/', $address_raw)[0] . '/32';
				$_SESSION['wg_msg_erro'] = "ATENÇÃO: O WireGuard exige máscara /32 para clientes no servidor (Roteamento por Chave Criptográfica). Usar máscaras como /24 causará sequestro de tráfego na rede. Por favor, utilize {$ip_sugerido}";
                header('Location: ?tab=criar');
                exit;
            }
            
            // Se chegou aqui, ou ele digitou só o IP, ou digitou certo com /32. 
            $ip_only = explode('/', $address_raw)[0];
            $address = $ip_only . '/32';
        }

        $msg_erro  = '';

        // ==========================================
        // 1. VALIDAÇÕES BÁSICAS
        // ==========================================
        if ($peer_name === '' || $address === '') {
            $msg_erro .= 'Falha na validação de campos. Nome e endereço são obrigatórios. ';
        }

        // ==========================================
        // 2. VALIDAÇÕES DE REDE (Usando suas funções nativas)
        // ==========================================
        if ($msg_erro === '') {
            if (!isValidIPv4Cidr($address)) {
                $msg_erro .= 'Endereço inválido. Use formato IPv4/CIDR, ex: 10.66.66.50/32. ';
            } else {
                [$net_ip, $net_mask] = wg_get_net_from_daemon($socketPath);
                if (!$net_ip || !$net_mask) {
                    $msg_erro .= 'Rede base da interface wg0 não encontrada no daemon. ';
                } elseif (!ipInSubnet($address, $net_ip, $net_mask)) {
                    $msg_erro .= "Endereço {$address} fora da faixa da interface wg0 ({$net_ip}/{$net_mask}). ";
                }
            }
        }

        // ==========================================
        // 3. VALIDAÇÃO DE UNICIDADE NO BANCO
        // ==========================================
        // Verifica NAS (Caso ainda seja usado no futuro, mantemos sua lógica)
        if ($msg_erro === '' && $id_nas > 0) {
            $stmtNas = $mysqli->prepare("SELECT id FROM wg_ramais WHERE id_nas = ? LIMIT 1");
            if ($stmtNas) {
                $stmtNas->bind_param('i', $id_nas);
                if (!$stmtNas->execute()) {
                    $msg_erro .= 'Erro BD (SELECT NAS): ' . $stmtNas->error;
                } else {
                    $stmtNas->store_result();
                    if ($stmtNas->num_rows > 0) {
                        $msg_erro .= 'Já existe um peer provisionado para este NAS. ';
                    }
                }
                $stmtNas->close();
            }
        }

        // Verifica Nome ou IP duplicado
        if ($msg_erro === '') {
            // 🛡️ CORREÇÃO CRÍTICA DE TABELA: Trocado 'nome' por 'peer_name'
            $stmt = $mysqli->prepare("SELECT peer_name, ip_wg FROM wg_ramais WHERE peer_name = ? OR ip_wg = ? LIMIT 1");
            if ($stmt) {
                $stmt->bind_param('ss', $peer_name, $address);
                if (!$stmt->execute()) {
                    $msg_erro .= 'Erro BD (SELECT unicidade): ' . $stmt->error;
                } else {
                    $result = $stmt->get_result();
                    if ($result->num_rows > 0) {
                        $row = $result->fetch_assoc();
                        if (strcasecmp($row['peer_name'], $peer_name) === 0) {
                            $msg_erro .= "Já existe uma conexão com o nome '{$peer_name}'. ";
                        } else {
                            $msg_erro .= "O IP '{$address}' já está sendo usado por outro servidor. ";
                        }
                    }
                }
                $stmt->close();
            } else {
                // 🛡️ CORREÇÃO DE FALHA SILENCIOSA: Se o prepare falhar, IMPEDE de mandar pro Daemon!
                $msg_erro .= 'Erro interno ao consultar o banco (validação de peer falhou): ' . $mysqli->error;
            }
        }

        // Se acumulou qualquer erro, aborta e volta pra tela de criação ANTES de chamar o Daemon
        if ($msg_erro !== '') {
            $_SESSION['wg_msg_erro'] = trim($msg_erro);
            header('Location: ?tab=criar');
            exit;
        }

        // ==============================================================
        // 4. PREPARAÇÃO E ENVIO PARA O DAEMON (wg-quick / socket)
        // ==============================================================
        
        // SNAPSHOT antes de criar o peer
        wg_snapshot_interface($mysqli, $socketPath, 'before_create_client');

        // Ler a linha 1 para injetar o NAT Forçado
        $ip_forcado_global = '';
        $rsCfg = $mysqli->query("SELECT endpoint FROM wg_ramais ORDER BY id ASC LIMIT 1");
        if ($rsCfg && $rowCfg = $rsCfg->fetch_assoc()) {
            $ip_forcado_global = trim($rowCfg['endpoint'] ?? '');
        }

        $payload = [
            'action'  => 'create-client',
            'name'    => $peer_name,
            'address' => $address,
        ];

        // Se o NAT estiver preenchido, injeta no payload
        if ($ip_forcado_global !== '') {
            $payload['endpoint'] = $ip_forcado_global;
        }

        $resp = wg_call($payload, $socketPath);

        // Debug log
        file_put_contents(
            '/tmp/wg_create_client.debug',
            date('c') . " CRIAR_PEER RESP: " . var_export($resp, true) . "\n",
            FILE_APPEND
        );

        if (empty($resp['ok']) || empty($resp['data'])) {
            $_SESSION['wg_msg_erro'] = 'Erro no Daemon (create-client): ' . ($resp['error'] ?? 'resposta inválida');
            header('Location: ?tab=criar');
            exit;
        }

        $d = $resp['data'];

        $wg_client_id    = $d['id']         ?? '';
        $public_key      = $d['publicKey']  ?? '';
        $allowed_ips     = $d['allowedIPs'] ?? $address;
        $persistent_keep = isset($d['persistentKeepalive']) ? (int)$d['persistentKeepalive'] : null;

        $config_text = '';
        if (!empty($d['config'])) {
            $config_text = str_replace("\\n", PHP_EOL, $d['config']);
        }

        if ($wg_client_id === '' || $public_key === '') {
            $_SESSION['wg_msg_erro'] = 'Daemon retornou resposta incompleta (sem id ou publicKey).';
            header('Location: ?tab=criar');
            exit;
        }

        // ==============================================================
        // 5. SALVAR NO BANCO DE DADOS
        // ==============================================================
        $stmtIns = $mysqli->prepare("
            INSERT INTO wg_ramais (
                id_nas, wg_client_id, peer_name, ip_wg, public_key, 
                allowed_ips, persistent_keepalive, config_text, 
                downloadable_config, status, provisionado_em, atualizado_em,
                endpoint
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 'enabled', NOW(), NOW(), ?)
        ");
        
        if (!$stmtIns) {
            $_SESSION['wg_msg_erro'] = 'Erro prepare INSERT: ' . $mysqli->error;
            header('Location: ?tab=criar');
            exit;
        }

        $stmtIns->bind_param(
            'isssssiss',
            $id_nas,
            $wg_client_id,
            $peer_name,
            $address,
            $public_key,
            $allowed_ips,
            $persistent_keep,
            $config_text,
            $ip_forcado_global
        );

        if ($stmtIns->execute()) {
            $_SESSION['wg_msg_sucesso'] = "✅ Servidor '{$peer_name}' configurado com sucesso!";
            $stmtIns->close();
            header('Location: ?tab=peers');
            exit;
        } else {
            $_SESSION['wg_msg_erro'] = 'Erro ao salvar no BD: ' . $stmtIns->error;
            $stmtIns->close();
            header('Location: ?tab=criar');
            exit;
        }
    }

    // ------------------------------------------------------------------
    // editar_peer: salvar IP (address) dos peers selecionados
    // ------------------------------------------------------------------
    if ($acao === 'editar_peer') {
        $subacao = isset($_POST['subacao']) ? trim($_POST['subacao']) : '';
        if ($subacao !== 'address') {
            $msg_erro .= 'Subação inválida.';
        } else {
            $peer_ids = isset($_POST['peer_ids']) && is_array($_POST['peer_ids'])
                ? array_map('intval', $_POST['peer_ids'])
                : [];

            if (!$peer_ids) {
                $msg_erro .= 'Nenhum peer selecionado.';
            } else {
                
                wg_snapshot_interface($mysqli, $socketPath, 'before_update_address');
                
                $msg_extra = '';
				
                foreach ($peer_ids as $id_peer) {
                    $address_raw = isset($_POST['address_inline'][$id_peer]) ? trim($_POST['address_inline'][$id_peer]) : '';
                    $address = '';
                    
                    if ($address_raw !== '') {
                        if (strpos($address_raw, '/') !== false && substr(trim($address_raw), -3) !== '/32') {
                            $msg_erro .= "⚠️ Aviso Peer ID {$id_peer}: O WireGuard funciona apenas com IPs exclusivos por peer (/32). ";
                            continue;
                        }
                        $ip_only = explode('/', $address_raw)[0];
                        $address = $ip_only . '/32';
                    }

                    if ($address === '') {
                        $msg_erro .= "Endereço vazio para o peer ID {$id_peer}. ";
                        continue;
                    }

                    if (!isValidIPv4Cidr($address)) {
                        $msg_erro .= "Endereço inválido para o peer ID {$id_peer}. Use IPv4/CIDR. ";
                        continue;
                    }

                    $stmt = $mysqli->prepare("SELECT public_key, ip_wg, config_text, status, id_nas FROM wg_ramais WHERE id = ? LIMIT 1");
                    if (!$stmt) { $msg_erro .= 'Erro prepare SELECT peer: ' . $mysqli->error; continue; }
                    $stmt->bind_param('i', $id_peer);
                    $stmt->execute();
                    $res = $stmt->get_result();
                    $row = $res->fetch_assoc();
                    $stmt->close();

                    if (!$row) { $msg_erro .= "Peer ID {$id_peer} não encontrado. "; continue; }

                    $public_key  = $row['public_key'];
                    $old_ip      = $row['ip_wg'];
                    $config_text = $row['config_text'];
                    $status      = $row['status'];
                    $id_nas      = (int)$row['id_nas'];
                    $newAllowed  = null;

                    $stmtChk = $mysqli->prepare("SELECT id FROM wg_ramais WHERE ip_wg = ? AND id <> ? LIMIT 1");
                    $stmtChk->bind_param('si', $address, $id_peer);
                    $stmtChk->execute();
                    $stmtChk->store_result();
                    if ($stmtChk->num_rows > 0) {
                        $msg_erro .= "Já existe outro peer com o endereço {$address}. ";
                        $stmtChk->close();
                        continue;
                    }
                    $stmtChk->close();

                    // BUSCA NAS NO BANCO
                    $senha = '';
                    $portassh = 22;
                    $ipfall = '';
                    
                    if ($id_nas > 0) {
                        $stmtNas = $mysqli->prepare("SELECT senha, portassh, ipfall FROM nas WHERE id = ? LIMIT 1");
                        if ($stmtNas) {
                            $stmtNas->bind_param('i', $id_nas);
                            $stmtNas->execute();
                            $resNas = $stmtNas->get_result();
                            if ($rowNas = $resNas->fetch_assoc()) {
                                $senha    = trim($rowNas['senha'] ?? '');
                                $portassh = !empty($rowNas['portassh']) ? (int)$rowNas['portassh'] : 22;
                                $ipfall   = trim($rowNas['ipfall'] ?? '');
                            }
                            $stmtNas->close();
                        }
                    }

                    // INTEGRAÇÃO COM O DAEMON GO
                    if ($status === 'enabled') {
                        $old_ip_host = explode('/', $old_ip)[0];
                        $target_ip = !empty($ipfall) ? $ipfall : $old_ip_host;

                        if (!empty($target_ip)) {
                            $payload_ssh = [
                                'action'    => 'update-mikrotik-wg-ip',
                                'target_ip' => $target_ip,
                                'port'      => $portassh,
                                'user'      => 'mkauth',
                                'pass'      => $senha,
                                'old_wg_ip' => $old_ip,  
                                'new_wg_ip' => $address  
                            ];
                            
                            $resp_ssh = wg_call($payload_ssh, $socketPath);
                            
                            // Blindagem de leitura 
                            $resp_arr = is_string($resp_ssh) ? json_decode($resp_ssh, true) : json_decode(json_encode($resp_ssh), true);
                            
                            if (is_array($resp_arr)) {
                                $go_ok = !empty($resp_arr['ok']) ? $resp_arr['ok'] : (!empty($resp_arr['OK']) ? $resp_arr['OK'] : false);
                                $go_msg = !empty($resp_arr['message']) ? $resp_arr['message'] : (!empty($resp_arr['Message']) ? $resp_arr['Message'] : '');
                            } else {
                                $go_ok = false;
                                $go_msg = 'A resposta do Go não pôde ser lida.';
                            }

                            // AQUI ESTÁ A BLINDAGEM: Limpamos TUDO que vem do Go pra não bugar a tela
                            $clean_msg = strip_tags((string)$go_msg);
                            $clean_msg = str_replace(["\r", "\n", "'", "\"", "\\"], " ", $clean_msg);

                            if (!$go_ok) {
                                $msg_extra .= "⚠️ AVISO: Atualizado no MK-Auth, mas falha ao alcançar a RB {$target_ip} (" . ($clean_msg ?: 'Erro desconhecido') . "). A alteração de endereço desse peer/ramal deve ser feita via arquivo .rsc disponível para cópia ou download. ";
                            } else {
                                $msg_extra .= "✅ " . ($clean_msg !== '' ? $clean_msg : "Atualizado na RB {$target_ip} com sucesso.") . " ";
                            }
                            
                            usleep(500000); 
                        } else {
                            $msg_extra .= "⚠️ Aviso: Atualizado no MK-Auth, mas não houve tentativa SSH pois o IP de acesso à RB é inválido! A alteração de endereço desse peer/ramal deve ser feita via arquivo .rsc disponível para cópia ou download. ";
                        }

                        // ATUALIZA O SERVIDOR WIREGUARD LOCAL (MK-AUTH)
                        $payload_wg = [
                            'action'     => 'update-client-address',
                            'publicKey'  => $public_key,
                            'allowedIPs' => $address,
                        ];
                        $resp = wg_call($payload_wg, $socketPath);

                        if (empty($resp['ok'])) {
                            $msg_erro .= "⚠️ Erro ao aplicar novo address no WireGuard local para o peer ID {$id_peer}. ";
                            continue;
                        }

                        if (!empty($resp['data']['allowedIPs'])) {
                            $newAllowed = trim($resp['data']['allowedIPs']);
                        }

                    } else {
                        // Peer desativado
                        file_put_contents('/tmp/wg_edit_address.debug', date('c') . " EDIT_ADDRESS ID {$id_peer} STATUS {$status} (SQL-only, no wg_call) PUB {$public_key} OLDADDR {$old_ip} NEWADDR {$address}\n", FILE_APPEND);
                    }

                    // MÁGICA PARA O OFFLINE
                    if (empty($newAllowed)) {
                        if (preg_match('/^AllowedIPs\s*=\s*(.+)$/mi', $config_text, $matches)) {
                            $current_allowed = trim($matches[1]);
                            $newAllowed = str_replace($old_ip, $address, $current_allowed);
                        } else {
                            $newAllowed = $address;
                        }
                    }

                    if (is_string($config_text) && $config_text !== '') {
                        $config_text = preg_replace('/^(Address\s*=\s*).+$/mi', '${1}' . $address, $config_text);
                        if (!empty($newAllowed)) {
                            $config_text = preg_replace('/^(AllowedIPs\s*=\s*).+$/mi', '${1}' . $newAllowed, $config_text);
                        }
                    }

                    // SALVA TUDO NO BANCO (wg_ramais E nas)
                    $stmtUp = $mysqli->prepare("UPDATE wg_ramais SET ip_wg = ?, allowed_ips = ?, config_text = ?, atualizado_em = NOW() WHERE id = ?");
                    if (!$stmtUp) { $msg_erro .= 'Erro prepare UPDATE address: ' . $mysqli->error; continue; }
                    $stmtUp->bind_param('sssi', $address, $newAllowed, $config_text, $id_peer);
                    if (!$stmtUp->execute()) { $msg_erro .= 'Erro ao atualizar endereço no banco: ' . $stmtUp->error; $stmtUp->close(); continue; }
                    $stmtUp->close();

                    $ipwgHost = preg_replace('~/.*$~', '', $address);
                    $stmtNasUpd = $mysqli->prepare("UPDATE nas SET nasname = ? WHERE id = ? LIMIT 1");
                    if ($stmtNasUpd) {
                        $stmtNasUpd->bind_param('si', $ipwgHost, $id_nas);
                        $stmtNasUpd->execute();
                        $stmtNasUpd->close();
                    }
                }
            }
        }

        // MOSTRA A MENSAGEM FINAL (Mantive a redundância de variáveis do MK-Auth pra não falhar a notificação)
        if ($msg_erro === '') {
            $texto_final = ($msg_extra !== '') ? trim($msg_extra) : '✅ Endereço(s) WireGuard atualizado(s) com sucesso.';
            
            $_SESSION['wg_msg_sucesso'] = $texto_final;
            $_SESSION['sucesso']        = $texto_final;
        } else {
            $_SESSION['wg_msg_erro'] = $msg_erro;
            $_SESSION['erro']        = $msg_erro;
        }

        header('Location: ?tab=peers');
        exit;
    }

    // ------------------------------------------------------------------
    // bulk_peers: enable/disable/delete em massa
    // ⚡ SNAPSHOT ANTES (uma vez, antes do loop)
    // ------------------------------------------------------------------
    if ($acao === 'bulk_peers') {
        $bulk_action = $_POST['bulk_action'] ?? '';
        $peer_ids    = isset($_POST['peer_ids']) && is_array($_POST['peer_ids'])
            ? array_map('intval', $_POST['peer_ids'])
            : [];

        if (!$peer_ids || $bulk_action === '') {
            $msg_erro .= 'Nenhum peer selecionado ou ação inválida para bulk.';
        } else {
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // SNAPSHOT antes de operação bulk
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            wg_snapshot_interface($mysqli, $socketPath, 'before_' . $bulk_action . '_client');

            $ids_in = implode(',', $peer_ids);

            $sqlSel = "
                SELECT
                    id,
                    public_key,
                    allowed_ips,
                    preshared_key,
                    persistent_keepalive
                FROM wg_ramais
                WHERE id IN ($ids_in)
            ";
            $resSel = $mysqli->query($sqlSel);
            if (!$resSel) {
                $msg_erro .= 'Erro ao carregar peers selecionados: ' . $mysqli->error;
            } else {
                $ok_count  = 0;
                $err_count = 0;

                while ($row = $resSel->fetch_assoc()) {
                    $id_row  = (int)$row['id'];
                    $pub     = $row['public_key'];
                    $allowed = $row['allowed_ips'];
                    $psk     = $row['preshared_key'];
                    $keep    = $row['persistent_keepalive'];

                    if ($pub === '') {
                        $err_count++;
                        continue;
                    }

                    if ($bulk_action === 'delete') {
                        $resp = wg_call([
                            'action'    => 'delete-client',
                            'publicKey' => $pub,
                        ], $socketPath);

                        file_put_contents(
                            '/tmp/wg_bulk_delete.debug',
                            date('c') . " DELETE ID {$id_row} PUB {$pub} RESP: " . var_export($resp, true) . "\n",
                            FILE_APPEND
                        );

                        if (!empty($resp['ok'])) {
                            $sqlDel = "DELETE FROM wg_ramais WHERE id = {$id_row}";
                            if ($mysqli->query($sqlDel)) {
                                $ok_count++;
                            } else {
                                $err_count++;
                            }
                        } else {
                            $err_count++;
                        }

                    } elseif ($bulk_action === 'disable') {
                        $resp = wg_call([
                            'action'    => 'disable-client',
                            'publicKey' => $pub,
                        ], $socketPath);

                        file_put_contents(
                            '/tmp/wg_bulk_disable.debug',
                            date('c') . " DISABLE ID {$id_row} PUB {$pub} RESP: " . var_export($resp, true) . "\n",
                            FILE_APPEND
                        );

                        if (!empty($resp['ok'])) {
                            $sqlUp = "
                                UPDATE wg_ramais
                                SET status='disabled',
                                    latest_handshake_at = NULL,
                                    transfer_rx = 0,
                                    transfer_tx = 0
                                WHERE id = {$id_row}
                            ";
                            if ($mysqli->query($sqlUp)) {
                                $ok_count++;
                            } else {
                                $err_count++;
                            }
                        } else {
                            $err_count++;
                        }

                    } elseif ($bulk_action === 'enable') {
                        $payload = [
                            'action'     => 'enable-client',
                            'publicKey'  => $pub,
                            'allowedIPs' => $allowed,
                        ];
                        if (!empty($psk)) {
                            $payload['presharedKey'] = $psk;
                        }
                        if (!empty($keep)) {
                            $payload['persistentKeepalive'] = (int)$keep;
                        }

                        $resp = wg_call($payload, $socketPath);

                        file_put_contents(
                            '/tmp/wg_bulk_enable.debug',
                            date('c') . " ENABLE ID {$id_row} PUB {$pub} ALLOWED {$allowed} RESP: " . var_export($resp, true) . "\n",
                            FILE_APPEND
                        );

                        if (!empty($resp['ok'])) {
                            $sqlUp = "UPDATE wg_ramais SET status='enabled' WHERE id = {$id_row}";
                            if ($mysqli->query($sqlUp)) {
                                $ok_count++;
                            } else {
                                $err_count++;
                            }
                        } else {
                            $err_count++;
                        }

                    } elseif ($bulk_action === 'efetivar_ip') {
                        // =========================================================
                        // NOVA AÇÃO BULK: EFETIVAR MIGRAÇÃO (ATUALIZAR TABELA NAS)
                        // =========================================================
                        
                        // 1. Precisamos saber o id_nas e o ip_wg desse peer
                        // (Podemos fazer uma query rápida aqui já que não trouxemos no SELECT principal)
                        $qNas = "SELECT id_nas, ip_wg FROM wg_ramais WHERE id = {$id_row}";
                        $resNasInfo = $mysqli->query($qNas);
                        
                        if ($resNasInfo && $rowNasInfo = $resNasInfo->fetch_assoc()) {
                            $id_nas_migrar = (int)$rowNasInfo['id_nas'];
                            $ip_wg_completo = $rowNasInfo['ip_wg'];
                            
                            if ($id_nas_migrar > 0 && !empty($ip_wg_completo)) {
                                // Limpa o IP (tira o /32)
                                $ip_limpo = explode('/', $ip_wg_completo)[0];
                                
                                // Dá o UPDATE violento na tabela principal do MK-Auth
                                $upNas = "UPDATE nas SET nasname = '{$ip_limpo}' WHERE id = {$id_nas_migrar}";
                                if ($mysqli->query($upNas)) {
                                    $ok_count++;
                                    
                                    // Log para auditoria
                                    file_put_contents(
                                        '/tmp/wg_bulk_efetivar.debug',
                                        date('c') . " EFETIVAR NAS {$id_nas_migrar} para IP {$ip_limpo} (Peer ID {$id_row})\n",
                                        FILE_APPEND
                                    );
                                } else {
                                    $err_count++;
                                }
                            } else {
                                $err_count++; // Não tem NAS atrelado ou IP vazio
                            }
                        } else {
                            $err_count++;
                        }
                    }
                } // Fim do loop while ($row = $resSel->fetch_assoc())						

                $resSel->close();

                if ($ok_count > 0) {
                    $_SESSION['wg_msg_sucesso'] =
                        "Ação em massa '{$bulk_action}' aplicada em {$ok_count} peers. Falhas: {$err_count}.";
                    header('Location: ?tab=peers');
                    exit;
                } else {
                    $msg_erro .= 'Nenhum peer foi alterado com sucesso pelo socket.';
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // provisionar_ramais: cria peers WG para vários NAS
    // ⚡ SNAPSHOT ANTES (uma vez, antes do loop)
    // ------------------------------------------------------------------
    if ($acao === 'provisionar_ramais') {
        $ramal_ids = isset($_POST['ramal_ids']) && is_array($_POST['ramal_ids'])
            ? array_map('intval', $_POST['ramal_ids'])
            : [];

        // 🎯 AQUI ESTÁ A MÁGICA: Captura exata do rádio (Força ser Inteiro)
        // Se o JS não enviar nada, assumimos 1 (Oficial) por segurança, mas se enviar 0, ele obedece!
        $atualizar_ip_nas = isset($_POST['atualizar_ip_nas']) ? (int)$_POST['atualizar_ip_nas'] : 1;

        file_put_contents(
            '/tmp/wg_flow.log',
            date('c') . " ENTROU provisionar_ramais RAMAIS=" . json_encode($ramal_ids) . " MODO_RADIO={$atualizar_ip_nas}\n",
            FILE_APPEND
        );

        if (!$ramal_ids) {
            $msg_erro .= 'Nenhum ramal (NAS) selecionado para provisionamento.';
        } else {
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            // SNAPSHOT antes de provisionar
            // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
            wg_snapshot_interface($mysqli, $socketPath, 'before_provisionar_ramais');

            $ok_count  = 0;
            $err_count = 0;

            $mode = $_POST['alloc_mode'] ?? 'seq';

            $status_data = wg_call(['action' => 'status'], $socketPath);
            $wg_base_cidr = $status_data['data']['wg_address'] ?? '';

            if ($wg_base_cidr === '' || strpos($wg_base_cidr, '/') === false) {
                $msg_erro .= 'Rede base da interface wg0 inválida ou não encontrada (wg_address). ';
            } else {
                [$net_ip, $net_mask] = explode('/', $wg_base_cidr, 2);
                $net_long = ip2long($net_ip);
                $mask     = (int)$net_mask;

                if ($net_long === false || $mask < 1 || $mask > 30) {
                    $msg_erro .= 'Máscara inválida ou fora de faixa (1 a 30) em wg_address. ';
                }
            }

            if ($msg_erro === '') {
                $used_ips = [];

                $sqlUsed = "
                    SELECT ip_wg, allowed_ips
                    FROM wg_ramais
                    WHERE ip_wg IS NOT NULL
                      AND ip_wg <> ''
                      AND (ip_wg LIKE ? OR allowed_ips LIKE ?)
                ";
                $likeNet = $net_ip . '%';
                if ($stmtUsed = $mysqli->prepare($sqlUsed)) {
                    $stmtUsed->bind_param('ss', $likeNet, $likeNet);
                    $stmtUsed->execute();
                    $resUsed = $stmtUsed->get_result();
                    while ($u = $resUsed->fetch_assoc()) {
                        foreach (['ip_wg', 'allowed_ips'] as $col) {
                            if (!empty($u[$col])) {
                                $ip = explode('/', $u[$col])[0];
                                $used_ips[$ip] = true;
                            }
                        }
                    }
                    $stmtUsed->close();
                }

                $used_ips[$net_ip] = true;
				
				// ==============================================================
                // === LER A LINHA 1 ANTES DO LOOP COMEÇAR ===
                // ==============================================================
                $ip_forcado_global = '';
                $rsCfg = $mysqli->query("SELECT endpoint FROM wg_ramais ORDER BY id ASC LIMIT 1");
                if ($rsCfg && $rowCfg = $rsCfg->fetch_assoc()) {
                    $ip_forcado_global = trim($rowCfg['endpoint'] ?? '');
                }
                // ==============================================================

                foreach ($ramal_ids as $id_nas) {
                    $stmtChk = $mysqli->prepare("
                        SELECT id FROM wg_ramais WHERE id_nas = ? LIMIT 1
                    ");
                    if (!$stmtChk) {
                        $msg_erro .= 'Erro prepare SELECT wg_ramais: ' . $mysqli->error . ' ';
                        $err_count++;
                        continue;
                    }
                    $stmtChk->bind_param('i', $id_nas);
                    if (!$stmtChk->execute()) {
                        $msg_erro .= 'Erro execute SELECT wg_ramais: ' . $stmtChk->error . ' ';
                        $stmtChk->close();
                        $err_count++;
                        continue;
                    }
                    $stmtChk->store_result();
                    if ($stmtChk->num_rows > 0) {
                        $stmtChk->close();
                        continue;
                    }
                    $stmtChk->close();

                    $stmtNas = $mysqli->prepare("
                        SELECT shortname, nasname, bairro
                        FROM nas
                        WHERE id = ?
                        LIMIT 1
                    ");
                    if (!$stmtNas) {
                        $msg_erro .= 'Erro prepare SELECT nas: ' . $mysqli->error . ' ';
                        $err_count++;
                        continue;
                    }
                    $stmtNas->bind_param('i', $id_nas);
                    if (!$stmtNas->execute()) {
                        $msg_erro .= 'Erro execute SELECT nas: ' . $stmtNas->error . ' ';
                        $stmtNas->close();
                        $err_count++;
                        continue;
                    }
                    $resNas = $stmtNas->get_result();
                    $nasRow = $resNas->fetch_assoc();
                    $stmtNas->close();

                    if (!$nasRow) {
                        $msg_erro .= "NAS ID {$id_nas} não encontrado. ";
                        $err_count++;
                        continue;
                    }

                    $short     = $nasRow['shortname'] ?: ('NAS-' . $id_nas);
                    $peer_name = $short;

                    if ($mode === 'rand') {
                        $ip_free = wg_pick_free_ip_rand($net_long, $mask, $used_ips);
                    } else {
                        $ip_free = wg_pick_free_ip_seq($net_long, $mask, $used_ips);
                    }

                    if ($ip_free === null) {
                        $msg_erro .= "Não foi possível encontrar IP livre na rede {$wg_base_cidr} para NAS ID {$id_nas}. ";
                        $err_count++;
                        continue;
                    }
                    $used_ips[$ip_free] = true;
                    $address            = $ip_free . '/32';

                    file_put_contents(
                        '/tmp/wg_flow.log',
                        date('c') . " ANTES create-client NAS={$id_nas} ADDRESS={$address}\n",
                        FILE_APPEND
                    );

                    // ==============================================================
                    // === MONTAR O PAYLOAD COM OU SEM O ENDPOINT ===
                    // ==============================================================
                    $payload = [
                        'action'  => 'create-client',
                        'name'    => $peer_name,
                        'address' => $address,
                    ];

                    // Se a nossa "célula" no banco não estava vazia, injeta no JSON
                    if ($ip_forcado_global !== '') {
                        $payload['endpoint'] = $ip_forcado_global;
                    }

                    // Agora sim, manda o payload pro Go
                    $resp = wg_call($payload, $socketPath);
                    // ==============================================================
                    
					file_put_contents(
                        '/tmp/wg_provisionar_ramais.debug',
                        date('c') . " PROVISIONAR NAS {$id_nas} PEER {$peer_name} ADDR {$address} RESP: " . var_export($resp, true) . "\n",
                        FILE_APPEND
                    );

                    if (empty($resp['ok']) || empty($resp['data'])) {
                        $msg_erro .= "Falha ao criar peer WireGuard para NAS ID {$id_nas}. ";
                        $err_count++;
                        continue;
                    }

                    $d = $resp['data'];

                    $wg_client_id    = $d['id'] ?? '';
                    $public_key      = $d['publicKey'] ?? '';
                    $allowed_ips     = $d['allowedIPs'] ?? $address;
                    $persistent_keep = isset($d['persistentKeepalive']) ? (int)$d['persistentKeepalive'] : null;

                    $config_text = '';
                    if (!empty($d['config'])) {
                        $config_text = str_replace("\\n", PHP_EOL, $d['config']);
                    }

                    if ($wg_client_id === '' || $public_key === '') {
                        $msg_erro .= "Resposta incompleta ao criar peer para NAS ID {$id_nas}. ";
                        $err_count++;
                        continue;
                    }

                    $stmtIns = $mysqli->prepare("
                        INSERT INTO wg_ramais (
                            id_nas,
                            wg_client_id,
                            peer_name,
                            ip_wg,
                            public_key,
                            allowed_ips,
                            persistent_keepalive,
                            config_text,
                            downloadable_config,
                            status,
                            provisionado_em,
                            atualizado_em,
                            endpoint
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 'enabled', NOW(), NOW(), ?)
                    ");
                    if (!$stmtIns) {
                        $msg_erro .= 'Erro prepare INSERT wg_ramais: ' . $mysqli->error . ' ';
                        $err_count++;
                        continue;
                    }
                    $stmtIns->bind_param(
                        'isssssiss',
                        $id_nas,
                        $wg_client_id,
                        $peer_name,
                        $address,
                        $public_key,
                        $allowed_ips,
                        $persistent_keep,
                        $config_text,
                        $ip_forcado_global
                    );

                    if ($stmtIns->execute()) {
                        $ok_count++;

                        // 🎯 AQUI O CÓDIGO SÓ ATUALIZA A TABELA NAS SE O VALOR FOR ESTRITAMENTE 1 (Oficial)
                        if ($atualizar_ip_nas === 1) {
                            $ipwgHost = preg_replace('~/.*$~', '', $address);

                            $sqlUpdNas = "UPDATE nas SET nasname = ? WHERE id = ? LIMIT 1";
                            if ($stmtNasUpd = $mysqli->prepare($sqlUpdNas)) {
                                $stmtNasUpd->bind_param('si', $ipwgHost, $id_nas);
                                $stmtNasUpd->execute();
                                $stmtNasUpd->close();
                            }
                        }
                    } else {
                        $msg_erro .= 'Erro execute INSERT wg_ramais: ' . $stmtIns->error . ' ';
                        $err_count++;
                    }

                    $stmtIns->close();
                }
            }

            // 🎯 REDIRECIONAMENTO E MENSAGENS
            if ($ok_count > 0) {
                $_SESSION['wg_msg_sucesso'] = "Provisionamento criado para {$ok_count} ramal(is). Falhas: {$err_count}.";
                header('Location: ?tab=provisionar');
                exit;
            } else {
                if ($msg_erro === '') {
                    $msg_erro = 'Nenhum ramal foi provisionado.';
                }
            }
        }
    }
} // fim if (!$erro_db && $_SERVER['REQUEST_METHOD'] === 'POST')
