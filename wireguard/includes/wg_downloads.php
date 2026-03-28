<?php
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
