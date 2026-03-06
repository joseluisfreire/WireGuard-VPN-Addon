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

// Lógica binária simples para saber se o Go respondeu e se a wg0 tá rodando
$is_daemon_ok = is_array($status_data) && (isset($status_data['ok']) || isset($status_data['data']));
$is_iface_up  = $is_daemon_ok && !empty($status_data['data']['if_up']);

if (!$is_daemon_ok) {
    // ❌ DAEMON OFFLINE
    $vs = [
        'bg_gradient' => 'linear-gradient(135deg, #ffe0e0 0%, #ffcccc 100%)',
        'border'      => '4px solid #e74c3c',
        'icon_color'  => '#e74c3c', 'icon_overlay'=> 'bi-x-lg', 'title_color' => '#c0392b',
        'title'       => 'Daemon wg-mkauthd',
        'subtitle'    => 'Sem conexão no socket'
    ];
    $show_details = false;
    $show_info = [
        ['label' => 'Serviço', 'value' => 'wg-mkauthd', 'type' => 'text'],
        ['label' => 'Status', 'value' => 'OFFLINE', 'type' => 'tag-danger'],
        ['label' => 'Ação', 'value' => 'service wg-mkauthd start', 'type' => 'code']
    ];
} else {
    // ✅ DAEMON ONLINE
    $vs = [
        'icon_color'  => '#48c774', 'icon_overlay'=> 'bi-check-lg', 'title_color' => '#27ae60',
        'title'       => 'Daemon wg-mkauthd',
        'subtitle'    => 'Socket conectado'
    ];
    
    if (!$interface_configurada) {
        // DAEMON OK, MAS NÃO CONFIGURADO (INSTALAÇÃO)
        $vs['bg_gradient'] = 'linear-gradient(135deg, #d6eaf8 0%, #aed6f1 100%)';
        $vs['border']      = '4px solid #3298dc';
        $vs['icon_overlay']= 'bi-dash-lg';
        $show_details = false;
        $show_info = [
            ['label' => 'Interface', 'value' => 'wg0', 'type' => 'text'],
            ['label' => 'Status', 'value' => 'NÃO CRIADA', 'type' => 'tag-info'],
        ];
    } elseif (!$is_iface_up) {
        // DAEMON OK, MAS INTERFACE DOWN (AVISO AMARELO)
        $vs['bg_gradient'] = 'linear-gradient(135deg, #fffbeb 0%, #fef08a 100%)';
        $vs['border']      = '4px solid #facc15';
        $vs['icon_color']  = '#ca8a04';
        $vs['title_color'] = '#a16207';
        $show_details = true;
        $d = $status_data['data'] ?? [];
    } else {
        // TUDO 100% OPERACIONAL
        $vs['bg_gradient'] = 'linear-gradient(135deg, #d4f4dd 0%, #bfe9c9 100%)';
        $vs['border']      = '4px solid #48c774';
        $show_details = true;
        $d = $status_data['data'] ?? [];
    }
}
?>

        <!-- CARD ÚNICO COMPACTO -->
        <div style="height: 100%; display: flex; flex-direction: column; background: <?php echo $vs['bg_gradient']; ?>; 
                    border-left: <?php echo $vs['border']; ?>; 
                    border-radius: 12px; 
                    padding: 1.25rem; 
                    box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
            
            <!-- SEÇÃO SUPERIOR: Plug + Status do DAEMON -->
            <div style="text-align: center; margin-bottom: 0.75rem;">
                <div style="position: relative; display: inline-block;">
                    <i class="bi bi-plug-fill" style="font-size: 2.5rem; color: <?php echo $vs['icon_color']; ?>; filter: drop-shadow(0 3px 6px rgba(0,0,0,0.2));"></i>
                    <i class="<?php echo $vs['icon_overlay']; ?>" style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 1.25rem; color: white; text-shadow: 0 2px 4px rgba(0,0,0,0.5); font-weight: bold;"></i>
                </div>
                <h2 class="title is-6" style="margin-top: 0.25rem; margin-bottom: 0; font-size: 0.95rem; color: <?php echo $vs['title_color']; ?>;">
                    <?php echo $vs['title']; ?>
                </h2>
                <p style="margin-top: 0.25rem; color: #666; font-size: 0.8rem; font-weight: 500;"><?php echo $vs['subtitle']; ?></p>
            </div>
            
            <!-- CONTEÚDO DINÂMICO (TABELA DA INTERFACE WG0) -->
            <?php if ($show_details && isset($d)): ?>
                <div style="background: rgba(255,255,255,0.5); border-radius: 10px; padding: 0.5rem 0.75rem; margin-bottom: 0; flex-grow: 1;">
                    
                    <!-- LINHA UNIFICADA: INTERFACE + STATUS -->
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.3rem 0; border-bottom: 1px solid rgba(0,0,0,0.06);">
                        <span style="font-size: 0.85rem; font-weight: 600; color: #1e293b;">Interface:</span>
                        <div style="display: flex; align-items: center; gap: 0.4rem;">
                            <span style="font-size: 0.85rem; font-family: monospace; color: #0f172a; font-weight: 700;">wg0</span>
                            <span class="tag <?php echo $is_iface_up ? 'is-success' : 'is-warning'; ?>" style="font-weight: 700; font-size: 0.65rem; height: 18px; padding: 0 0.4rem;">
                                <?php echo $is_iface_up ? 'UP' : 'DOWN'; ?>
                            </span>
                        </div>
                    </div>

                    <!-- ENDPOINT -->
                    <?php 
                    $ip_forcado = '';
                    $rsCfg = $mysqli->query("SELECT endpoint FROM wg_ramais ORDER BY id ASC LIMIT 1");
                    if ($rsCfg && $rowCfg = $rsCfg->fetch_assoc()) {
                        $ip_forcado = trim($rowCfg['endpoint'] ?? '');
                    }
                    $ip_detectado = $d['public_ip'] ?? 'N/A';
                    $ip_mostrar = ($ip_forcado !== '') ? $ip_forcado : $ip_detectado;
                    ?>
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.3rem 0; border-bottom: 1px solid rgba(0,0,0,0.06);">
                        <span style="font-size: 0.85rem; font-weight: 600; color: #1e293b;">Endpoint:</span>
                        <div style="display: flex; align-items: center; gap: 0.4rem;">
                            
                            <!-- Tag e Engrenagem clicáveis juntos -->
                            <div style="display: flex; align-items: center; gap: 0.2rem; cursor: pointer; transition: opacity 0.2s;" onmouseover="this.style.opacity=0.7" onmouseout="this.style.opacity=1" onclick="document.getElementById('modal_nat').classList.add('is-active');" title="Configurar Endpoint">
                                <?php if ($ip_forcado !== ''): ?>
                                    <span class="tag is-warning is-light" style="font-size: 0.6rem; padding: 0 4px; height: 16px;">Manual</span>
                                <?php else: ?>
                                    <span class="tag is-info is-light" style="font-size: 0.6rem; padding: 0 4px; height: 16px;">Auto</span>
                                <?php endif; ?>
                                <i class="bi-gear-fill" style="color: #94a3b8; font-size: 0.75rem;"></i>
                            </div>
                            
                            <!-- Valor e Copiar -->
                            <span style="font-size: 0.85rem; font-family: monospace; color: #0f172a; font-weight: 700; margin-left: 0.2rem;"><?php echo htmlspecialchars($ip_mostrar); ?></span>
                            <a href="#" onclick="copiarTexto('<?php echo htmlspecialchars($ip_mostrar); ?>'); return false;" style="color: #64748b; font-size: 0.9rem;" title="Copiar Endpoint">
                                <i class="bi-clipboard"></i>
                            </a>
                        </div>
                    </div>

                    <!-- PORTA -->
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.3rem 0; <?php echo !empty($d['wg_address']) ? 'border-bottom: 1px solid rgba(0,0,0,0.06);' : ''; ?>">
                        <span style="font-size: 0.85rem; font-weight: 600; color: #1e293b;">Porta:</span>
                        <div style="display: flex; align-items: center; gap: 0.4rem;">
                            <span style="font-size: 0.85rem; font-family: monospace; color: #0f172a; font-weight: 700;"><?php echo isset($d['port']) ? (int)$d['port'] : 'N/A'; ?></span>
                            <a href="#" onclick="copiarTexto('<?php echo isset($d['port']) ? (int)$d['port'] : ''; ?>'); return false;" style="color: #64748b; font-size: 0.9rem;" title="Copiar Porta">
                                <i class="bi-clipboard"></i>
                            </a>
                        </div>
                    </div>

                    <!-- NETWORK -->
                    <?php if (!empty($d['wg_address'])): ?>
                    <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.3rem 0;">
                        <span style="font-size: 0.85rem; font-weight: 600; color: #1e293b;">Network:</span>
                        <div style="display: flex; align-items: center; gap: 0.4rem;">
                            <span style="font-size: 0.85rem; font-family: monospace; color: #0f172a; font-weight: 700;"><?php echo htmlspecialchars($d['wg_address']); ?></span>
                            <a href="#" onclick="copiarTexto('<?php echo htmlspecialchars($d['wg_address']); ?>'); return false;" style="color: #64748b; font-size: 0.9rem;" title="Copiar Network">
                                <i class="bi-clipboard"></i>
                            </a>
                        </div>
                    </div>
                    <?php endif; ?>

                </div>
            
            <!-- INFORMAÇÕES ESTÁTICAS (PARA ERROS OU NÃO CONFIGURADO) -->
            <?php elseif (isset($show_info) && !empty($show_info)): ?>
                <div style="background: rgba(255,255,255,0.5); border-radius: 10px; padding: 0.5rem 0.75rem; margin-bottom: 0; flex-grow: 1;">
                    <?php $total = count($show_info); $i = 0; ?>
                    <?php foreach ($show_info as $info): ?>
                        <?php $i++; $is_last = ($i === $total); ?>
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 0.3rem 0; <?php echo !$is_last ? 'border-bottom: 1px solid rgba(0,0,0,0.06);' : ''; ?>">
                            <span style="font-size: 0.85rem; font-weight: 600; color: #1e293b;"><?php echo htmlspecialchars($info['label']); ?>:</span>
                            <div style="display: flex; align-items: center; gap: 0.4rem;">
                                <?php if ($info['type'] === 'code'): ?>
                                    <span style="font-size: 0.85rem; font-family: monospace; color: #0f172a; font-weight: 700;"><?php echo htmlspecialchars($info['value']); ?></span>
                                <?php elseif ($info['type'] === 'tag-danger'): ?>
                                    <span class="tag is-danger" style="font-weight: 700; font-size: 0.7rem; height: 20px; padding: 0 0.5rem;"><?php echo htmlspecialchars($info['value']); ?></span>
                                <?php elseif ($info['type'] === 'tag-info'): ?>
                                    <span class="tag is-info" style="font-weight: 700; font-size: 0.7rem; height: 20px; padding: 0 0.5rem;"><?php echo htmlspecialchars($info['value']); ?></span>
                                <?php else: ?>
                                    <span style="font-size: 0.85rem; color: #0f172a; font-weight: 500;"><?php echo htmlspecialchars($info['value']); ?></span>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>
        </div> <!-- fim da coluna 1 -->

        <!-- ========================================
             COLUNA 2: PAINEL DE CONTROLE (is-4 = 33% da tela)
             ======================================== -->
        <div class="column is-4">
            <div class="box" style="height: 100%; display: flex; flex-direction: column;">
                
                <!-- HEADER FIXO (Não entra na rolagem) -->
                <div class="level is-mobile mb-4" style="border-bottom: 1px solid #f1f5f9; padding-bottom: 0.5rem; flex-shrink: 0;">
                    <div class="level-left">
                        <h2 class="title is-5 mb-0" style="color: #334155;">
                            <span class="icon"><i class="bi bi-sliders"></i></span>
                            <span>Painel de Controle</span>
                        </h2>
                    </div>
                    <div class="level-right">
                        <?php if ($interface_configurada && $daemon_ok): ?>
                            <button class="button is-small is-light" type="button" onclick="document.getElementById('modal_wg_raw').classList.add('is-active');" title="Ver wg0.conf bruto">
                                <span class="icon"><i class="bi bi-file-earmark-code"></i></span>
                            </button>
                        <?php endif; ?>
                    </div>
                </div>

                <?php if (!$daemon_ok): ?>
                    <!-- CASO 1: DAEMON OFFLINE -->
                    <div class="notification is-danger"><p><i class="bi bi-x-circle-fill"></i> Daemon Offline</p></div>

                <?php elseif (!$interface_configurada): ?>
                    <!-- CASO 2: PRIMEIRA INSTALAÇÃO (Motor Original / Visual Novo) -->
                    <div class="notification is-info is-light is-size-7">
                        <strong>Primeira Instalação</strong><br>
                        A interface <strong>wg0</strong> ainda não está configurada neste servidor. Preencha os dados abaixo para gerar as chaves e criar a interface.
                    </div>

                    <!-- Motor: action="?tab=status" e onsubmit original -->
                    <form method="POST" action="?tab=status" onsubmit="return confirm('Criar interface wg0 com essa rede/porta?');">
                        
                        <!-- Motor: acao=create_server -->
                        <input type="hidden" name="acao" value="create_server">
                        
                        <div class="field">
                            <label class="label is-small">Porta de Escuta (ListenPort)</label>
                            <div class="control has-icons-left">
                                <!-- Motor: name="wg_port" -->
                                <input class="input" type="number" name="wg_port" min="1" max="65535" value="51820" required>
                                <span class="icon is-small is-left"><i class="fas fa-network-wired"></i></span>
                            </div>
                        </div>

                        <div class="field">
                            <label class="label is-small">Rede (Address)</label>
                            <div class="field has-addons">
                                <div class="control is-expanded has-icons-left">
                                    <!-- Motor: name="wg_network_v4" -->
                                    <input class="input" type="text" name="wg_network_v4" value="10.66.66.1/24" required>
                                    <span class="icon is-small is-left"><i class="fas fa-server"></i></span>
                                </div>
                                <div class="control">
                                    <!-- Motor: Chamando o JS original sem mexer nele -->
                                    <button class="button is-info is-light" type="button" onclick="wgRandomPrivate24();" title="Gerar Rede Aleatória">
                                        <i class="bi bi-shuffle"></i>
                                    </button>
                                </div>
                            </div>
                        </div>

                        <div class="field mt-5">
                            <div class="control">
                                <button type="submit" class="button is-success is-fullwidth">
                                    <span class="icon"><i class="fas fa-plus-circle"></i></span>
                                    <span>Criar Interface wg0</span>
                                </button>
                            </div>
                        </div>
                    </form>

                <?php else: ?>
                    <!-- CASO 3: TUDO OK (Mostra a Danger Zone) -->
                    
                    <!-- CORPO DO CARD 2: AQUI ENTRA A MÁGICA DO SEU CSS (.scroll-interno-card) -->
                    <div class="scroll-interno-card" style="display: flex; flex-direction: column;">
                        
                        <!-- ESTADO 1: BLOQUEADO (Centralizado bonitão) -->
                        <div id="visao_normal" style="flex: 1; display: flex; flex-direction: column; justify-content: center; align-items: center; min-height: 150px;">
                            <i class="bi bi-shield-lock" style="font-size: 3.5rem; color: #e2e8f0; margin-bottom: 1rem;"></i>
                            <button class="button is-danger is-light is-fullwidth" type="button" onclick="document.getElementById('visao_normal').style.display = 'none'; document.getElementById('visao_perigo').style.display = 'flex';" style="font-weight: bold; border: 1px dashed #f87171;">
                                <span class="icon"><i class="bi bi-unlock-fill"></i></span>
                                <span>Desbloquear Zona de Perigo</span>
                            </button>
                        </div>

                        <!-- ESTADO 2: ZONA DE PERIGO -->
                        <div id="visao_perigo" style="display: none; flex-direction: column; animation: fadeIn 0.3s ease;">
                            
                            <div class="level is-mobile mb-3">
                                <div class="level-left">
                                    <span class="has-text-danger has-text-weight-bold is-size-6">
                                        <i class="bi bi-exclamation-triangle-fill mr-1"></i> Ações Críticas
                                    </span>
                                </div>
                                <div class="level-right">
                                    <!-- Clicar no X volta pro estado 1 -->
                                    <button class="delete" aria-label="close" type="button" onclick="document.getElementById('visao_perigo').style.display = 'none'; document.getElementById('visao_normal').style.display = 'flex';"></button>
                                </div>
                            </div>

                            <!-- LIGAR / DESLIGAR -->
                            <div class="box is-shadowless mb-3" style="border: 1px solid #e2e8f0; padding: 0.75rem;">
                                <p class="heading has-text-grey mb-2"><i class="bi bi-power"></i> Interface wg0</p>
                                <div style="display: flex; gap: 0.5rem;">
                                    <?php $is_up = !empty($status_data['data']['if_up']); ?>
                                    <form method="post" style="flex: 1;" onsubmit="return confirm('Ligar wg0?');">
                                        <input type="hidden" name="acao" value="server-up">
                                        <button class="button is-success is-small is-fullwidth <?php echo $is_up ? '' : 'is-outlined'; ?>" type="submit" <?php echo $is_up ? 'disabled' : ''; ?>>Ligar</button>
                                    </form>
                                    <form method="post" style="flex: 1;" onsubmit="return confirm('PERIGO: Desligar wg0 e desconectar clientes?');">
                                        <input type="hidden" name="acao" value="server-down">
                                        <button class="button is-danger is-small is-fullwidth <?php echo !$is_up ? '' : 'is-outlined'; ?>" type="submit" <?php echo !$is_up ? 'disabled' : ''; ?>>Desligar</button>
                                    </form>
                                </div>
                            </div>

                            <!-- RESET TOTAL -->
                            <div class="box is-shadowless mb-0" style="border: 1px solid #fef08a; padding: 0.75rem; background-color: #fffbeb;">
                                <p class="heading has-text-warning-dark mb-2"><i class="bi bi-arrow-clockwise"></i> Reset Total</p>
                                <form method="post" action="?tab=status" onsubmit="return confirmReset();">
                                    <input type="hidden" name="acao" value="reset_server">
                                    
                                    <div class="field has-addons mb-2">
                                        <div class="control is-expanded">
                                            <input class="input is-small" type="text" name="wg_network_v4_reset" value="<?php echo htmlspecialchars($current_network ?: '10.66.66.1/24'); ?>" required>
                                        </div>
                                        <div class="control">
                                            <button class="button is-small is-info is-light" type="button" onclick="wgRandomPrivate24();" title="Gerar Rede Aleatória">
                                                <i class="bi bi-shuffle"></i>
                                            </button>
                                        </div>
                                    </div>

                                    <div class="field mb-3">
                                        <div class="control">
                                            <input class="input is-small" type="number" name="wg_port_reset" value="<?php echo $current_port ?: 51820; ?>" required placeholder="Porta">
                                        </div>
                                    </div>
                                    
                                    <button class="button is-warning is-small is-fullwidth has-text-weight-bold" type="submit" style="border: 1px solid #facc15;">
                                        Executar Reset Total
                                    </button>
                                </form>
                            </div>

                        </div> <!-- fim visão perigo -->

                    </div> <!-- fim da mola -->

                    <style>
                        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
                    </style>

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
    <!-- MODAL WG0.CONF RAW (SOMENTE LEITURA) -->
    <?php if ($interface_configurada && $daemon_ok): ?>
    <div class="modal" id="modal_wg_raw">
        <div class="modal-background" onclick="document.getElementById('modal_wg_raw').classList.remove('is-active');"></div>
        <div class="modal-content" style="max-width:700px;">
            <div class="box" style="background: #1e293b; padding: 1.5rem; border: 1px solid #334155;">
                <div class="is-flex is-justify-content-space-between is-align-items-center mb-3">
                    <h3 class="title is-5 has-text-white mb-0">
                        <i class="bi bi-file-earmark-code mr-2"></i>wg0.conf (Snapshot em Memória)
                    </h3>
                    <button class="delete" aria-label="close" onclick="document.getElementById('modal_wg_raw').classList.remove('is-active');"></button>
                </div>
                <pre style="background: #0f172a; color: #38bdf8; padding: 1rem; border-radius: 8px; font-size: 0.85rem; max-height: 400px; overflow-y: auto; box-shadow: inset 0 2px 4px rgba(0,0,0,0.5);"><code><?php echo htmlspecialchars($wg_conf_raw ?? ''); ?></code></pre>
            </div>
        </div>
    </div>
    <?php endif; ?>
