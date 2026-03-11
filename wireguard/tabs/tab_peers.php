	<div class="box">

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
						<option value="">Status (Todos)</option>
						<option value="desativado" <?php echo (isset($_GET['status']) && $_GET['status']==='desativado') ? 'selected' : ''; ?>>Desativado</option>
						<option value="offline_oficial" <?php echo (isset($_GET['status']) && $_GET['status']==='offline_oficial') ? 'selected' : ''; ?>>Offline (Oficial)</option>
						<option value="offline_paralelo" <?php echo (isset($_GET['status']) && $_GET['status']==='offline_paralelo') ? 'selected' : ''; ?>>Offline (Paralelo)</option>
						<option value="online_oficial" <?php echo (isset($_GET['status']) && $_GET['status']==='online_oficial') ? 'selected' : ''; ?>>Online (Oficial)</option>
						<option value="online_paralelo" <?php echo (isset($_GET['status']) && $_GET['status']==='online_paralelo') ? 'selected' : ''; ?>>Online (Paralelo)</option>
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
		<?php
		// --- MOTOR DE BUSCA INTELIGENTE (NOME, IP E OS 5 ESTADOS) ---
		$termo_busca = strtolower(trim($_GET['search'] ?? ''));
		$status_filtro = $_GET['status'] ?? '';

		if ($termo_busca !== '' || $status_filtro !== '') {
			$clients_filtrados = [];
			
			foreach ($clients as $c) {
				$pub = $c['publicKey'] ?? '';
				$linha = $mapRamaisByPub[$pub] ?? null;
				
				// Regra 1: Filtro por Nome ou IP
				$passou_busca = true;
				if ($termo_busca !== '') {
					$nome_peer = $linha ? strtolower($linha['peer_name']) : '';
					$ip_wg = $linha ? strtolower($linha['ip_wg']) : '';
					if (strpos($nome_peer, $termo_busca) === false && strpos($ip_wg, $termo_busca) === false) {
						$passou_busca = false;
					}
				}

				// Regra 2: Filtro dos 5 Estados
				$passou_status = true;
				if ($status_filtro !== '') {
					$is_maquete = false;
					if ($linha && !empty($linha['id_nas'])) {
						$id_nas_atual = $linha['id_nas'];
						$ip_wg_limpo = explode('/', $linha['ip_wg'])[0];
						$ip_mk_atual = $mapNasIP[$id_nas_atual] ?? '';
						if ($ip_wg_limpo !== $ip_mk_atual && $ip_mk_atual !== '') {
							$is_maquete = true;
						}
					}
					
					$is_online = false;
					$dt_handshake = !empty($c['latestHandshakeAt']) ? $c['latestHandshakeAt'] : ($linha['latest_handshake_at'] ?? '');
					if (!empty($dt_handshake) && (time() - strtotime($dt_handshake)) < 180) {
						$is_online = true;
					}

					$admin_disabled = (!$linha || $linha['status'] !== 'enabled');
					
					$estado_atual = '';
					if ($admin_disabled) {
						$estado_atual = 'desativado';
					} elseif (!$is_online) {
						$estado_atual = $is_maquete ? 'offline_paralelo' : 'offline_oficial';
					} else {
						$estado_atual = $is_maquete ? 'online_paralelo' : 'online_oficial';
					}

					if ($estado_atual !== $status_filtro) {
						$passou_status = false;
					}
				}

				// Só exibe se passar nas duas regras (Texto e Status)
				if ($passou_busca && $passou_status) {
					$clients_filtrados[] = $c;
				}
			}
			// Substitui a lista original pela filtrada!
			$clients = $clients_filtrados;
		}
		?>

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
						<th>Ações</th>
					</tr>
				</thead>
				<tbody>
				<?php 
				$tem_paralelo = false; 
				if (!$clients): ?>
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
								$tem_paralelo = true;
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
						
						<?php
						// --- A NOVA LÓGICA DE UNIFICAÇÃO (Os 5 Estados) ---
						$admin_disabled = (!$linha || $linha['status'] !== 'enabled');
						$classe_linha = 'wg-peer-row' . ($admin_disabled ? ' peer-desativado' : '');
						?>

						<!-- 🎯 ÂNCORA 1: TR recebe a classe 'peer-desativado' automaticamente -->
						<tr class="<?php echo $classe_linha; ?>" data-pubkey="<?php echo htmlspecialchars($pub); ?>">
							
							<td class="is-vcentered">
								<?php if ($linha): ?>
									<input type="checkbox" name="peer_ids[]" value="<?php echo (int)$linha['id']; ?>" class="peer-checkbox" data-id_nas="<?php echo (int)$linha['id_nas']; ?>" data-nome="<?php echo htmlspecialchars($linha['peer_name']); ?>">
								<?php endif; ?>
							</td>
							
							<td class="is-vcentered"><strong><?php echo $linha ? htmlspecialchars($linha['peer_name']) : '-'; ?></strong></td>
							
							<td class="is-vcentered">
							<?php if ($linha): ?>
								<input class="input ip-input" style="width: 100%; min-width: 140px; height: 28px; font-size: 0.85rem; padding-left: 8px;" type="text" name="address_inline[<?php echo (int)$linha['id']; ?>]" value="<?php echo htmlspecialchars($linha['ip_wg']); ?>" readonly>
							<?php else: ?>
								-
							<?php endif; ?>
							</td>
							
							<!-- 🎯 ÂNCORA 2: A COLUNA UNIFICADA "DEUSA" (Status do Túnel) -->
							<td class="is-vcentered wg-status-cell" data-is-maquete="<?php echo $is_maquete ? '1' : '0'; ?>" data-disabled="<?php echo $admin_disabled ? '1' : '0'; ?>" style="white-space: nowrap;">
								<?php if ($admin_disabled): ?>
									<!-- ESTADO 1: Desativado -->
									<span class="tag is-dark wg-btn-status" style="font-weight: 600;">
										<i class="bi bi-x-circle-fill mr-1"></i> Desativado
									</span>
								<?php else: ?>
									<?php if (!$is_online): ?>
										<!-- ESTADO 2 e 3: Offline (Paralelo ou Oficial) -->
										<span class="tag is-warning wg-btn-status" style="background-color: #ffedd5; color: #9a3412; border: 1px solid #fdba74; font-weight: 600;">
											<i class="bi bi-exclamation-triangle-fill mr-1"></i> Offline <?php echo $is_maquete ? '(Paralelo)' : '(Oficial)'; ?>
										</span>
									<?php else: ?>
										<!-- Está Online! Mas qual túnel? -->
										<?php if ($is_maquete): ?>
											<!-- ESTADO 4: Online no Paralelo (Roxo) -->
											<span class="tag wg-btn-status status-online-glow" title="Em Paralelo: IP do ramal ainda não foi efetivado." style="background-color: #f3e8ff; color: #7e22ce; border: 1px solid #d8b4fe; font-weight: 600;">
												<i class="bi bi-diagram-2-fill mr-1"></i> Online (Paralelo)
											</span>
										<?php else: ?>
											<!-- ESTADO 5: Online no Oficial (Verde Enterprise) -->
											<span class="tag wg-btn-status status-online-glow" title="IP Oficial: Túnel principal operacional." style="background-color: #dcfce7; color: #166534; border: 1px solid #86efac; font-weight: 600;">
												<i class="bi bi-diagram-2-fill mr-1"></i> Online (Oficial)
											</span>
										<?php endif; ?>
									<?php endif; ?>
								<?php endif; ?>
							</td>

							<td class="is-vcentered wg-endpoint-cell">
								<?php if (!empty($c['endpoint'])): ?>
									<code style="background-color: #f1f5f9; color: #475569; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; border: 1px solid #e2e8f0; white-space: nowrap;">
										<?php echo htmlspecialchars($c['endpoint']); ?>
									</code>
								<?php else: ?>
									<span style="color: #94a3b8;">-</span>
								<?php endif; ?>
							</td>
							
							<!-- 🎯 ÂNCORA 3: ÚLTIMO HANDSHAKE - Mãozinha + Data + Raiozinho -->
							<td class="is-vcentered wg-handshake-cell" style="font-size:0.85rem; color:#475569; white-space: nowrap;">
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
														
							<!-- 🎯 ÂNCORA 4: RX (Download) - Fundo branco (is-white) pra não gritar -->
							<td class="is-vcentered has-text-right" style="white-space: nowrap;">
								<span class="tag is-white wg-rx-cell" data-bytes="<?php echo (int)$c['transferRx']; ?>" style="font-family: 'Consolas', monospace; font-weight: 600; min-width: 90px; justify-content: flex-end; border: 1px solid #e2e8f0;">
									<i class="bi bi-arrow-down mr-1" style="color: #3b82f6;"></i> <span class="texto-bytes"><?php echo humanBytes((int)$c['transferRx']); ?></span>
								</span>
							</td>

							<!-- 🎯 ÂNCORA 5: TX (Upload) - Fundo branco (is-white) pra não gritar -->
							<td class="is-vcentered has-text-right" style="white-space: nowrap;">
								<span class="tag is-white wg-tx-cell" data-bytes="<?php echo (int)$c['transferTx']; ?>" style="font-family: 'Consolas', monospace; font-weight: 600; min-width: 90px; justify-content: flex-end; border: 1px solid #e2e8f0;">
									<i class="bi bi-arrow-up mr-1" style="color: #eab308;"></i> <span class="texto-bytes"><?php echo humanBytes((int)$c['transferTx']); ?></span>
								</span>
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
					<a href="#" title="Executar Ação Mágica (OTP)" onclick="return submitOtpFromPeers();">
						<span class="icon" style="color: #ec4899;">
							<i class="bi-magic" style="font-size: 30px"></i>
						</span>
					</a>
				</div>

				  <!-- SÓ APARECE SE TIVER PELO MENOS UM PEER EM PARALELO -->
				  <?php if ($tem_paralelo): ?>
				  <div class="level-item">
					<a href="#" title="Efetivar Rota (Atualizar IP dos NAS selecionados no MK-Auth)" onclick="if(confirm('Tem certeza que deseja EFETIVAR os peers selecionados?\nIsso atualizará o IP no cadastro do MK-Auth, fazendo a comunicação ocorrer exclusivamente pelo WireGuard.')) { return submitPeersBulk('efetivar_ip'); } return false;">
					  <span class="icon" style="color: #8b5cf6;">
						<i class="bi-arrow-left-right" style="font-size: 30px"></i>
					  </span>
					</a>
				  </div>
				  <?php endif; ?>
				  
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
				<option value="varinha_magica">varinha_magica</option>
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
