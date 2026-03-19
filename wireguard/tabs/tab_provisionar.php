    <!-- O FORMULÁRIO ENGLOBA TUDO (Banner + Cards) PARA ENVIAR OS DADOS CORRETAMENTE -->
    <form id="form_provisionar" method="POST" action="?tab=provisionar">
        
        <!-- Ação exata que o Backend espera -->
        <input type="hidden" name="acao" value="provisionar_ramais">

        <!-- ==============================================================
             NOVO LAYOUT: 3 CARDS LADO A LADO (REDE + OFICIAL + PARALELO)
             ============================================================== -->
        <div class="columns is-desktop mb-5 is-variable is-3">
            
			<!-- CARD 1: REDE E ESTRATÉGIA DE IP (Borda Azul) -->
			<div class="column is-4">
				<div class="box" style="border-top: 4px solid #0ea5e9; border-radius: 12px; height: 100%; display: flex; flex-direction: column; box-shadow: 0 4px 15px rgba(0,0,0,0.05); padding: 1.25rem;">
					
					<!-- Dados da Rede -->
					<div style="display: flex; align-items: center; gap: 0.75rem; margin-bottom: 1.25rem;">
						<div style="background: #e0f2fe; color: #0284c7; padding: 8px 10px; border-radius: 8px; font-size: 1.25rem; line-height: 1;">
							<i class="bi bi-diagram-3-fill"></i>
						</div>
						<h3 class="title is-6 mb-0" style="color: #0f172a; margin-right: auto;">Rede WireGuard</h3>
						<span style="font-family: monospace; background: #f1f5f9; color: #0f172a; padding: 4px 10px; border-radius: 6px; font-size: 1.15rem; font-weight: 700; border: 1px solid #cbd5e1; box-shadow: inset 0 1px 3px rgba(0,0,0,0.02);">
							<?php echo htmlspecialchars($wg_base_cidr ?: 'Não configurada'); ?>
						</span>
					</div>
					
					<!-- Divisão Lado a Lado -->
					<div style="display: flex; gap: 1rem; margin-top: auto; flex: 1;">
						
						<!-- Coluna Esquerda: Servidor e Capacidade -->
						<div style="flex: 1; background: #f8fafc; padding: 10px; border-radius: 8px; border: 1px dashed #cbd5e1; font-size: 0.85rem; display: flex; flex-direction: column; justify-content: center;">
							<div style="display: flex; justify-content: space-between; margin-bottom: 8px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px;">
								<span class="has-text-grey">Servidor:</span>
								<strong style="color: #0f172a; font-family: monospace;"><?php echo htmlspecialchars($wg_server_host); ?></strong>
							</div>
							<div style="display: flex; justify-content: space-between;">
								<span class="has-text-grey">Capacidade:</span>
								<strong style="color: #0f172a;"><?php echo $wg_max_peers; ?> peers</strong>
							</div>
						</div>

						<!-- Coluna Direita: Estratégia de IPs -->
						<div style="flex: 1.2; display: flex; flex-direction: column; justify-content: center;">
							<div style="display: flex; align-items: center; gap: 6px; margin-bottom: 8px;">
								<i class="bi bi-hdd-network" style="color: #0ea5e9; font-size: 0.9rem;"></i>
								<span style="font-size: 0.65rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px; color: #64748b; line-height: 1.2;">
									Alocação de IPs p/ RBs
								</span>
							</div>
							
							<!-- RADIO: SEQUENCIAL -->
							<label title="IPs atribuídos em ordem crescente. Você poderá alterar o IP manualmente na aba Peers a qualquer momento." style="cursor: pointer; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 8px 10px; margin-bottom: 6px; display: flex; align-items: center; justify-content: space-between; transition: all 0.2s;" onmouseover="this.style.background='#f1f5f9'" onmouseout="this.style.background='#f8fafc'">
								<div style="display: flex; align-items: center; color: #334155; font-weight: 600; font-size: 0.85rem;">
									<input type="radio" name="alloc_mode" value="seq" required style="margin-right: 8px; transform: scale(1.2); accent-color: #0ea5e9;"> Sequencial
								</div>
								<div style="font-size: 0.78rem; color: #64748b; font-family: monospace; font-weight: 800; letter-spacing: 0px;">.2→.3→.4</div>
							</label>
							
							<!-- RADIO: ALEATÓRIO -->
							<label title="IPs atribuídos aleatoriamente dentro do range da rede. Você poderá alterar o IP manualmente na aba Peers a qualquer momento." style="cursor: pointer; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 8px 10px; display: flex; align-items: center; justify-content: space-between; transition: all 0.2s;" onmouseover="this.style.background='#f1f5f9'" onmouseout="this.style.background='#f8fafc'">
								<div style="display: flex; align-items: center; color: #334155; font-weight: 600; font-size: 0.85rem;">
									<input type="radio" name="alloc_mode" value="rand" required style="margin-right: 8px; transform: scale(1.2); accent-color: #0ea5e9;"> Aleatório
								</div>
								<div style="font-size: 0.78rem; color: #64748b; font-family: monospace; font-weight: 800; letter-spacing: 0px;">.14···.89</div>
							</label>

						</div>
						
					</div>
				</div>
			</div>

			<!-- CARD 2: EM PRODUÇÃO (Borda Verde) -->
			<div class="column is-4">
				<label class="box" style="border-top: 4px solid #16a34a; border-radius: 12px; height: 100%; display: flex; flex-direction: column; cursor: pointer; background: #f0fdf4; box-shadow: 0 4px 15px rgba(34, 197, 94, 0.08); transition: transform 0.2s;" onmouseover="this.style.transform='scale(1.02)'" onmouseout="this.style.transform='scale(1)'">
					<div class="is-flex is-align-items-center mb-3">
						<input type="radio" name="atualizar_ip_nas" value="1" required style="transform: scale(1.3); margin-right: 12px; accent-color: #166534;">
						<h3 class="title is-6 mb-0" style="color: #166534; display: flex; align-items: center;">
							<i class="bi bi-diagram-3" style="margin-right: 6px;"></i> Integração Direta
						</h3>
					</div>
					<div style="margin-left: 28px;">
						<p class="has-text-grey-dark" style="font-size: 0.85rem; line-height: 1.6;">
							O IP do MK será <strong>substituído imediatamente</strong> pelo novo endereço da rede WireGuard no cadastro do sistema em "Controle de Ramais". Use a varinha mágica na aba "Peers" ou use o script .rsc diretamente no terminal da rb para subir o túnel.
							Após o provisionamento, o status do túnel será exibido assim:
						</p>
						<!-- Card 2 - preview -->
						<div class="mt-2" style="display: flex; flex-direction: column; gap: 6px;">
							<div style="display: flex; align-items: center; gap: 8px; flex-wrap: nowrap; margin-top: 8px;">
								<span style="font-size: 0.72rem; color: #64748b;">Túnel WireGuard:</span>
								<span class="tag" style="background-color: #16a34a; color: #fff; font-weight: 600; font-size: 0.72rem;">
									<i class="bi bi-diagram-3"></i>&nbsp;Em Produção
								</span>
								&nbsp;|&nbsp;
								<span style="font-size: 0.72rem; color: #64748b;">IP do MK:</span>
								<code style="font-size: 0.72rem; background: #dcfce7; color: #166534; padding: 2px 6px; border-radius: 4px;">CAMPO</code>
								<span style="font-size: 0.68rem; color: #16a34a;">← atualizado</span>
							</div>
						</div>
					</div>
				</label>
			</div>

			<!-- CARD 3: EM PARALELO (Borda Amarela) -->
			<div class="column is-4">
				<label class="box" style="border-top: 4px solid #eab308; border-radius: 12px; height: 100%; display: flex; flex-direction: column; cursor: pointer; background: #fefce8; box-shadow: 0 4px 15px rgba(234, 179, 8, 0.08); transition: transform 0.2s;" onmouseover="this.style.transform='scale(1.02)'" onmouseout="this.style.transform='scale(1)'">
					<div class="is-flex is-align-items-center mb-3">
						<input type="radio" name="atualizar_ip_nas" value="0" required style="transform: scale(1.3); margin-right: 12px; accent-color: #ca8a04;">
						<h3 class="title is-6 mb-0" style="color: #854d0e; display: flex; align-items: center;">
							<i class="bi bi-diagram-2" style="margin-right: 6px;"></i> Migração
						</h3>
					</div>
					<div style="margin-left: 28px;">
						<p class="has-text-grey-dark" style="font-size: 0.85rem; line-height: 1.6;">
							O IP do MK <strong>não será alterado</strong>. O túnel WireGuard é criado silenciosamente em paralelo, permitindo <strong>homologação e testes</strong> sem impactar a conexão atual da RouterBoard com o MK-AUTH.
						</p>
						<p class="has-text-grey-dark mt-2" style="font-size: 0.82rem; line-height: 1.5;">
							Use o botão <span style="color: #8b5cf6; font-weight: 600;"><i class="bi-arrow-repeat" style="font-size: 1rem; vertical-align: middle;"></i> Efetivar</span> na aba "Peers" para promover o túnel à produção.
						</p>
						<!-- Card 3 - preview -->
						<div class="mt-2" style="display: flex; flex-direction: column; gap: 6px;">
							<div style="display: flex; align-items: center; gap: 8px; flex-wrap: nowrap; margin-top: 8px;">
								<span style="font-size: 0.72rem; color: #64748b;">Túnel WireGuard:</span>
								<span class="tag is-warning is-light" style="font-weight: 600; font-size: 0.72rem;">
									<i class="bi bi-diagram-2" style="color: #ca8a04;"></i>&nbsp;Em Paralelo
								</span>
								&nbsp;|&nbsp;
								<span style="font-size: 0.72rem; color: #64748b;">IP do MK:</span>
								<code style="font-size: 0.72rem; background: #fef9c3; color: #854d0e; padding: 2px 6px; border-radius: 4px;">CAMPO</code>
								<span style="font-size: 0.68rem; color: #ca8a04;">← inalterado</span>
							</div>
						</div>
					</div>
				</label>
			</div>

        </div>
        <!-- FIM DOS CARDS -->
        
        <!-- ==============================================================
             A TABELA DE RAMAIS MESTRA (REORDENADA)
             ============================================================== -->
        <div class="table-container">
            <table class="table is-fullwidth is-hoverable is-striped" style="background: white; border-radius: 8px; overflow: hidden; font-size: 0.9rem;">
                <thead style="background-color: #f1f5f9;">
                    <tr>
                        <th width="4%" class="has-text-centered">
                            <input type="checkbox" onchange="toggleAllRamais(this)" title="Selecionar Todos">
                        </th>
                        <th width="16%">Nome do Ramal</th>
                        <th width="15%" class="has-text-centered" title="Status de operação do Túnel">Túnel Wireguard</th>
                        <th width="13%" class="has-text-centered">IP do MK</th>
                        <th width="13%" class="has-text-centered">IP Fallback</th>
                        <th width="10%" class="has-text-centered">Porta SSH</th>
                        <th width="14%" class="has-text-centered">Senha MK-Auth</th>
                        <th width="15%" class="has-text-centered">Validação OTP</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($ramais_list)): ?>
                        <tr><td colspan="8" class="has-text-centered py-5 has-text-grey"><i class="bi bi-inbox is-size-3"></i><br>Nenhum NAS cadastrado no MK-AUTH.</td></tr>
                    <?php else: ?>
						<?php foreach ($ramais_list as $row): 
							
							$ip_mk_atual = trim($row['nasname']);
							$ip_fall_atual = trim($row['ipfall']);
							
							$ja_provisionado = !empty($row['wg_id']);
							
							// Tem IP válido se tiver o Fallback OU o IP do MK
							$has_ip    = !empty($ip_fall_atual) || !empty($ip_mk_atual); 
							
							$has_pass  = !empty($row['senha']);
							$porta_ssh = !empty($row['portassh']) ? $row['portassh'] : '22';
							
							// Agora o OTP fica pronto se qualquer um dos IPs existir + a senha
							$otp_pronto = ($has_ip && $has_pass);

							$ip_wg_limpo = $ja_provisionado ? explode('/', $row['wg_ip'])[0] : '';
						
                            // Lógica inteligente dos cards
                            $ip_espelhado_ok = ($ja_provisionado && $ip_wg_limpo === $ip_mk_atual);
                            $is_disabled     = ($ja_provisionado && isset($row['wg_status']) && $row['wg_status'] === 'disabled');
                        ?>
                        <tr>
                            <!-- 1. CHECKBOX -->
                            <td class="is-vcentered has-text-centered">
								<input type="checkbox" class="ramal-checkbox" name="ramal_ids[]" value="<?= $row['id_nas'] ?>" data-otp="<?= $otp_pronto ? '1' : '0' ?>" data-prov="<?= $ja_provisionado ? '1' : '0' ?>">
                            </td>
                            
                            <!-- 2. NOME DO RAMAL -->
                            <td class="is-vcentered">
                                <strong><?= htmlspecialchars($row['shortname'] ?: 'NAS '.$row['id_nas']) ?></strong>
                            </td>

                            <!-- 3. STATUS DO TÚNEL -->
                            <td class="is-vcentered has-text-centered">
                                <?php if (!$ja_provisionado): ?>
                                    <span class="tag is-light" style="font-weight: 600;" title="Ainda não existe túnel para esta RB">Não Configurado</span>
                                <?php elseif ($is_disabled): ?>
                                    <span class="tag is-danger is-light" style="font-weight: 600;" title="Túnel desativado! Habilite na aba peers!"><i class="bi bi-x-circle mr-1"></i> Desativado</span>
								<?php elseif ($ip_espelhado_ok): ?>
									<span class="tag" style="background-color: #16a34a; color: #ffffff; font-weight: 600; box-shadow: 0 2px 4px rgba(22, 163, 74, 0.2);" title="Túnel em operação, IP do MK-Auth configurado e ativo">
										<i class="bi bi-diagram-3-fill" style="color: #ffffff; margin-right: 5px;"></i> Em Produção
									</span>
                                <?php else: ?>
                                    <span class="tag is-warning is-light" style="font-weight: 600; border: 1px solid #fef08a;" title="Túnel gerado, mas ainda falta 'Efetivar Rota' na aba Peers"><i class="bi bi-diagram-2 mr-1" style="color: #ca8a04;"></i> Em Paralelo</span>
                                <?php endif; ?>
                            </td>

                            <!-- 4. IP DO SISTEMA (MK-AUTH) -->
                            <td class="is-vcentered has-text-centered">
                                <?php if (!empty($ip_mk_atual)): ?>
                                    <code id="ip_mk_<?= $row['id_nas'] ?>" style="transition: all 0.3s ease;"><?= htmlspecialchars($ip_mk_atual) ?></code>
                                <?php else: ?>
                                    <span class="tag is-light" title="Sem IP principal definido">Sem IP</span>
                                <?php endif; ?>
                            </td>
                            
							<!-- 5. IP FALLBACK -->
							<td class="is-vcentered has-text-centered">
								<?php if(!empty($ip_fall_atual)): ?>
									<code id="ip_fall_<?= $row['id_nas'] ?>" style="transition: all 0.3s ease;"><?= htmlspecialchars($ip_fall_atual) ?></code>
								<?php else: ?>
									<span class="tag is-danger is-light" title="Usando IP do MK como fallback."><i class="bi bi-exclamation-circle mr-1"></i> Faltando</span>
								<?php endif; ?>
							</td>

                            <!-- 6. PORTA SSH -->
                            <td class="is-vcentered has-text-centered">
                                <span class="has-text-grey font-weight-bold"><?= htmlspecialchars($porta_ssh) ?></span>
                            </td>

							<!-- 7. SENHA MKAUTH -->
							<td class="is-vcentered has-text-centered">
								<?php if($has_pass): ?>
									<!-- Usamos CSS inline flex e gap de 10px para garantir o espaçamento -->
									<div style="display: flex; align-items: center; justify-content: center; gap: 10px; height: 100%;">
										
										<span id="senha_txt_<?php echo $row['id_nas']; ?>" 
											  data-senha="<?php echo htmlspecialchars($row['senha']); ?>" 
											  style="font-family: monospace; font-size: 1.1rem; font-weight: 700; color: #363636; letter-spacing: 1px; line-height: 1; margin-top: 3px;">••••••</span>
										
										<a onclick="toggleSenhaSpan('senha_txt_<?php echo $row['id_nas']; ?>', this)" 
										   style="cursor: pointer; color: #64748b; display: flex; align-items: center;" 
										   title="Ver/Ocultar Senha">
											<i class="bi bi-eye" style="font-size: 1.1rem;"></i>
										</a>
										
									</div>
								<?php else: ?>
									<span class="tag is-danger is-light"><i class="bi bi-exclamation-circle mr-1"></i> Faltando</span>
								<?php endif; ?>
							</td>

                            <!-- 8. STATUS OTP (SSH) -->
                            <td class="is-vcentered has-text-centered cell-ssh-status" id="status_ssh_<?= $row['id_nas'] ?>" data-id="<?= $row['id_nas'] ?>">
                                <?php if ($otp_pronto): ?>
                                    <span class="tag is-light" style="font-weight: 600; color: #64748b;"><i class="bi bi-hourglass mr-1"></i> Pendente</span>
                                <?php else: ?>
                                    <span class="tag is-danger is-light" title="Faltam credenciais (IP ou Senha)"><i class="bi bi-x-circle mr-1"></i> Inválido</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>

		<div class="mt-4">
			<div class="field is-grouped is-align-items-center">
				<p class="control">
					<button type="button" class="button is-success" onclick="submitProvisionarRamais()" style="font-weight: 600;">
						<span class="icon is-small"><i class="bi bi-plus-lg"></i></span>
						<span>Provisionar Rb</span>
					</button>
				</p>
				<p class="control">
					<button type="button" class="button is-info is-light" onclick="testarSshEmMassa()" style="font-weight: 600; border: 1px solid #0ea5e9;" title="Testar conexão SSH dos ramais selecionados">
						<span class="icon is-small"><i class="bi bi-terminal-fill"></i></span>
						<span>Validar OTP</span>
					</button>
				</p>
                <!-- BOTÃO DE INFO DO OTP -->
                <p class="control ml-2">
                    <button type="button" class="button is-ghost has-text-info px-2" onclick="abrirModalInfoOtp()" title="O que é a validação OTP?" style="text-decoration: none; border-radius: 50%;">
                        <i class="bi bi-info-circle-fill is-size-4"></i>
                    </button>
                </p>
			</div>
			
			<div class="is-size-7 has-text-grey mt-2">
				<i class="bi bi-info-circle"></i> <strong>Provisionar Rb:</strong> Cria o peer WireGuard VPN para RouterBoard no servidor MK-Auth. | <strong>Valida OTP:</strong> Testa as credenciais simulando conexão com as Rb's.
			</div>
		</div>
    </form>

    <!-- ==============================================================
         MODAL: EXPLICAÇÃO DO OTP (One Touch Provisioning)
         ============================================================== -->
	<div class="modal" id="modal_info_otp">
		<div class="modal-background" onclick="fecharModalInfoOtp()" style="background-color: rgba(15, 23, 42, 0.7); backdrop-filter: blur(4px);"></div>
		<div class="modal-card" style="border-radius: 12px; overflow: hidden; width: 600px; max-width: 95%;">
			<header class="modal-card-head" style="background-color: #f8fafc; border-bottom: 1px solid #e2e8f0;">
				<p class="modal-card-title has-text-weight-bold" style="color: #0f172a; font-size: 1.25rem;">
					<i class="bi bi-magic" style="color: #f59e0b; margin-right: 8px;"></i> Sobre o OTP (One Touch Provisioning)
				</p>
				<button class="delete" aria-label="close" onclick="fecharModalInfoOtp()" type="button"></button>
			</header>
			<section class="modal-card-body" style="color: #475569; line-height: 1.6;">
				<p class="mb-4">
					O <strong>OTP</strong> é a funcionalidade mágica do Addon que acessa a sua RouterBoard via SSH e injeta todas as configurações do WireGuard automaticamente, sem você precisar abrir o WinBox.
				</p>

				<!-- BLOCO DE ATENÇÃO: PRÉ-REQUISITO SSH -->
				<div style="background: #fff7ed; border: 1px solid #fed7aa; border-left: 4px solid #f97316; border-radius: 8px; padding: 1rem; margin-bottom: 1.25rem;">
					<div style="display: flex; align-items: flex-start; gap: 10px;">
						<i class="bi bi-shield-lock-fill" style="color: #f97316; font-size: 1.2rem; margin-top: 2px; flex-shrink: 0;"></i>
						<div>
							<p style="font-weight: 700; color: #9a3412; margin-bottom: 4px; font-size: 0.9rem;">Pré-requisito obrigatório na RouterBoard</p>
							<p style="font-size: 0.85rem; color: #7c3a1e; line-height: 1.6; margin-bottom: 8px;">
								Para o OTP funcionar, a RouterBoard precisa estar configurada com o <strong>usuário <code>mkauth</code></strong> e a <strong>chave SSH do MK-Auth importada</strong>. Sem isso, a conexão SSH será recusada e o provisionamento automático falhará.
							</p>
							<a href="https://mk-auth.com.br/page/configurar-ssh" target="_blank" style="display: inline-flex; align-items: center; gap: 6px; background: #f97316; color: #ffffff; font-size: 0.82rem; font-weight: 700; padding: 5px 12px; border-radius: 6px; text-decoration: none;">
								<i class="bi bi-box-arrow-up-right"></i> Ver documentação oficial de configuração SSH
							</a>
						</div>
					</div>
				</div>
				
				<h4 class="title is-6 mb-2" style="color: #1e293b;">Como o sistema sabe qual IP acessar?</h4>
				<div class="content is-small">
					<ul>
						<li>
							<strong>Modo Em Produção:</strong> Para a mágica funcionar, o ramal precisa ter os dados validados: <strong class="has-text-info">IP Fallback</strong> (ou IP do MK), <strong>Senha</strong> e/ou <a href="https://mk-auth.com.br/page/configurar-ssh" target="_blank" style="color: #2563eb; text-decoration: underline;">chave SSH</a>.
						</li>
						<li>
							<strong>Modo Em Paralelo:</strong> A mágica utilizará o túnel antigo (PPTP, OVPN) já existente para acessar a RB. Caso falhe, utilizará o IP Fallback como último recurso.
						</li>
					</ul>
				</div>

				<div class="notification is-info is-light mt-4" style="padding: 1rem;">
					<div style="display: flex; align-items: flex-start; gap: 10px;">
						<i class="bi bi-lightbulb-fill is-size-5" style="color: #0ea5e9;"></i>
						<span style="font-size: 0.9rem;">
							Dica: Sempre utilize o botão <strong>"Testar SSH em Lote"</strong> antes de provisionar. Se a coluna <em>Validação OTP</em> ficar verde, o OTP funcionará perfeitamente!
						</span>
					</div>
				</div>
			</section>
			<footer class="modal-card-foot" style="justify-content: flex-end; background-color: #f8fafc; border-top: 1px solid #e2e8f0;">
				<button class="button is-info" onclick="fecharModalInfoOtp()" type="button">Entendi</button>
			</footer>
		</div>
	</div>

