    <!-- O FORMULÁRIO ENGLOBA TUDO (Banner + Cards) PARA ENVIAR OS DADOS CORRETAMENTE -->
    <form id="form_provisionar" method="POST" action="?tab=provisionar">
        
        <!-- Ação exata que o Backend espera -->
        <input type="hidden" name="acao" value="provisionar_ramais">

        <!-- ==============================================================
             CABEÇALHO WIZARD: FRAME ESTÁTICO COM PAINEL VISUAL DE IP
             ============================================================== -->
        <div class="notification" style="background: linear-gradient(135deg, #0ea5e9 0%, #0284c7 100%); border: none; color: white; border-radius: 12px; box-shadow: 0 4px 12px rgba(14,165,233,0.3); padding: 1.5rem; margin-bottom: 2rem; width: 100%; display: flex; align-items: center; justify-content: space-between;">
            
            <!-- ESQUERDA: CÓPIA LITERAL -->
            <div style="display: flex; align-items: center; gap: 1.5rem;">
                <div style="font-size: 3rem; opacity: 0.9; line-height: 1;">
                    <i class="bi bi-diagram-3-fill"></i>
                </div>
                <div>
                    <h3 class="title is-4" style="color: white; margin-bottom: 0.25rem; display: flex; align-items: center;">
                        Rede WireGuard: <span style="font-family: monospace; background: rgba(255,255,255,0.2); padding: 2px 8px; border-radius: 6px; letter-spacing: 1px; margin-left: 10px; font-weight: normal; font-size: 1.2rem;"><?php echo htmlspecialchars($wg_base_cidr ?: 'Não configurada'); ?></span>
                    </h3>
                    <p style="opacity: 0.95; font-size: 1rem; margin-top: 0.5rem; margin-bottom: 0;">
                        IP do Servidor: <strong><?php echo htmlspecialchars($wg_server_host); ?></strong> &nbsp;|&nbsp; 
                        Capacidade: <strong><?php echo $wg_max_peers; ?> peers</strong>
                    </p>
                </div>
            </div>

            <!-- DIREITA: Painel Interativo (Agora com ícones de RBs reais) -->
            <div style="background: rgba(255, 255, 255, 0.15); backdrop-filter: blur(8px); padding: 0.8rem 1.2rem; border-radius: 12px; border: 1px solid rgba(255, 255, 255, 0.4); box-shadow: 0 8px 16px rgba(0,0,0,0.1);">
                
                <div style="display: flex; align-items: center; justify-content: center; gap: 8px; margin-bottom: 10px;">
                    <i class="bi bi-hdd-network" style="color: #fde047; font-size: 1.1rem;"></i>
                    <span style="font-size: 0.75rem; font-weight: 800; text-transform: uppercase; letter-spacing: 1px; color: #fff;">
                        Estratégia de IPs p/ RBs
                    </span>
                    <i class="bi bi-question-circle-fill" title="Define como o WireGuard irá gerar os endereços de IP para as RBs conectadas." style="cursor: help; opacity: 0.8; font-size: 0.85rem;"></i>
                </div>

                <div style="display: flex; align-items: center; gap: 1rem;">
                    
                    <!-- OPÇÃO 1: SEQUENCIAL -->
                    <label style="cursor: pointer; padding: 0.5rem 0.8rem; border-radius: 8px; background: rgba(0,0,0,0.25); border: 1px solid rgba(255,255,255,0.15); transition: transform 0.2s; display: flex; flex-direction: column; align-items: center; justify-content: center; min-width: 140px;" onmouseover="this.style.transform='scale(1.05)'" onmouseout="this.style.transform='scale(1)'">
                        <div style="display: flex; align-items: center; margin-bottom: 6px; color: white; font-weight: 700; font-size: 0.85rem;">
                            <input type="radio" name="alloc_mode" value="seq" checked style="margin-right: 6px; transform: scale(1.2);"> Sequencial
                        </div>
                        <div style="display: flex; align-items: center; gap: 6px; opacity: 0.95;">
                            <div style="display: flex; flex-direction: column; align-items: center; line-height: 1;">
                                <i class="bi bi-hdd-network" style="font-size: 1.1rem; color: rgba(255,255,255,0.8); margin-bottom: 2px;"></i>
                                <span style="font-size: 0.65rem; font-family: monospace; font-weight: bold; color: #bbf7d0;">.2</span>
                            </div>
                            <i class="bi bi-arrow-right" style="font-size: 0.7rem; color: rgba(255,255,255,0.4);"></i>
                            <div style="display: flex; flex-direction: column; align-items: center; line-height: 1;">
                                <i class="bi bi-hdd-network" style="font-size: 1.1rem; color: rgba(255,255,255,0.8); margin-bottom: 2px;"></i>
                                <span style="font-size: 0.65rem; font-family: monospace; font-weight: bold; color: #bbf7d0;">.3</span>
                            </div>
                            <i class="bi bi-arrow-right" style="font-size: 0.7rem; color: rgba(255,255,255,0.4);"></i>
                            <div style="display: flex; flex-direction: column; align-items: center; line-height: 1;">
                                <i class="bi bi-hdd-network" style="font-size: 1.1rem; color: rgba(255,255,255,0.8); margin-bottom: 2px;"></i>
                                <span style="font-size: 0.65rem; font-family: monospace; font-weight: bold; color: #bbf7d0;">.4</span>
                            </div>
                        </div>
                    </label>

                    <!-- OPÇÃO 2: ALEATÓRIO -->
                    <label style="cursor: pointer; padding: 0.5rem 0.8rem; border-radius: 8px; background: rgba(0,0,0,0.25); border: 1px solid rgba(255,255,255,0.15); transition: transform 0.2s; display: flex; flex-direction: column; align-items: center; justify-content: center; min-width: 140px;" onmouseover="this.style.transform='scale(1.05)'" onmouseout="this.style.transform='scale(1)'">
                        <div style="display: flex; align-items: center; margin-bottom: 6px; color: white; font-weight: 700; font-size: 0.85rem;">
                            <input type="radio" name="alloc_mode" value="rand" style="margin-right: 6px; transform: scale(1.2);"> Aleatório
                        </div>
                        <div style="display: flex; align-items: center; gap: 6px; opacity: 0.95;">
                            <div style="display: flex; flex-direction: column; align-items: center; line-height: 1;">
                                <i class="bi bi-hdd-network" style="font-size: 1.1rem; color: rgba(255,255,255,0.8); margin-bottom: 2px;"></i>
                                <span style="font-size: 0.65rem; font-family: monospace; font-weight: bold; color: #fef08a;">.14</span>
                            </div>
                            <i class="bi bi-three-dots" style="font-size: 0.7rem; color: rgba(255,255,255,0.4);"></i>
                            <div style="display: flex; flex-direction: column; align-items: center; line-height: 1;">
                                <i class="bi bi-hdd-network" style="font-size: 1.1rem; color: rgba(255,255,255,0.8); margin-bottom: 2px;"></i>
                                <span style="font-size: 0.65rem; font-family: monospace; font-weight: bold; color: #fef08a;">.89</span>
                            </div>
                            <i class="bi bi-three-dots" style="font-size: 0.7rem; color: rgba(255,255,255,0.4);"></i>
                            <div style="display: flex; flex-direction: column; align-items: center; line-height: 1;">
                                <i class="bi bi-hdd-network" style="font-size: 1.1rem; color: rgba(255,255,255,0.8); margin-bottom: 2px;"></i>
                                <span style="font-size: 0.65rem; font-family: monospace; font-weight: bold; color: #fef08a;">.21</span>
                            </div>
                        </div>
                    </label>

                </div>
            </div>
        </div>
        <!-- FIM DO BANNER AZUL -->

        <!-- ==============================================================
             CAIXA BRANCA: CARDS DE DECISÃO DE PROVISIONAMENTO
             ============================================================== -->
        <div class="box custom-card" style="border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); padding: 2rem; background: #fafafa;">
            
            <div class="columns is-desktop mb-5">
                
                <!-- OPÇÃO 1: OFICIAL (Verde) -->
                <div class="column is-6">
                    <label class="box" style="height: 100%; border: 2px solid #bbf7d0; border-left: 8px solid #22c55e; background: #f0fdf4; cursor: pointer; display: flex; flex-direction: column; box-shadow: 0 4px 10px rgba(34, 197, 94, 0.1);">
                        <div class="is-flex is-align-items-center mb-3">
                            <input type="radio" name="atualizar_ip_nas" value="1" checked style="transform: scale(1.5); margin-right: 15px;">
                            <h3 class="title is-5 mb-0" style="color: #166534; display: flex; align-items: center;">
                                <i class="bi bi-check-circle-fill" style="margin-right: 8px;"></i>
                                Integração Direta<span class="tag is-success is-light ml-2" style="font-weight: 700; border: 1px solid #bbf7d0; font-size: 0.9rem;">Oficial</span>
                            </h3>
                        </div>
                        <div class="has-text-grey-dark" style="margin-left: 34px; font-size: 0.9rem; line-height: 1.5;">
                            <p>
                                Crie e configure o túnel para a integração das suas RBs MikroTik com o sistema MK-Auth. O novo IP gerado pelo WireGuard será atualizado <strong>IMEDIATAMENTE</strong> em "Controle de Ramais", gravando no campo "IP do MK" das RBs selecionadas.
                            </p>
                            <p class="mt-3" style="padding-top: 10px; border-top: 1px dashed rgba(34, 197, 94, 0.3);">
                                <strong style="color: #15803d;"><i class="bi bi-magic" style="margin-right: 4px;"></i> Sobre o OTP (One Touch Provisioning):</strong> 
                                Para que a "varinha mágica" funcione corretamente, o ramal precisa ter os dados essenciais de cadastro validados (IP Fallback, Senha do user mkauth e/ou 
                                <a href="https://mk-auth.com.br/page/configurar-ssh" target="_blank" rel="noopener noreferrer" style="color: #15803d; text-decoration: underline; font-weight: 600; position: relative; z-index: 10;" onclick="event.stopPropagation();" title="Abrir Manual MK-Auth">chave SSH devidamente importada <i class="bi bi-box-arrow-up-right" style="font-size: 0.75rem; margin-left: 2px;"></i></a>). 
                                Garantindo o correto preenchimento desses dados, basta clicar na varinha mágica para o sistema acessar a RB e injetar todas as configurações!
                            </p>
                        </div>
                    </label>
                </div>

                <!-- OPÇÃO 2: PARALELO (Amarelo) -->
                <div class="column is-6">
                    <label class="box" style="height: 100%; border: 2px solid #fef08a; border-left: 8px solid #eab308; background: #fefce8; cursor: pointer; display: flex; flex-direction: column; box-shadow: 0 4px 10px rgba(234, 179, 8, 0.1);">
                        <div class="is-flex is-align-items-center mb-3">
                            <input type="radio" name="atualizar_ip_nas" value="0" style="transform: scale(1.5); margin-right: 15px;">
                            <h3 class="title is-5 mb-0" style="color: #854d0e; display: flex; align-items: center;">
                                <i class="bi bi-diagram-2" style="margin-right: 8px;"></i>
                                Migração 
                                <span class="tag is-warning is-light ml-2" style="font-weight: 700; border: 1px solid #fef08a; color: #854d0e; font-size: 0.9rem;">Em Paralelo</span>
                            </h3>
                        </div>
                        <div class="has-text-grey-dark" style="margin-left: 34px; font-size: 0.9rem; line-height: 1.5;">
                            <p>
                                O IP do MK em "Controle de Ramais" <strong>não será alterado agora</strong>. O WireGuard será configurado de forma silenciosa. Ideal para RBs em produção que já possuem túneis antigos (PPTP, OVPN, L2TP). Crie o túnel, garanta que ele conectou e, só então, vá na aba "Peers" e clique em <strong>"Efetivar Rota"</strong>, oficializando a migração com total segurança.
                            </p>
                            <p class="mt-3" style="padding-top: 10px; border-top: 1px dashed rgba(234, 179, 8, 0.4);">
                                <strong style="color: #854d0e;"><i class="bi bi-magic" style="margin-right: 4px;"></i> Sobre o OTP (One Touch):</strong> 
                                Neste modo, a mágica utilizará o túnel antigo já existente no cadastro para acessar a RB via SSH e injetar a nova VPN. Caso a conexão por essa rota primária falhe, o Addon utilizará o IP Fallback como último recurso.
                            </p>
                        </div>
                    </label>
                </div>
                
            </div> <!-- FIM DAS COLUNAS DE CARDS -->
        
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
                        <th width="13%" class="has-text-centered">IP Fallback (SSH)</th>
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
                                    <span class="tag is-success is-light" style="font-weight: 600; border: 1px solid #bbf7d0;" title="Túnel em operação, IP do MK-Auth configurado e ativo"><i class="bi bi-check-circle-fill mr-1" style="color: #22c55e;"></i> Oficial</span>
                                <?php else: ?>
                                    <span class="tag is-warning is-light" style="font-weight: 600; border: 1px solid #fef08a;" title="Túnel gerado, mas ainda falta 'Efetivar Rota' na aba Peers"><i class="bi bi-diagram-2 mr-1" style="color: #ca8a04;"></i> Em Paralelo</span>
                                <?php endif; ?>
                            </td>

                            <!-- 4. IP DO SISTEMA (MK-AUTH) -->
                            <td class="is-vcentered has-text-centered">
                                <?php if (!empty($ip_mk_atual)): ?>
                                    <code><?= htmlspecialchars($ip_mk_atual) ?></code>
                                <?php else: ?>
                                    <span class="tag is-light" title="Sem IP principal definido">Sem IP</span>
                                <?php endif; ?>
                            </td>
                            
                            <!-- 5. IP FALLBACK -->
                            <td class="is-vcentered has-text-centered">
                                <?php if($has_ip): ?>
                                    <code><?= htmlspecialchars($row['ipfall']) ?></code>
                                <?php else: ?>
                                    <span class="tag is-danger is-light" title="IP Fallback é necessário para que o OTP funcione corretamente em um cenário de primeira instalação."><i class="bi bi-exclamation-circle mr-1"></i> Faltando</span>
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
                            <td class="is-vcentered has-text-centered cell-ssh-status" data-id="<?= $row['id_nas'] ?>">
                                <?php if ($otp_pronto): ?>
                                    <button type="button" class="button is-small is-light is-info" onclick="testarConexaoSsh(this, <?= $row['id_nas'] ?>)" style="font-weight: 600; transition: all 0.2s;">
                                        <span class="icon is-small"><i class="bi bi-terminal-fill"></i></span>
                                        <span>Testar SSH</span>
                                    </button>
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

