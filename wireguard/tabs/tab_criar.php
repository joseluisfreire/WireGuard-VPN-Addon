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
