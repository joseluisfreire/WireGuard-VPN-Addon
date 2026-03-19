<!-- MODAL About -->
<div class="modal" id="about-wg-popup">
  <div class="modal-background"
       onclick="document.getElementById('about-wg-popup').classList.remove('is-active');"></div>

  <div class="modal-content" style="max-width: 420px;">
    <div class="box">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
        <h2 class="title is-5" style="margin-bottom:0;">Sobre WireGuard</h2>
        <button class="delete" aria-label="close"
                onclick="document.getElementById('about-wg-popup').classList.remove('is-active');"></button>
      </div>

      <?php if (!is_array($version_data) || empty($version_data['ok']) || empty($version_data['data'])): ?>
        <p>Não foi possível obter informações de versão via socket.</p>
      <?php else: ?>
        <?php $v = $version_data['data']; ?>

        <figure class="image" style="max-width: 320px; margin: 0 auto 0.5rem auto;">
          <img src="wireguard-logo.png" alt="WireGuard">
        </figure>

        <p><strong>WireGuard tools:</strong><br>
          <small><?php echo nl2br(htmlspecialchars($v['wgVersion'] ?? '')); ?></small>
        </p>

        <p><strong>Daemon addon:</strong>
          wg-mkauthd <?php echo htmlspecialchars($v['daemonVersion'] ?? ''); ?>
        </p>

        <p><strong>Socket:</strong>
          <?php echo htmlspecialchars($v['socketPath'] ?? ''); ?>
        </p>

        <p><strong>Daemon iniciado em:</strong>
          <?php echo htmlspecialchars($v['daemonStartedAt'] ?? ''); ?>
        </p>

        <p><strong>Kernel com WireGuard:</strong>
          <?php echo !empty($v['kernelHasWireguard']) ? 'Sim' : 'Não'; ?>
        </p>

        <hr style="margin:0.5rem 0;">
        <p style="font-size:0.85em;">
          Addon WireGuard para MK-AUTH – daemon em Go inspirado em wireguard-tools.
        </p>
      <?php endif; ?>
    </div>
  </div>
</div>
<!-- MODAL DE CONFIGURAÇÃO DE NAT / ENDPOINT -->
<div class="modal" id="modal_nat">
    <div class="modal-background" onclick="this.parentElement.classList.remove('is-active')"></div>
    <div class="modal-card" style="max-width: 450px;">
        <header class="modal-card-head" style="background-color: #f8fafc; border-bottom: 1px solid #e2e8f0;">
            <p class="modal-card-title is-size-5" style="font-weight: 700; color: #0f172a;">
                <i class="bi bi-globe" style="color: #0ea5e9;"></i> IP Público / NAT
            </p>
            <button class="delete" aria-label="close" onclick="document.getElementById('modal_nat').classList.remove('is-active')"></button>
        </header>
            <section class="modal-card-body">
                <div class="notification is-warning is-light" style="font-size: 0.85rem; padding: 1rem;">
                    <i class="bi bi-exclamation-triangle-fill"></i> 
                    <strong>Aviso:</strong> O Daemon detectou o IP Público<code><?php echo htmlspecialchars($ip_detectado); ?></code> automaticamente.<br><br>
                    Só altere esse campo caso o ip público de entrada mapaedo para o seu servidor MK-Auth seja diferente do endereço público de saída detectado pelo Daemon.
                </div>

                <?php
                // Pega o IP local principal da máquina
                $ip_local_detectado = explode(" ", trim(shell_exec("hostname -I")))[0];

                // Fallback caso dê algum erro no shell
                if(empty($ip_local_detectado)) {
                    $ip_local_detectado = $_SERVER['SERVER_ADDR'] ?? '192.168.x.x'; 
                }
                ?>
                <!-- Bloco Visual do IP Local (Sugestão Clicável) -->
                <div style="margin-bottom: 1.5rem; font-size: 0.85rem; color: #64748b; background: #f8fafc; padding: 10px 12px; border-radius: 6px; border: 1px dashed #cbd5e1; display: flex; align-items: center; gap: 8px;">
                    <i class="bi bi-diagram-3-fill" style="color: #0284c7; font-size: 1rem;"></i> 
                    <span>Interface eth0 endereço ip</span>
                    
                    <!-- Link clicável (Joga pro id="ip_nat_input" que você já criou!) -->
                    <span onclick="document.getElementById('ip_nat_input').value='<?php echo $ip_local_detectado; ?>'" 
                          style="font-weight: 700; color: #0369a1; background: #e0f2fe; padding: 3px 8px; border-radius: 4px; cursor: pointer; transition: all 0.2s ease;"
                          onmouseover="this.style.background='#bae6fd'; this.style.transform='scale(1.02)';" 
                          onmouseout="this.style.background='#e0f2fe'; this.style.transform='scale(1)';">
                        <?php echo $ip_local_detectado; ?> <i class="bi bi-hand-index-thumb" style="font-size: 0.8rem; margin-left: 2px;"></i>
                    </span>
                </div>
    
                <form method="post" action="?tab=status">
                    <input type="hidden" name="acao" value="salvar_nat">
                    
                    <div class="field">
                        <label class="label is-small">IP Fixo manual (.rsc .conf ENDPOINT)</label>
                        
                        <!-- AQUI ENTRA A MÁGICA DO HAS-ADDONS -->
                        <div class="field has-addons mb-1">
                            <div class="control is-expanded has-icons-left">
                                <!-- Adicionei o id="ip_nat_input" para o botão conseguir esvaziar ele -->
                                <input class="input" type="text" id="ip_nat_input" name="ip_nat" placeholder="Ex: 200.20.20.5 ou vpn.provedor.com" value="<?php echo htmlspecialchars($ip_forcado); ?>">
                                <span class="icon is-small is-left"><i class="bi bi-hdd-network"></i></span>
                            </div>
                            <div class="control">
                                <!-- O Botão de Limpar colado no campo -->
                                <button class="button is-warning is-light" type="button" onclick="document.getElementById('ip_nat_input').value = '';" title="Limpar para Voltar ao Automático" style="border-radius: 0 4px 4px 0; border: 1px solid #dbdbdb; border-left: none;">
                                    <span class="icon is-small"><i class="bi bi-eraser-fill" style="color: #d97706;"></i></span>
                                    <span class="is-hidden-mobile has-text-weight-bold" style="font-size: 0.85rem; color: #b45309;">Limpar (Auto)</span>
                                </button>
                            </div>
                        </div>
                        
                        <p class="help has-text-grey">
                            Deixe vazio e clique em salvar para retornar à <strong>Detecção Automática</strong>.
                        </p>
                    </div>
                    
                    <div class="field mt-4">
                        <button type="submit" class="button is-info is-fullwidth" style="font-weight: 600;">
                            <i class="bi bi-save mr-2"></i> Salvar Configuração
                        </button>
                    </div>
                </form>
            </section>
    </div>
</div>
<!-- MODAL OTP PROGRESSO -->
<div id="modal_otp_progress" class="modal">
  <div class="modal-background" style="background-color: rgba(15, 23, 42, 0.85);"></div>
  <div class="modal-card" style="border-radius: 16px; overflow: hidden; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5);">
    <header class="modal-card-head" style="background-color: #f8fafc; border-bottom: 1px solid #e2e8f0; padding: 1.25rem;">
      <p class="modal-card-title" style="font-weight: 800; color: #0f172a; font-size: 1.1rem; display: flex; align-items: center; gap: 10px;">
        <span class="icon" style="color: #0ea5e9;"><i class="bi bi-magic"></i></span>
        Auto OTP (One Touch Provisioning)
      </p>
    </header>
    <section class="modal-card-body" style="background-color: #ffffff; padding: 1.5rem;">
      <div id="otp_log_container" style="background: #0f172a; color: #f8fafc; padding: 1.25rem; border-radius: 12px; font-family: 'Courier New', Courier, monospace; font-size: 0.9rem; line-height: 1.6; height: 350px; overflow-y: auto; box-shadow: inset 0 4px 10px rgba(0,0,0,0.5);">
          <!-- Logs aparecerão aqui via JS -->
      </div>
    </section>
    <footer class="modal-card-foot" style="background-color: #f8fafc; border-top: 1px solid #e2e8f0; padding: 1.25rem; justify-content: flex-end;">
      <button id="btn_fechar_otp" class="button is-info" disabled style="border-radius: 10px; font-weight: 700; padding: 0.5rem 1.5rem; transition: all 0.3s ease;">
        Aguarde o Processo...
      </button>
    </footer>
  </div>
</div>

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
