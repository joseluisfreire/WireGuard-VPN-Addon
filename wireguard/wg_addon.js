function toggleAllPeers(bx) {
  var cbs = document.querySelectorAll('.peer-checkbox');
  cbs.forEach(function (cb) {
    cb.checked = bx.checked;
  });
}

jQuery(function ($) {

  function getSelectedPeerIds() {
    var ids = [];
    $('#form_peers .peer-checkbox:checked').each(function () {
      ids.push($(this).val());
    });
    return ids;
  }

  function setIpReadonlyState(readonly) {
    $('#form_peers .peer-checkbox').each(function () {
      if (this.checked) {
        var id = $(this).val();
        var $input = $('#form_peers input[name="address_inline[' + id + ']"]');
        if ($input.length) {
          if (readonly) {
            $input.prop('readonly', true).removeClass('is-editing-ip');
          } else {
            $input.prop('readonly', false).addClass('is-editing-ip');
          }
        }
      }
    });
  }

  // Entrar em modo edição de IPs
  $('#btn_enter_edit_ip').click(function (e) {
    e.preventDefault();
    var ids = getSelectedPeerIds();
    if (ids.length === 0) {
      alert('Selecione ao menos um peer para editar o IP.');
      return false;
    }

    setIpReadonlyState(false);

    $('#wrap_save_ip_bulk').show();
    $('#wrap_cancel_edit_ip').show();
    $('#wrap_enter_edit_ip').hide();

    return false;
  });

  // Cancelar edição de IPs
  $('#btn_cancel_edit_ip').click(function (e) {
    e.preventDefault();

    $('#form_peers .ip-input').prop('readonly', true).removeClass('is-editing-ip');

    $('#wrap_save_ip_bulk').hide();
    $('#wrap_cancel_edit_ip').hide();
    $('#wrap_enter_edit_ip').show();

    return false;
  });

  // Salvar IPs dos selecionados
  $('#btn_save_ip_bulk').click(function (e) {
    e.preventDefault();
    var ids = getSelectedPeerIds();
    if (ids.length === 0) {
      alert('Nenhum peer selecionado.');
      return false;
    }

    var temErro = false;
    ids.forEach(function (id) {
      var $input = $('#form_peers input[name="address_inline[' + id + ']"]');
      if ($input.length) {
        var ipCidr = $.trim($input.val());
        if (!isValidIPv4Cidr(ipCidr)) {
          $input.addClass('is-danger');
          temErro = true;
        } else {
          $input.removeClass('is-danger');
        }
      }
    });

    if (temErro) {
      alert('Um ou mais endereços são inválidos. Use IPv4/CIDR, ex: 10.6.0.2/32 ou 10.6.0.0/24.');
      return false;
    }

    if (!confirm('Salvar o IP atual dos peers selecionados?')) {
      return false;
    }

    $('#acao_peers').val('editar_peer');
    $('#subacao_peers').val('address');
    $('#form_peers').attr('action', '?tab=peers');
    $('#form_peers').attr('target', '_self');
    $('#form_peers').submit();
    return false;
  });

}); // jQuery ready

function isValidIPv4Cidr(str) {
  var re = /^((25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\/(3[0-2]|[12]?\d)$/;
  return re.test(str);
}

function submitPeersBulk(action) {
  var form = document.getElementById('form_peers');
  var anyChecked = form.querySelector('.peer-checkbox:checked');
  if (!anyChecked) {
    alert('Nenhum peer selecionado.');
    return false;
  }
  if (!confirm('Confirmar ação "' + action + '" nos peers selecionados?')) {
    return false;
  }
  document.getElementById('acao_peers').value = 'bulk_peers';
  document.getElementById('subacao_peers').value = '';
  document.getElementById('bulk_action_peers').value = action;
  form.submit();
  return false;
}

function toggleAllRamais(bx) {
  var cbs = document.querySelectorAll('.ramal-checkbox');
  cbs.forEach(function (cb) {
    cb.checked = bx.checked;
  });
}

function submitProvisionarRamais() {
  var form = document.getElementById('form_provisionar');
  var anyChecked = form.querySelector('.ramal-checkbox:checked');
  if (!anyChecked) {
    alert('Nenhum ramal selecionado.');
    return false;
  }
  if (!confirm('Criar peers WireGuard para os ramais selecionados?')) {
    return false;
  }
  form.submit();
  return false;
}

function abrirConfModal(id) {
  document.getElementById('modal_conf_id').value = id;
  document.getElementById('form_modal_conf').submit();
}

function abrirRscModal(id) {
  document.getElementById('modal_rsc_id').value = id;
  document.getElementById('form_modal_rsc').submit();
}

function abrirWgStringModal(id) {
  document.getElementById('modal_wgstring_id').value = id;
  document.getElementById('form_modal_wgstring').submit();
}
function fecharConfModal() {
  var m = document.getElementById('modal_conf');
  if (m) m.classList.remove('is-active');
}

function copiarConf() {
  var ta = document.getElementById('conf_textarea');
  if (!ta) return;
  ta.select();
  document.execCommand('copy');
}

function fecharRscModal() {
  var m = document.getElementById('modal_rsc');
  if (m) m.classList.remove('is-active');
}

function copiarRsc() {
  var ta = document.getElementById('rsc_textarea');
  if (!ta) return;
  ta.select();
  document.execCommand('copy');
}

function fecharWgStringModal() {
  var m = document.getElementById('modal_wgstring');
  if (m) m.classList.remove('is-active');
}

function copiarWgString() {
  var ta = document.getElementById('wgstring_textarea');
  if (!ta) return;
  ta.select();
  document.execCommand('copy');
}

function wgRandomPrivate24() {
    const familia = Math.floor(Math.random() * 3);
    let octets = [];
    
    if (familia === 0) {
        octets = [10, Math.floor(Math.random() * 256), Math.floor(Math.random() * 256), 1];
    } else if (familia === 1) {
        octets = [172, 16 + Math.floor(Math.random() * 16), Math.floor(Math.random() * 256), 1];
    } else {
        octets = [192, 168, Math.floor(Math.random() * 256), 1];
    }
    
    const ip = octets.join('.') + '/24';
    const input = document.querySelector('input[name="wg_network_v4"], input[name="wg_network_v4_reset"]');
    if (input) {
        input.value = ip;
    }
}
// ==============================================================
// MÁGICA DO SORTEIO DE IP (Aba: Criar Peer)
// ==============================================================

// Converte IP pra Número (Cálculos matemáticos)
function ipToLongJS(ip) {
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

// Converte Número devolta pra IP
function longToIpJS(long) {
    return [(long >>> 24) & 255, (long >>> 16) & 255, (long >>> 8) & 255, long & 255].join('.');
}

// Animação visual da roleta
function animarInput() {
    const input = document.getElementById('peer_address');
    if (!input) return;
    input.style.transform = 'scale(1.02)';
    input.style.backgroundColor = '#f0fdfa';
    input.style.borderColor = '#48c774';
    setTimeout(() => {
        input.style.transform = 'scale(1)';
        input.style.backgroundColor = '';
        input.style.borderColor = '#e2e8f0';
    }, 200);
}

// O Motor do Sorteio
function sortearIpPeerJS() {
    const cfg = window.wgIpConfig; // Lê os dados exportados pelo PHP
    if (!cfg || !cfg.netIp || cfg.mask === 0) return alert('Rede base inválida.');

    let netLong = ipToLongJS(cfg.netIp);
    let hostBits = 32 - cfg.mask;
    let maxHosts = (1 << hostBits);
    let maskLong = ~((1 << hostBits) - 1) >>> 0;
    let networkStart = netLong & maskLong;

    let tries = 0;
    while(tries < 1000) {
        // Sorteia entre 1 e maxHosts-2 (ignora Rede e Broadcast)
        let offset = Math.floor(Math.random() * (maxHosts - 2)) + 1; 
        let candidateLong = networkStart + offset;
        let candidateIp = longToIpJS(candidateLong);

        // Se o IP não está no banco (usedIps), joga na tela!
        if(!cfg.usedIps.includes(candidateIp) && candidateIp !== cfg.netIp) {
            document.getElementById('peer_address').value = candidateIp + '/32';
            animarInput();
            return;
        }
        tries++;
    }
    alert('A rede está cheia ou quase cheia, impossível sortear mais IPs.');
}

// Botão de voltar pro Sequencial
function restaurarSequencialJS() {
    const cfg = window.wgIpConfig;
    if(cfg && cfg.seqIp) {
        document.getElementById('peer_address').value = cfg.seqIp + '/32';
        animarInput();
    }
}

// Função para copiar texto ao clicar no botão
function copiarTexto(texto) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(texto).then(function() {
            // Feedback visual (opcional)
            alert('Copiado: ' + texto);
        }).catch(function(err) {
            console.error('Erro ao copiar:', err);
        });
    } else {
        // Fallback para navegadores antigos
        const textarea = document.createElement('textarea');
        textarea.value = texto;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand('copy');
        document.body.removeChild(textarea);
        alert('Copiado: ' + texto);
    }
}
/**
 * Confirmação em 2 etapas para Reset do servidor WireGuard.
 */
function confirmReset() {
    // Etapa 1: Aviso sobre backups
    var ok1 = confirm(
        '⚠️ ATENÇÃO: RESET DO SERVIDOR WIREGUARD\n\n'
        + 'Esta ação irá:\n'
        + '• Gerar nova keypair do servidor\n'
        + '• Recriar wg0.conf do zero\n'
        + '• DELETAR TODOS os peers da tabela wg_ramais\n'
        + '• ⚠️ APAGAR TODOS OS BACKUPS/SNAPSHOTS!\n\n'
        + '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n'
        + 'Se deseja reverter um estado anterior,\n'
        + 'faça o DOWNLOAD do(s) backup(s) ANTES\n'
        + 'dessa ação na coluna "Backup & Restore".\n'
        + '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n'
        + 'Deseja continuar mesmo assim?'
    );

    if (!ok1) return false;

    // Etapa 2: Confirmação final
    var ok2 = confirm(
        '🔴 CONFIRMAÇÃO FINAL\n\n'
        + 'Todos os peers e backups serão perdidos.\n'
        + 'Esta ação é IRREVERSÍVEL.\n\n'
        + 'Clique OK para RESETAR.'
    );

    return ok2;
}
/**
 * Confirmação para importar backup .conf externo
 */
function confirmImportBackup() {
    return confirm(
        '⚠️ IMPORTAR BACKUP EXTERNO\n\n'
        + 'Isso vai:\n'
        + '• Fazer snapshot do estado atual (segurança)\n'
        + '• Substituir o wg0.conf pelo arquivo enviado\n'
        + '• Reconstruir os peers no banco a partir do .conf\n\n'
        + 'O servidor WireGuard será reiniciado.\n\n'
        + 'Continuar?'
    );
}
// ==============================================================
// FUNÇÃO PARA MOSTRAR/OCULTAR SENHA (VERSÃO TEXTO PURO)
// ==============================================================
function toggleSenhaSpan(spanId, btnElement) {
    const span = document.getElementById(spanId);
    const icone = btnElement.querySelector('i');
    
    if (!span || !icone) return;

    const senhaReal = span.getAttribute('data-senha');

    // Se estiver aparecendo bolinhas, mostra a senha real
    if (span.innerText === '••••••') {
        span.innerText = senhaReal;
        span.style.fontSize = '0.9rem'; // Ajusta fonte pra caber bem
        icone.classList.remove('bi-eye');
        icone.classList.add('bi-eye-slash'); // Troca pro olho cortado
        
        // Timer de segurança: Esconde a senha de volta depois de 10 segundos
        setTimeout(() => {
            if (span.innerText === senhaReal) {
                span.innerText = '••••••';
                span.style.fontSize = '1.1rem';
                icone.classList.remove('bi-eye-slash');
                icone.classList.add('bi-eye');
            }
        }, 10000); 

    } else {
        // Se estiver aparecendo o texto, volta pras bolinhas
        span.innerText = '••••••';
        span.style.fontSize = '1.1rem';
        icone.classList.remove('bi-eye-slash');
        icone.classList.add('bi-eye');
    }
}
// ==============================================================
// FUNÇÕES DA ABA PROVISIONAR (Massa)
// ==============================================================

// Botão 1: Provisionar no Servidor (Trava dura em duplicados)
function submitProvisionarRamais() {
    var form = document.getElementById('form_provisionar');
    
    // 🛑 NOVA TRAVA DE SEGURANÇA AQUI:
    // Pede ao navegador para verificar se os campos obrigatórios (required) estão preenchidos.
    // Se faltar algum botão de rádio, o reportValidity() retorna falso e mostra a mensagem "Selecione uma opção".
    if (!form.reportValidity()) {
        return false; // Trava a execução, obriga o cara a ler os cards e escolher.
    }

    var selecionados = form.querySelectorAll('.ramal-checkbox:checked');
    
    if (selecionados.length === 0) {
        alert('Nenhum ramal selecionado.');
        return false;
    }

    // Conta se selecionou alguém que já tem túnel
    var jaProvisionados = 0;
    selecionados.forEach(function(cb) {
        if (cb.getAttribute('data-prov') === '1') jaProvisionados++;
    });

    // TRAVA DURA: Não deixa o cara prosseguir se houverem peers repetidos
    if (jaProvisionados > 0) {
        alert('❌ ERRO: Você selecionou ramal(is) que JÁ ESTÃO PROVISIONADOS no servidor.\n\nDesmarque os ramais que já possuem IP do WireGuard para poder criar os novos.');
        return false; // Trava a função. Não submete o formulário.
    }

    // Se passou pela trava, pede a confirmação padrão
    if (!confirm('Criar peers WireGuard para os ramais selecionados no SERVIDOR?')) {
        return false;
    }

    form.querySelector('input[name="acao"]').value = 'provisionar_ramais';
    form.submit();
    return false;
}

    // ==============================================================
    // TESTE DE SSH EM MASSA COM HIGHLIGHT DE IP
    // ==============================================================
    async function testarSshEmMassa() {
        var form = document.getElementById('form_provisionar');
        var selecionados = form.querySelectorAll('.ramal-checkbox:checked');
        
        if (selecionados.length === 0) {
            alert('Selecione ao menos um ramal para testar o SSH.');
            return;
        }
    
        // Passa por cada caixinha selecionada
        for (let cb of selecionados) {
            if (cb.getAttribute('data-otp') === '0') continue; // Pula quem tá "Inválido"
            
            let idNas = cb.value;
            let tdStatus = document.getElementById('status_ssh_' + idNas);
            
            if (!tdStatus) continue;

            // Coloca o status "Testando..." animado
            tdStatus.innerHTML = '<span class="tag is-warning is-light" style="font-weight:bold;"><i class="bi bi-arrow-repeat mr-1" style="animation: spin 2s linear infinite;"></i> Testando...</span>';
            
            try {
                let formData = new FormData();
                formData.append('acao', 'testar_ssh_otp');
                formData.append('id_nas', idNas);
        
                let response = await fetch(window.location.href, {
                    method: 'POST',
                    body: formData
                });
                let data = await response.json(); 
    
                if(data.status === 'ok') {
                    // Sucesso Total!
                    let icone_metodo = data.metodo === 'Chave SSH' ? '<i class="bi bi-key-fill mr-1"></i>' : '<i class="bi bi-asterisk mr-1"></i>';
                    
                    tdStatus.innerHTML = `
                        <span class="tag" style="background-color: #4ade80; color: #000; border: 1px solid #22c55e; font-weight: 600;" title="Logado como '${data.user}' no IP ${data.ip} usando ${data.metodo}">
                            ${icone_metodo} Conectado
                        </span>`;
                    
                    // MÁGICA DO MARCA-TEXTO: Compara o IP usado com o da tela
                    let codeMk = document.getElementById('ip_mk_' + idNas);
                    let codeFall = document.getElementById('ip_fall_' + idNas);
                    
                    if (codeMk && codeMk.innerText.trim() === data.ip) {
                        aplicarMarcaTexto(codeMk);
                    } else if (codeFall && codeFall.innerText.trim() === data.ip) {
                        aplicarMarcaTexto(codeFall);
                    }
                } else {
                    console.warn("Motivo da falha SSH (Log do PHP):", data.debug);
                    tdStatus.innerHTML = `
                        <span class="tag is-danger is-light" style="font-weight: 600; border: 1px solid #f87171;" title="${data.msg}">
                            <i class="bi bi-x-circle-fill mr-1"></i> Falhou
                        </span>`;
                }
            } catch (error) {
                console.error("Erro de Rede ou JS:", error);
                tdStatus.innerHTML = '<span class="tag is-danger"><i class="bi bi-wifi-off mr-1"></i> Erro de Rede</span>';
            }
        }
    }
    
    // Funçãozinha para pintar o IP que funcionou
    function aplicarMarcaTexto(elemento) {
        elemento.style.backgroundColor = '#dcfce7'; 
        elemento.style.color = '#166534'; 
        elemento.style.border = '1px solid #22c55e';
        if (!elemento.innerHTML.includes('bi-check-circle-fill')) {
            elemento.innerHTML += ' <i class="bi bi-check-circle-fill" style="color:#22c55e; font-size: 0.85rem; margin-left: 4px;"></i>';
        }
    }

function submitOtpFromPeers(event) {
    // Bloqueia o recarregamento fantasma da página
    if (event) {
        event.preventDefault();
    }

    const checkboxes = document.querySelectorAll('.peer-checkbox:checked');
    
    if (checkboxes.length === 0) {
        alert('Selecione pelo menos um peer para executar a varinha mágica.');
        return false;
    }
    
    let rbs = [];
    checkboxes.forEach(chk => {
        let id_nas = chk.getAttribute('data-id_nas');
        let nome = chk.getAttribute('data-nome');
        
        if (id_nas && id_nas !== "0" && id_nas !== "") {
            rbs.push({ id_nas: id_nas, nome: nome });
        }
    });
    
    if (rbs.length === 0) {
        alert('Nenhum dos peers selecionados possui um NAS válido (MK-Auth) cadastrado.');
        return false;
    }
    
    // --- TRAVA DE SEGURANÇA (EXATAMENTE COMO NA OUTRA ABA) ---
    const msgConfirmacao = "✨ Executar o Auto OTP (One Touch Provisioning) nos Peers selecionados?\n\nO sistema irá se conectar via SSH a cada RB para aplicar as configurações do WireGuard automaticamente.";
    
    if (confirm(msgConfirmacao)) {
        // Se ele clicar em OK, a mágica acontece
        abrirModalOtp(rbs);
    }
    // Se clicar em Cancelar, nada acontece e ele volta pra tabela de boa!
}

async function abrirModalOtp(rbs) {
    const modal = document.getElementById('modal_otp_progress');
    const container = document.getElementById('otp_log_container');
    const btnFechar = document.getElementById('btn_fechar_otp');
    
    if(!modal) return alert("HTML do modal não encontrado!");
    
    modal.classList.add('is-active');
    container.innerHTML = `<div style="color: #38bdf8; font-weight: bold;">⚡ Iniciando fila de injeção em ${rbs.length} RouterBoard(s)...</div><br>`;
    btnFechar.disabled = true;
    btnFechar.innerText = "Aguarde o Processo...";
    
    for(let i = 0; i < rbs.length; i++) {
        let rb = rbs[i];
        
        let logLine = document.createElement('div');
        logLine.innerHTML = `<span style="color:#94a3b8;">[${i+1}/${rbs.length}]</span> Processando <b>${rb.nome}</b>... <i class="bi bi-hourglass-split" style="animation: spin 2s linear infinite; color: #facc15;"></i>`;
        container.appendChild(logLine);
        container.scrollTop = container.scrollHeight;
        
        let formData = new FormData();
        formData.append('acao', 'executar_otp_unitario');
        formData.append('id_nas', rb.id_nas);
        
        try {
            let res = await fetch(window.location.href, { method: 'POST', body: formData });
            let data = await res.json();
            
            if(data.status === 'ok') {
                logLine.innerHTML = `
                    <div style="margin-bottom: 15px; border-left: 2px solid #4ade80;">
                        <span style="color:#4ade80; font-weight: bold; margin-left: 10px;">[${i+1}/${rbs.length}] ✅ SUCESSO NO NAS: ${rb.nome}</span>
                        ${data.msg_html}
                    </div>`;
            } else {
                logLine.innerHTML = `<span style="color:#f87171;">[${i+1}/${rbs.length}] ❌ Falha em <b>${rb.nome}</b>: ${data.msg}</span>`;
                console.warn("Log SSH Falha:", data.debug);
            }
        } catch(e) {
            logLine.innerHTML = `<span style="color:#f87171;">[${i+1}/${rbs.length}] ❌ Erro Crítico: Falha na requisição ao servidor.</span>`;
        }
        container.scrollTop = container.scrollHeight;
    }
    
    container.innerHTML += `<br><div style="color: #38bdf8; font-weight: bold;">✨ Processo Finalizado!</div>`;
    btnFechar.disabled = false;
    btnFechar.innerText = "Concluir e Atualizar Tela";
    btnFechar.onclick = function() { window.location.reload(); };
}

function fecharModalOtp() {
    document.getElementById('modal_otp_progress').classList.remove('is-active');
}

// ==============================================================
// RADAR LIVE STATS - O "Efeito WinBox" (Atualiza Tudo ao Vivo)
// ==============================================================

// Converte bytes para formato humano
function formatarBytesJS(bytes) {
    if (bytes <= 0) return '<span class="has-text-grey-light">0 B</span>';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Formata o Timestamp do Handshake para "Hoje às HH:MM" ou "DD/MM às HH:MM"
function formatarDataHandshakeJS(timestamp) {
    if (!timestamp || timestamp === 0) return '-';
    const date = new Date(timestamp * 1000);
    const now = new Date();
    
    const isToday = date.getDate() === now.getDate() && date.getMonth() === now.getMonth() && date.getFullYear() === now.getFullYear();
    const hh = String(date.getHours()).padStart(2, '0');
    const mm = String(date.getMinutes()).padStart(2, '0');
    
    if (isToday) {
        return `Hoje às ${hh}:${mm}`;
    } else {
        const dd = String(date.getDate()).padStart(2, '0');
        const mo = String(date.getMonth() + 1).padStart(2, '0');
        return `${dd}/${mo} às ${hh}:${mm}`;
    }
}

// --- VARIÁVEIS DO FAST-DETECT ---
let historicoPeers = {}; 
const TEMPO_LIMITE_RX_SEGUNDOS = 35; // Se o RX não subir por 35 segundos, marca como Offline
// 🤫 MÁGICA: Função para mostrar/esconder o ping ao clicar na Tag Online
window.togglePingJS = function(pubKey) {
    if (historicoPeers[pubKey]) {
        // Inverte o estado (Se tava escondido, mostra. Se tava mostrando, esconde)
        historicoPeers[pubKey].showPing = !historicoPeers[pubKey].showPing;
        
        // Atualiza a tela na mesma hora, sem esperar o Radar dar a volta!
        let row = document.querySelector(`.wg-peer-row[data-pubkey="${pubKey}"]`);
        if (row) {
            let pingSpan = row.querySelector('.wg-ping-span');
            if (pingSpan) {
                pingSpan.style.display = historicoPeers[pubKey].showPing ? 'inline-block' : 'none';
            }
        }
    }
};

// Inicia o Radar a cada 5 segundos
setInterval(function() {
    let formData = new FormData();
    formData.append('acao', 'get_live_stats');

    // Bate silenciosamente no nosso backend
    fetch(window.location.href, {
        method: 'POST',
        body: formData
    })
    .then(res => res.json())
    .then(data => {
        if(data.status === 'ok') {
            let agora = Date.now(); // Pega a hora exata deste pulso do radar

            // Varre cada linha da tabela
            document.querySelectorAll('.wg-peer-row').forEach(row => {
                let pubKey = row.getAttribute('data-pubkey');
                
                if(data.peers[pubKey]) {
                    let liveData = data.peers[pubKey];
                    
                    // --- 🧠 INÍCIO DA LÓGICA FAST-DETECT (RX) ---
                    if (!historicoPeers[pubKey]) {
                        // Primeira vez que vemos o peer, salva o RX atual
                        historicoPeers[pubKey] = {
                            ultimoRx: liveData.rx,
                            ultimaVezQueMexeu: agora
                        };
                    }

                    let memoria = historicoPeers[pubKey];
                    let tempoCongelado = (agora - memoria.ultimaVezQueMexeu) / 1000;

                    // O RX Subiu?
                    if (liveData.rx > memoria.ultimoRx) {
                        memoria.ultimoRx = liveData.rx;      // Atualiza o novo recorde de RX
                        memoria.ultimaVezQueMexeu = agora;   // Zera o cronômetro de inatividade
                        tempoCongelado = 0;
                    }

                    // A MÁGICA ACONTECE AQUI:
                    // O cliente só fica com a tag Online SE o PHP confirmar (Handshake < 3 min) 
                    // E se o RX não estiver congelado há mais tempo que o nosso limite (35s)
                    let isRealmenteOnline = liveData.online && (tempoCongelado <= TEMPO_LIMITE_RX_SEGUNDOS);
                    // --- 🧠 FIM DA LÓGICA FAST-DETECT ---

                    let cellRx = row.querySelector('.wg-rx-cell');
                    let cellTx = row.querySelector('.wg-tx-cell');
                    let cellStatus = row.querySelector('.wg-status-cell');
                    let cellEndpoint = row.querySelector('.wg-endpoint-cell');
                    let cellHandshake = row.querySelector('.wg-handshake-cell');
                    
                    // 1. Atualiza RX e TX girando os números
                    if(cellRx && cellTx) {
                        cellRx.setAttribute('data-bytes', liveData.rx);
                        cellRx.querySelector('.texto-bytes').innerHTML = formatarBytesJS(liveData.rx);
                        
                        cellTx.setAttribute('data-bytes', liveData.tx);
                        cellTx.querySelector('.texto-bytes').innerHTML = formatarBytesJS(liveData.tx);
                    }
                    
                    // 2. Atualiza Endpoint (IP:Porta ou tracinho)
                    if(cellEndpoint) {
                        if(liveData.endpoint && liveData.endpoint !== '(none)' && liveData.endpoint !== '') {
                            cellEndpoint.innerHTML = `<code style="background-color: #f1f5f9; color: #475569; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; border: 1px solid #e2e8f0; white-space: nowrap;">${liveData.endpoint}</code>`;
                        } else {
                            cellEndpoint.innerHTML = '<span style="color: #94a3b8;">-</span>';
                        }
                    }

                    // 3. Atualiza Status, Handshake e CHECK-TUNNEL (Ping Assíncrono)
                    if(cellStatus && cellHandshake) {
                        let isDisabled = cellStatus.getAttribute('data-disabled') === '1';
                        let isMaquete = cellStatus.getAttribute('data-is-maquete') === '1';
                        let ipLimpo = row.getAttribute('data-wg-ip'); // Pega o IP limpo do HTML
                        
                        if (!isDisabled) {
                            let horaFormatada = formatarDataHandshakeJS(liveData.handshake);
                            
                            if(isRealmenteOnline) { 
                                // --- O CLIENTE PARECE ONLINE. VAMOS TIRAR A PROVA REAL! ---
                                
                                if (!memoria.ultimoPingTs) memoria.ultimoPingTs = 0;
                                if (!memoria.statusRota) memoria.statusRota = 'HEALTHY';
                                if (typeof memoria.showPing === 'undefined') memoria.showPing = false; // Começa escondido
                                
                                // Dispara o ping a cada 10 segundos silenciosamente
                                if (agora - memoria.ultimoPingTs > 10000) {
                                    memoria.ultimoPingTs = agora;
                                    
                                    let formPing = new FormData();
                                    formPing.append('acao', 'check_tunnel_unitario');
                                    formPing.append('target_ip', ipLimpo);
                                    
                                    fetch(window.location.href, { method: 'POST', body: formPing })
                                        .then(r => r.json())
                                        .then(pingData => {
                                            if (pingData.ok && pingData.data) {
                                                memoria.statusRota = pingData.data.status_code;
                                                memoria.latencia = pingData.data.latency;
                                            }
                                        }).catch(() => {});
                                }

                                // --- RENDERIZAÇÃO BASEADA NO PING ---
                                if (memoria.statusRota === 'ROUTING_FAULT') {
                                    // 🔴 FALSO ONLINE CAÇADO! (Usando as cores pastéis harmonizadas)
                                    cellStatus.innerHTML = `<span class="tag wg-btn-status" title="IP incorreto na RB! As chaves batem, mas o Ping falhou." style="background-color: #fee2e2; color: #991b1b; border: 1px solid #fca5a5; font-weight: bold;"><i class="bi bi-x-octagon-fill mr-1"></i> Erro de Rota</span>`;
                                    
                                    cellHandshake.innerHTML = `
                                        <i class="fa fa-handshake-o mr-1" style="color: #0ea5e9; font-size: 0.95rem;"></i>
                                        <span style="color:#0f172a; text-decoration: line-through;">${horaFormatada}</span>
                                        <i class="bi bi-sign-stop-fill ml-2" style="color: #ef4444;" title="Rota Quebrada"></i>`;
                                } else {
                                    // 🟢 VERDADEIRO ONLINE (Ping OK)
                                    
                                    // 🎨 CORREÇÃO DAS CORES: Usa opacidade herdeira, sem estragar sua paleta!
                                    let displayPing = memoria.showPing ? 'inline' : 'none';
                                    let latenciaBadge = memoria.latencia ? `<span class="wg-ping-span" style="display: ${displayPing}; opacity: 0.75; font-size: 0.85em; margin-left: 4px;">(${memoria.latencia})</span>` : '';
                                    
                                    // Transforma a tag inteira em um botão clicável (SEM DUPLICAR O STYLE!)
                                    let onClick = `onclick="window.togglePingJS('${pubKey}')"`;
                                    let tituloHover = "Túnel OK. Clique para mostrar/ocultar a Latência";

                                    if(isMaquete) {
                                        cellStatus.innerHTML = `<span class="tag wg-btn-status status-online-glow" title="${tituloHover}" ${onClick} style="cursor: pointer; user-select: none; background-color: #f3e8ff; color: #7e22ce; border: 1px solid #d8b4fe; font-weight: 600;"><i class="bi bi-diagram-2-fill mr-1"></i> Online (Paralelo)${latenciaBadge}</span>`;
                                    } else {
                                        cellStatus.innerHTML = `<span class="tag wg-btn-status status-online-glow" title="${tituloHover}" ${onClick} style="cursor: pointer; user-select: none; background-color: #dcfce7; color: #166534; border: 1px solid #86efac; font-weight: 600;"><i class="bi bi-diagram-2-fill mr-1"></i> Online (Oficial)${latenciaBadge}</span>`;
                                    }
                                    
                                    cellHandshake.innerHTML = `
                                        <i class="fa fa-handshake-o mr-1" style="color: #0ea5e9; font-size: 0.95rem;" title="Handshake estabelecido"></i>
                                        <span style="color:#0f172a; font-weight: 500;">${horaFormatada}</span>
                                        <i class="bi bi-activity wg-icon-handshake icon-online ml-2" title="Túnel Ativo e Comunicando!"></i>`;
                                }

                            } else {
                                // MODO OFFLINE RAIZ (Sem Handshake)
                                memoria.statusRota = null; // Reseta o estado do ping
                                
                                if(isMaquete) {
                                    cellStatus.innerHTML = `<span class="tag is-warning wg-btn-status" style="background-color: #ffedd5; color: #9a3412; border: 1px solid #fdba74; font-weight: 600;"><i class="bi bi-exclamation-triangle-fill mr-1"></i> Offline (Paralelo)</span>`;
                                } else {
                                    cellStatus.innerHTML = `<span class="tag is-warning wg-btn-status" style="background-color: #ffedd5; color: #9a3412; border: 1px solid #fdba74; font-weight: 600;"><i class="bi bi-exclamation-triangle-fill mr-1"></i> Offline (Oficial)</span>`;
                                }
                                
                                cellHandshake.innerHTML = `
                                    <i class="fa fa-handshake-o has-text-grey-light mr-1" style="font-size: 0.95rem;"></i>
                                    <span class="has-text-grey-light">${horaFormatada}</span>
                                    <i class="bi bi-activity wg-icon-handshake has-text-grey-light ml-2" title="Túnel Parado"></i>`;
                            }
                        }
                    }
                }
            });
        }
    })
    .catch(err => console.log("Radar Live em repouso..."));
}, 5000); // 5000 ms = 5 Segundos
/**
 * Revela os botões de funções nativas do RouterOS após o usuário aceitar o risco
 * @param {number} id_peer ID da linha do peer 
 */
function revelarPerigo(id_peer) {
    const titulo = "⚠️ ALERTA: RECURSO NATIVO FALHO!";
    
    // TEXTO DO SWEETALERT2 (Com links em HTML)
    const textoHTML = `
        <div style="text-align: left; font-size: 14px; color: #475569; line-height: 1.5;">
            <p>Os comandos nativos do ROS7.x WG Import (WinBox) e config-string são <b>limitados!</b></p>
            
            <p style="color: #dc2626; font-weight: 600; background: #fee2e2; padding: 10px; border-radius: 6px; margin: 15px 0;">
                Eles <b>NÃO</b> possuem lógica de <b>idempotência</b> e estão sujeitos a duplicar interfaces e endereços IP se executados mais de uma vez.
            </p>
            
            <p>Para atestar, veja os diversos relatos de bugs e crashes no <b>Fórum Oficial da MikroTik</b>:</p>
            <ul style="margin-left: 20px; margin-bottom: 15px; font-size: 13px;">
                <li><a href="https://forum.mikrotik.com/viewtopic.php?t=207479" target="_blank" style="color: #2563eb;">Relato 1: RouterOS sofrendo Crash (Reboot) ao importar configuração do Wireguard.</a></li>
                <li><a href="https://forum.mikrotik.com/t/wg-import-function-odd-behaviour/181481" target="_blank" style="color: #2563eb;">Relato 2: Comportamento bizarro da função “WG Import” ("odd behaviour")</a></li>
            </ul>
            
            <hr style="border-top: 1px solid #cbd5e1; margin: 15px 0;">
            
            <p><b>Por que o método sugerido pelo ADDON é melhor? 😎</b></p>
            <p>O método <b>.RSC</b> é inteligente, idempotente e faz uma varredura prévia no ambiente, garantindo a <b>não duplicidade</b>.</p>
            
            <p style="margin-top: 15px; font-weight: bold; color: #1e293b;">Deseja liberar as opções de importação nativas por SUA CONTA E RISCO?</p>
        </div>
    `;

    if (typeof Swal !== 'undefined') {
        Swal.fire({
            title: titulo,
            html: textoHTML,
            icon: 'warning',
            iconColor: '#f59e0b',
            showCancelButton: true,
            confirmButtonColor: '#ef4444',
            cancelButtonColor: '#3b82f6',
            confirmButtonText: 'Sim, assumo o risco!',
            cancelButtonText: 'Melhor não (Recomendado)',
            width: '650px'
        }).then((result) => {
            if (result.isConfirmed) {
                // Esconde O BOTÃO EXATO amarelo pelo ID
                const btnNativas = document.getElementById('btn_nativas_' + id_peer);
                if(btnNativas) btnNativas.style.display = 'none';
                
                // Mostra os botões vermelhos
                document.getElementById('botoes_perigo_' + id_peer).style.display = 'inline-block';
            }
        });
    } else {
        // TEXTO DO ALERTA NATIVO (Texto Puro)
        let msg = "⚠️ ALERTA: Os comandos nativos do ROS7.x WG Import (WinBox) e config-string são limitados!\n\n";
        msg += "Eles NÃO possuem lógica de IDEMPOTÊNCIA e estão sujeitos a duplicar interfaces e endereços IP se rodado mais de uma vez.\n\n";
        
        msg += "Veja os relatos de bugs e crashes no Fórum Oficial:\n";
        msg += "1. forum.mikrotik.com/viewtopic.php?t=207479\n";
        msg += "2. forum.mikrotik.com/t/wg-import-function-odd-behaviour/181481\n\n";
        
        msg += "O método .RSC é inteligente, idempotente, faz uma varredura prévia no ambiente, garantindo a não duplicidade.\n\n";
        msg += "Deseja liberar as opções de importação nativas por SUA CONTA E RISCO? (NÃO RECOMENDADO)";
        
        if (confirm(msg)) {
            // Esconde O BOTÃO EXATO amarelo pelo ID
            const btnNativas = document.getElementById('btn_nativas_' + id_peer);
            if(btnNativas) btnNativas.style.display = 'none';
            
            // Mostra os botões vermelhos
            document.getElementById('botoes_perigo_' + id_peer).style.display = 'inline-block';
        }
    }
}
// ==============================================================
// MODAL DE INFORMAÇÕES DO OTP 
// ==============================================================
function abrirModalInfoOtp() {
    var modal = document.getElementById('modal_info_otp');
    if(modal) modal.classList.add('is-active');
}

function fecharModalInfoOtp() {
    var modal = document.getElementById('modal_info_otp');
    if(modal) modal.classList.remove('is-active');
}
