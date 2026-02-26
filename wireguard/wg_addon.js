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
