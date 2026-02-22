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
