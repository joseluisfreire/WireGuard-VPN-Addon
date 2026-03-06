<div class="tabs is-boxed">
  <ul>
    <!-- ========================================
         ABA STATUS (sempre acessível)
         ======================================== -->
    <li class="<?php echo ($tab === 'status') ? 'is-active' : ''; ?>">
      <a href="?tab=status">
        <span class="icon"><i class="bi bi-server"></i></span>
        <span>Servidor WireGuard</span>
      </a>
    </li>

    <?php if ($daemon_ok): ?>
      <!-- ========================================
           ABAS HABILITADAS (daemon online)
           ======================================== -->
      <li class="<?php echo ($tab === 'peers') ? 'is-active' : ''; ?>">
        <a href="?tab=peers">
          <span class="icon"><i class="bi bi-people-fill"></i></span>
          <span>Peers</span>
        </a>
      </li>
      <li class="<?php echo ($tab === 'provisionar') ? 'is-active' : ''; ?>">
        <a href="?tab=provisionar">
          <span class="icon"><i class="bi bi-hdd-rack-fill"></i></span>
          <span>Provisionar Ramais</span>
        </a>
      </li>
      <li class="<?php echo ($tab === 'criar') ? 'is-active' : ''; ?>">
        <a href="?tab=criar">
          <span class="icon"><i class="bi bi-plus-circle-fill"></i></span>
          <span>Criar Peer</span>
        </a>
      </li>
      
    <?php else: ?>
      <!-- ========================================
           ABAS DESABILITADAS (daemon offline)
           ======================================== -->
      <li class="is-disabled" title="Requer daemon WireGuard online">
        <a>
          <span class="icon"><i class="bi bi-people-fill"></i></span>
          <span>Peers</span>
        </a>
      </li>
      <li class="is-disabled" title="Requer daemon WireGuard online">
        <a>
          <span class="icon"><i class="bi bi-hdd-rack-fill"></i></span>
          <span>Provisionar Ramais</span>
        </a>
      </li>
      <li class="is-disabled" title="Requer daemon WireGuard online">
        <a>
          <span class="icon"><i class="bi bi-plus-circle-fill"></i></span>
          <span>Criar Peer</span>
        </a>
      </li>
    <?php endif; ?>
  </ul>
</div>
<!-- ========================================
     BLOQUEIO: Daemon offline
     ======================================== -->
<?php if ($tab !== 'status' && !$daemon_ok): ?>
    <div class="notification is-warning">
        <p class="title is-5">
            <span class="icon has-text-warning">
                <i class="bi bi-exclamation-triangle-fill"></i>
            </span>
            Daemon WireGuard Offline
        </p>
        <p>
            As funcionalidades de <strong>Peers</strong>, <strong>Provisionar Ramais</strong> 
            e <strong>Criar Peer</strong> requerem que o serviço <code>wg-mkauthd</code> 
            esteja em execução.
        </p>
        <div class="content" style="margin-top: 1.5rem;">
            <p><strong>Diagnóstico (SysVinit):</strong></p>
            <pre style="background: #f5f5f5; padding: 0.75rem; border-radius: 4px;"><code># Verificar se daemon está rodando
ps aux | grep wg-mkauthd | grep -v grep

# Verificar socket
ls -l /run/wgmkauth.sock

# Iniciar daemon
service wg-mkauthd start

# Verificar logs
tail -50 /var/log/wg-mkauthd.log</code></pre>
        </div>
        <p style="margin-top: 1rem;">
            <a href="https://wiki.mk-auth.com.br/doku.php?id=mk-auth_addons" 
               target="_blank" 
               class="button is-info is-light">
                <span class="icon"><i class="bi bi-book"></i></span>
                <span>Documentação</span>
            </a>
        </p>
    </div>
<?php 
    // Força sair do script aqui para não renderizar conteúdo das abas
    include('../../baixo.php'); 
    echo '<script src="../../menu.js.hhvm"></script>';
    echo '<script src="wg_addon.js"></script>';
    echo '</body></html>';
    exit;
endif; 
?>

