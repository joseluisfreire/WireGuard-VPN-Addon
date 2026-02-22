// addon_wireguard.js

// URL base do admin
const minha_url = window.location.protocol + "//" + window.location.hostname
  + (window.location.port ? ':' + window.location.port : '') + "/admin/";

// Adiciona item no menu (ex.: menu Provedor; ajuste conforme preferir)
add_menu.provedor('{ "plink": "' + minha_url + 'addons/wireguard/", "ptext": "WireGuard VPN" }');

// A última linha deve apontar para a pasta do addon:
addon_url + 'addons/wireguard/';
