'use strict';

const REFRESH_MS = 30000;
const $ = (selector) => document.querySelector(selector);
let session = null;
let config = null;
let lastRole = {};
let operating = false;
let timer = null;
let emergencyMode = false;

class ApiError extends Error { constructor(message, code, status) { super(message); this.code = code; this.status = status; } }

async function api(path, options = {}) {
  const request = { credentials: 'same-origin', cache: 'no-store', ...options };
  request.headers = { Accept: 'application/json', ...(options.headers || {}) };
  if (request.body && !request.headers['Content-Type']) request.headers['Content-Type'] = 'application/json';
  if (request.method && !['GET', 'HEAD'].includes(request.method) && session?.csrf_token) request.headers['X-CSRF-Token'] = session.csrf_token;
  const response = await fetch(path, request);
  let body = {}; try { body = await response.json(); } catch { /* empty */ }
  if (!response.ok) throw new ApiError(body.error || body.detail?.message || `HTTP ${response.status}`, body.code || body.detail?.code, response.status);
  return body;
}

function el(tag, content, className) { const node = document.createElement(tag); if (className) node.className = className; if (content !== undefined && content !== null) node.textContent = String(content); return node; }
function cell(label, className, content) { const td = el('td', content, className); if (label) td.dataset.etiqueta = label; return td; }
function json(data) { return JSON.stringify(data); }
function message(target, text, ok = false) { const box = $(target); box.textContent = text; box.className = `recado ${ok ? 'bien' : 'mal'}`; }
function clearMessage(target) { $(target).className = 'recado oculto'; }

let dialogResolve = null;
let dialogLastFocus = null;

function closeAppDialog(accepted = false) {
  if (!dialogResolve) return;
  const resolve = dialogResolve;
  dialogResolve = null;
  $('#app-dialog-layer').classList.add('oculto');
  $('#app-dialog-layer').setAttribute('aria-hidden', 'true');
  document.body.classList.remove('dialog-open');
  if (dialogLastFocus?.isConnected) dialogLastFocus.focus();
  dialogLastFocus = null;
  resolve(accepted);
}

function confirmAction({ title, message: text, confirmText = 'Continuar', tone = 'warning' }) {
  if (dialogResolve) closeAppDialog(false);
  dialogLastFocus = document.activeElement;
  const panel = $('#app-dialog');
  panel.className = `dialog-panel${tone === 'danger' ? ' danger' : ''}`;
  $('#app-dialog-symbol').textContent = tone === 'danger' ? '!' : '?';
  $('#app-dialog-eyebrow').textContent = tone === 'danger' ? 'OPERACIÓN DE RIESGO' : 'CONFIRMAR OPERACIÓN';
  $('#app-dialog-title').textContent = title;
  $('#app-dialog-message').textContent = text;
  $('#app-dialog-confirm').textContent = confirmText;
  $('#app-dialog-layer').classList.remove('oculto');
  $('#app-dialog-layer').setAttribute('aria-hidden', 'false');
  document.body.classList.add('dialog-open');
  return new Promise((resolve) => {
    dialogResolve = resolve;
    $('#app-dialog-confirm').focus();
  });
}

function notify(title, text, tone = 'info') {
  const symbols = { success: '✓', warning: '!', error: '×', info: 'i' };
  const toast = el('section', null, `toast ${tone}`);
  toast.setAttribute('role', tone === 'error' ? 'alert' : 'status');
  const symbol = el('span', symbols[tone] || symbols.info, 'toast-symbol');
  symbol.setAttribute('aria-hidden', 'true');
  const copy = el('div', null, 'toast-copy');
  copy.append(el('strong', title), el('p', text));
  const close = el('button', '×', 'toast-close');
  close.type = 'button'; close.setAttribute('aria-label', 'Cerrar notificación');
  const remove = () => toast.remove();
  close.addEventListener('click', remove);
  toast.append(symbol, copy, close);
  $('#toast-region').prepend(toast);
  while ($('#toast-region').children.length > 4) $('#toast-region').lastElementChild.remove();
  window.setTimeout(remove, tone === 'error' ? 15000 : tone === 'warning' ? 12000 : 8000);
  return toast;
}

$('#app-dialog-cancel').addEventListener('click', () => closeAppDialog(false));
$('#app-dialog-confirm').addEventListener('click', () => closeAppDialog(true));
$('#app-dialog-layer').addEventListener('click', (event) => {
  if (event.target === $('#app-dialog-layer')) closeAppDialog(false);
});
document.addEventListener('keydown', (event) => {
  if (!dialogResolve) return;
  if (event.key === 'Escape') { event.preventDefault(); closeAppDialog(false); return; }
  if (event.key !== 'Tab') return;
  const focusable = [$('#app-dialog-cancel'), $('#app-dialog-confirm')];
  const first = focusable[0]; const last = focusable[focusable.length - 1];
  if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
  else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
});

function showLogin() { $('#app-view').classList.add('oculto'); $('#login-view').classList.remove('oculto'); }
function showSetup() {
  $('#login-view').classList.add('oculto'); $('#app-view').classList.add('oculto');
  $('#setup-view').classList.remove('oculto');
}

function parseMembers(value) {
  return value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map((line) => {
    const parts = line.split('|').map((part) => part.trim());
    if (parts.length !== 3) throw new Error(`Línea de miembro no válida: ${line}`);
    return { name: parts[0], address: parts[1], guardian_url: parts[2] };
  });
}
function formatMembers(members) { return (members || []).map((member) => `${member.name} | ${member.address} | ${member.guardian_url || ''}`).join('\n'); }
function setupMembers() { return parseMembers($('#setup-members').value); }

function suggestLocalMember() {
  if (!$('#setup-members').value.trim() && $('#setup-node').value.trim() && $('#setup-address').value.trim()) {
    $('#setup-members').value = `${$('#setup-node').value.trim()} | ${$('#setup-address').value.trim()} |`;
  }
}
$('#setup-node').addEventListener('blur', suggestLocalMember);
$('#setup-address').addEventListener('blur', suggestLocalMember);
$('#setup-standalone').addEventListener('change', () => {
  const disabled = $('#setup-standalone').checked;
  ['#setup-keepalived-url', '#setup-keepalived-service', '#setup-keepalived-token', '#setup-keepalived-ca', '#setup-keepalived-http'].forEach((selector) => { $(selector).disabled = disabled; });
  $('#setup-keepalived-url').required = !disabled; $('#setup-keepalived-service').required = !disabled;
});

$('#setup-form').addEventListener('submit', async (event) => {
  event.preventDefault(); const button = $('#setup-save'); button.disabled = true; clearMessage('#setup-message');
  try {
    const standalone = $('#setup-standalone').checked;
    const payload = {
      node: $('#setup-node').value.trim(), members: setupMembers(), standalone,
      enrollment_code: $('#setup-enrollment').value.trim(),
      keepalived: { url: standalone ? '' : $('#setup-keepalived-url').value.trim(), service: standalone ? '' : $('#setup-keepalived-service').value.trim(), token: standalone ? '' : $('#setup-keepalived-token').value.trim(), ca_certificate: standalone ? '' : $('#setup-keepalived-ca').value.trim(), allow_http: standalone ? false : $('#setup-keepalived-http').checked },
      portal: { public_url: $('#setup-public-url').value.trim(), public_port: Number($('#setup-public-port').value), session_minutes: Number($('#setup-session-minutes').value), trusted_proxies: $('#setup-proxies').value.trim(), allow_http: $('#setup-portal-http').checked },
      npm: { container: $('#setup-npm-container').value.trim(), scheme: $('#setup-npm-scheme').value, api_port: Number($('#setup-npm-port').value), https_port: Number($('#setup-npm-https-port').value), ca_certificate: $('#setup-npm-ca').value.trim(), allow_http: $('#setup-npm-http').checked },
    };
    const result = await api('/api/bootstrap', { method: 'POST', body: json(payload) });
    $('#setup-form').classList.add('oculto');
    if (result.enrollment_code) {
      $('#setup-code').value = result.enrollment_code; $('#setup-code-card').classList.remove('oculto');
    } else {
      message('#setup-message', 'ConfiguraciÃ³n guardada. Guardian se estÃ¡ iniciando.', true);
      $('#setup-form').classList.remove('oculto'); window.setTimeout(() => window.location.reload(), 1500);
    }
  } catch (error) { message('#setup-message', error.message); button.disabled = false; }
});
$('#setup-code-copy').addEventListener('click', async () => {
  const field = $('#setup-code');
  try { await navigator.clipboard.writeText(field.value); } catch { field.select(); document.execCommand('copy'); }
});
async function refreshLoginGuidance() {
  try {
    const status = await api('/api/public/status');
    if (status.setup_required) {
      $('#login-heading').textContent = 'Vincular administrador de NPM';
      $('#login-help').textContent = 'Primer acceso: entra con una cuenta administradora de NPM. Guardian guardará su identidad, nunca la contraseña.';
    } else {
      $('#login-heading').textContent = 'Entrar en NPM Guardian';
      $('#login-help').textContent = 'Usa tus credenciales actuales de NPM. Guardian las valida en el nodo activo y no conserva la contraseña.';
    }
  } catch { $('#login-help').textContent = 'Introduce las credenciales del NPM activo.'; }
}
function showApp() {
  $('#login-view').classList.add('oculto'); $('#app-view').classList.remove('oculto');
  $('#profile-name').value = session.display_name || session.username || '';
}

function setEmergencyMode(enabled) {
  emergencyMode = enabled;
  $('#login-password-wrap').classList.toggle('oculto', enabled);
  $('#login-password').required = !enabled;
  $('#login-otp-wrap').classList.add('oculto'); $('#login-otp').required = false;
  $('#login-recovery-wrap').classList.toggle('oculto', !enabled);
  $('#login-recovery').required = enabled;
  $('#login-button').textContent = enabled ? 'Entrar con código de recuperación' : 'Entrar';
  $('#emergency-toggle').textContent = enabled ? 'Volver al acceso normal' : 'Usar acceso de emergencia';
  if (enabled) $('#login-help').textContent = 'Disponible sólo si NPM está caído. Consume un código de recuperación de Guardian.';
  else void refreshLoginGuidance();
}

$('#emergency-toggle').addEventListener('click', () => setEmergencyMode(!emergencyMode));

async function refreshSession() { session = await api('/api/session'); showApp(); return session; }

$('#login-form').addEventListener('submit', async (event) => {
  event.preventDefault(); const button = $('#login-button'); button.disabled = true; clearMessage('#login-error');
  try {
    const payload = emergencyMode ? { username: $('#login-user').value, recovery_code: $('#login-recovery').value, emergency: true } : { username: $('#login-user').value, password: $('#login-password').value, otp: $('#login-otp').value || null };
    session = await api('/api/session', { method: 'POST', body: json(payload) });
    showApp(); await Promise.all([loadConfig(), refreshDashboard()]); renderTwoFactor(); startTimer();
  } catch (error) {
    if (error.code === 'TWO_FACTOR_REQUIRED') { $('#login-otp-wrap').classList.remove('oculto'); $('#login-otp').required = true; $('#login-otp').focus(); }
    if (error.code === 'NPM_AUTH_UNAVAILABLE') { $('#emergency-toggle').classList.remove('oculto'); }
    message('#login-error', error.message);
  } finally { button.disabled = false; }
});

$('#logout').addEventListener('click', async () => { try { await api('/api/session', { method: 'DELETE' }); } catch { /* local logout anyway */ } session = null; clearInterval(timer); setEmergencyMode(false); showLogin(); });

function switchView(name) {
  document.querySelectorAll('.vista-panel').forEach((node) => node.classList.toggle('oculto', node.id !== `view-${name}`));
  document.querySelectorAll('.tabs button').forEach((node) => node.classList.toggle('activo', node.dataset.view === name));
  if (name === 'config') void loadConfig(); if (name === 'profile') renderTwoFactor();
}
document.querySelectorAll('.tabs button').forEach((button) => button.addEventListener('click', () => switchView(button.dataset.view)));
$('#profile-shortcut').addEventListener('click', () => switchView('profile'));

function dayClass(days) { if (days == null) return ''; if (days < 0) return 'pasado'; if (days <= 15) return 'urgente'; if (days <= 30) return 'cerca'; return 'lejos'; }

function readableDate(value) {
  if (!value) return 'Sin comprobar';
  const raw = String(value);
  const date = new Date(raw.includes('T') ? raw : raw.replace(' ', 'T'));
  if (Number.isNaN(date.getTime())) return String(value).replace('T', ' ');
  return date.toLocaleString('es-ES', {
    day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

function setStatusCard(cardSelector, badgeSelector, tone, label) {
  $(cardSelector).dataset.tone = tone;
  const badge = $(badgeSelector);
  badge.className = `status-badge ${tone}`;
  badge.textContent = label;
}

function paintRole(role) {
  lastRole = role || {};
  $('#active-node').textContent = role.activo || 'Sin determinar';
  $('#floating-ip').textContent = role.ip || (role.origen === 'modo independiente declarado' ? 'No aplica' : '—');
  $('#role-source').textContent = role.origen === 'modo independiente declarado' ? 'Modo independiente' : 'Keepalived';
  if (role.soy_yo === true) {
    setStatusCard('#ha-card', '#ha-status', 'ok', 'Nodo activo');
    $('#role-detail').textContent = 'Este nodo atiende el portal y coordina las operaciones y la réplica.';
  } else if (role.activo) {
    setStatusCard('#ha-card', '#ha-status', 'info', 'Activo localizado');
    $('#role-detail').textContent = 'El portal completo sólo está disponible en el nodo que posee la IP flotante.';
  } else {
    setStatusCard('#ha-card', '#ha-status', 'warning', 'Sin determinar');
    $('#role-detail').textContent = role.origen || 'Keepalived todavía no ha identificado un nodo activo.';
  }
  if (role.soy_yo !== true) setTimeout(() => window.location.reload(), 1000);
}

function paintCertificates(certificates) {
  const items = certificates || [];
  const risk = items.filter((cert) => cert.dias != null && cert.dias <= 30).length;
  $('#cert-total').textContent = `${items.length} certificado${items.length === 1 ? '' : 's'}`;
  $('#cert-risk').textContent = `${risk} en 30 días`;
  if (operating) return; const body = $('#cuerpo-certs'); body.textContent = '';
  if (!certificates?.length) { const row = el('tr'); const td = cell('', 'vacio', 'No hay certificados o no se puede leer NPM.'); td.colSpan = 5; row.append(td); body.append(row); return; }
  certificates.forEach((cert) => {
    const row = el('tr'); row.append(cell('Certificado', 'servicio', cert.nombre)); row.append(cell('Caduca', 'puertos', (cert.caduca || '—').replace('T', ' ')));
    const days = cell('Quedan'); const badge = el('span', cert.dias == null ? '—' : cert.dias < 0 ? 'caducado' : `${cert.dias} días`, `dias ${dayClass(cert.dias)}`); badge.title = cert.caduca ? `Caducidad exacta: ${cert.caduca}` : ''; days.append(badge); row.append(days);
    row.append(cell('Método', 'desc', cert.reto_dns ? `DNS-01 · ${cert.proveedor_dns || '?'}` : (cert.proveedor || '—')));
    const action = cell('', 'sin-etiqueta'); const button = el('button', 'Renovar ahora'); button.type = 'button'; button.addEventListener('click', () => renew(cert, button)); action.append(button); row.append(action); body.append(row);
  });
}

function nodeService(name, value, tone) {
  const row = el('div', null, 'linea-serv');
  row.append(el('span', name, 'nom'), el('span', value, `est ${tone}`));
  return row;
}

function sameNode(left, right) { return String(left || '').toLocaleLowerCase('es') === String(right || '').toLocaleLowerCase('es'); }
function displayVersion(value) {
  const version = String(value || '?');
  return version.startsWith('v') ? version : `v${version}`;
}

function paintNodes(nodes, role) {
  const grid = $('#rejilla-nodos'); grid.textContent = '';
  const entries = Object.entries(nodes || {}).sort(([left], [right]) => {
    if (sameNode(left, role?.activo)) return -1; if (sameNode(right, role?.activo)) return 1;
    return left.localeCompare(right, 'es');
  });
  const available = entries.filter(([, node]) => node.alcanzable && node.npm_accesible).length;
  $('#nodes-summary').textContent = entries.length ? `${available} / ${entries.length} disponibles` : 'Sin datos';
  entries.forEach(([name, node]) => {
    const nodeName = node.nodo || name; const active = sameNode(nodeName, role?.activo);
    const card = el('article', null, `tarjeta node-card${node.alcanzable ? '' : ' caida'}`);
    const head = el('header'); const identity = el('div', null, 'node-identity');
    identity.append(el('h3', nodeName), el('span', node.version ? displayVersion(node.version) : 'versión desconocida', 'meta'));
    const badge = el('span', !node.alcanzable ? 'Sin respuesta' : active ? 'Activo' : 'Pasivo', `insignia ${!node.alcanzable ? 'parada' : active ? 'viva' : 'pasiva'}`);
    head.append(identity, badge); card.append(head);
    const services = el('div', null, 'servicios-nodo');
    services.append(
      nodeService('Guardian', node.alcanzable ? 'Disponible' : 'No responde', node.alcanzable ? 'ok' : 'error'),
      nodeService('NPM', !node.alcanzable ? 'No verificable' : node.npm_accesible ? 'Disponible' : 'No disponible', node.alcanzable && node.npm_accesible ? 'ok' : 'error'),
      nodeService('Receptor de réplica', !node.alcanzable ? 'No verificable' : node.puede_recibir_replica ? 'Preparado' : 'No disponible', node.alcanzable && node.puede_recibir_replica ? 'ok' : 'warning'),
      nodeService('Secretos de clúster', !node.alcanzable ? 'No verificable' : node.security_compatible === false ? 'No coinciden' : 'Coinciden', node.alcanzable && node.security_compatible !== false ? 'ok' : 'error'),
    );
    card.append(services);
    if (node.alcanzable && node.npm_accesible) {
      const summary = node.resumen || {}; const expiring = Number(summary.caducan_en_30_dias || 0);
      const metrics = el('div', null, `node-metrics${expiring ? ' warning' : ''}`);
      metrics.append(el('span', `${summary.certificados ?? 0} certificados`), el('span', `${summary.dominios ?? 0} proxy hosts`));
      if (expiring) metrics.append(el('span', `${expiring} próximos a caducar`, 'node-risk'));
      card.append(metrics);
    } else if (node.error) card.append(el('p', node.error, 'node-error'));
    grid.append(card);
  });
}

function paintDomains(domains) { const items = domains || []; $('#proxy-total').textContent = `${items.length} publicado${items.length === 1 ? '' : 's'}`; const body = $('#cuerpo-dominios'); body.textContent = ''; if (!domains?.length) { const row = el('tr'); const td = cell('', 'vacio', 'Sin proxy hosts.'); td.colSpan = 3; row.append(td); body.append(row); return; } domains.forEach((domain) => { const row = el('tr'); row.append(cell('Dominio', 'servicio', (domain.dominios || []).join(', ')), cell('Destino', 'puertos', domain.destino), cell('Certificado', 'desc', domain.certificado ? `#${domain.certificado}` : 'sin certificado')); body.append(row); }); }

function paintNamecheap(watch) {
  const nc = watch?.namecheap || {};
  const states = {
    ok: { tone: 'ok', label: 'IP autorizada', readiness: 'Disponible', detail: 'La renovación DNS-01 puede ejecutarse desde esta IP.' },
    ip_rechazada: { tone: 'error', label: 'IP no autorizada', readiness: 'Bloqueado', detail: 'Añade esta IP a la lista blanca de Namecheap antes de renovar.' },
    sin_credenciales: { tone: 'warning', label: 'Configuración incompleta', readiness: 'Bloqueado', detail: 'Configura el usuario y la clave API de Namecheap.' },
    indeterminado: { tone: 'warning', label: 'Sin verificar', readiness: 'Sin confirmar', detail: nc.mensaje || 'No se pudo consultar Namecheap.' },
    otro_error: { tone: 'error', label: 'Error de API', readiness: 'Bloqueado', detail: nc.mensaje || 'Namecheap respondió con un error.' },
    no_me_toca: { tone: 'info', label: 'Nodo pasivo', readiness: 'Lo comprueba el activo', detail: nc.mensaje || 'La comprobación corresponde al nodo activo.' },
    sin_saber_quien_manda: { tone: 'warning', label: 'Sin nodo activo', readiness: 'Pausado', detail: nc.mensaje || 'No se puede decidir qué nodo debe comprobar las renovaciones.' },
    desactivado: { tone: 'neutral', label: 'Desactivado', readiness: 'No aplica', detail: 'No se comprueba la IP pública; la alta disponibilidad sigue operativa.' },
  };
  const state = states[nc.estado] || { tone: 'neutral', label: 'Pendiente', readiness: 'Sin comprobar', detail: nc.mensaje || 'Todavía no se ha realizado la primera comprobación.' };
  setStatusCard('#namecheap-card', '#namecheap-status', state.tone, state.label);
  $('#namecheap-ip').textContent = nc.ip || (nc.estado === 'desactivado' ? 'No se comprueba' : '—');
  $('#namecheap-readiness').textContent = state.readiness;
  $('#namecheap-checked').textContent = readableDate(watch?.cuando);
  $('#namecheap-detail').textContent = state.detail;
}

function paintCredentials(value) { const box = $('#credenciales'); box.textContent = ''; if (value?.comparable && value.coinciden === false) { $('#namecheap-card').dataset.tone = 'error'; $('#namecheap-readiness').textContent = 'Bloqueado'; box.append(el('div', value.aviso, 'recado mal')); } }

async function sync(force, button) {
  const warning = force ? 'Se impondrá el estado de este nodo y se perderán versiones más nuevas de otros nodos.' : 'Se copiará el estado del nodo activo a todos los pasivos.';
  const accepted = await confirmAction({
    title: force ? 'Imponer el estado de este nodo' : 'Sincronizar los nodos',
    message: `${warning}\n\nCada pasivo detendrá NPM, aplicará una copia coherente y volverá a arrancarlo.`,
    confirmText: force ? 'Imponer y sincronizar' : 'Sincronizar',
    tone: force ? 'danger' : 'warning',
  });
  if (!accepted) return;
  const old = button.textContent; operating = true; button.disabled = true; button.textContent = 'sincronizando…';
  try {
    const result = await api(`/api/sincronizar${force ? '?forzar=1' : ''}`, { method: 'POST' });
    if (!result.hecho) {
      notify('Sin cambios que aplicar', result.motivo || 'Todos los nodos ya tenían el mismo estado.', 'info');
    } else {
      const entries = Object.entries(result.resultados || {});
      const failures = entries.filter(([, value]) => !value.ok);
      const detail = entries.map(([name, value]) => `${value.ok ? '✓' : '✗'} ${name}${value.error ? `: ${value.error}` : ''}`).join('\n');
      notify(failures.length ? 'Sincronización incompleta' : 'Sincronización terminada', detail || 'Los nodos pasivos están actualizados.', failures.length ? 'warning' : 'success');
    }
  } catch (error) {
    notify('No se pudo sincronizar', error.message, 'error');
  } finally {
    operating = false; button.disabled = false; button.textContent = old; void refreshDashboard();
  }
}

function paintSyncActions(state) {
  if (operating) return;
  const box = $('#acciones-sincronia'); box.textContent = '';
  if (!state || state.error || lastRole.soy_yo !== true) return;
  const winners = state.nodos_con_algo_ganador || [];
  const logicalWinners = state.nodos_con_cambio_logico || [];
  const otherWinners = winners.filter((node) => node !== lastRole.activo);
  const otherLogical = logicalWinners.filter((node) => node !== lastRole.activo);
  const conflicts = state.conflictos || [];
  const button = (text, force = false, className = null) => {
    const b = el('button', text, className); b.type = 'button';
    b.addEventListener('click', () => sync(force, b)); box.append(b);
  };

  if (state.en_sincronia) {
    button('Copiar de todos modos', true);
  } else if (conflicts.length || logicalWinners.length > 1) {
    box.append(el('div', 'Hay cambios lógicos incompatibles y no existe una fuente única. Guardian no los sobrescribirá automáticamente.', 'recado mal'));
    button('Imponer este estado', true, 'peligro');
  } else if (otherLogical.length === 1 && state.comparacion_completa) {
    const source = otherLogical[0];
    box.append(el('div', `${source} contiene todos los cambios funcionales más recientes. Guardian recuperará ese estado coherente y lo replicará al clúster.`, 'recado bien'));
    button(`Recuperar desde ${source} y sincronizar`);
  } else if (otherLogical.length) {
    box.append(el('div', 'No responden todos los nodos; no se puede acreditar una fuente lógica única.', 'recado mal'));
  } else if (!logicalWinners.length && otherWinners.length) {
    box.append(el('div', 'Sólo difieren ficheros sin un cambio lógico asociado. Guardian no supondrá cuál debe conservarse.', 'recado mal'));
    button('Imponer este estado', true, 'peligro');
  } else {
    if (otherWinners.length) {
      box.append(el('div', 'El nodo activo contiene los cambios funcionales. Los ficheros derivados se regenerarán y viajarán con esa configuración.', 'recado bien'));
    }
    button('Sincronizar ahora');
  }
}

function paintSync(state) {
  const summary = $('#sincronia'); const details = $('#diferencias'); details.textContent = ''; paintSyncActions(state);
  if (!state) { summary.className = 'mando'; summary.textContent = 'Todavía sin comparar.'; return; }
  if (state.error) { summary.className = 'mando nadie'; summary.textContent = `No se pudo comparar: ${state.error}`; return; }
  const missing = Object.keys(state.nodos_sin_respuesta || {}); const consulted = (state.nodos_consultados || []).join(', ');
  if (state.en_sincronia && state.comparacion_completa) { summary.className = 'mando yo'; summary.textContent = `Todos los nodos coinciden.\nComparados: ${consulted}.`; return; }
  summary.className = 'mando otro'; summary.textContent = state.en_sincronia ? `Coinciden los nodos disponibles, pero no responden: ${missing.join(', ')}.` : `${state.diferencias.length} elementos no coinciden.${missing.length ? ` Tampoco responden: ${missing.join(', ')}.` : ''}`;
  if (!state.diferencias?.length) return; const labels = { certificado: 'Certificado', dominio: 'Proxy host', estado_npm: 'Estado interno', artefactos_npm: 'Ficheros NPM' }; const table = el('table'); const head = el('thead'); const hr = el('tr'); hr.append(el('th', 'Elemento')); (state.nodos_consultados || []).forEach((node) => hr.append(el('th', node))); hr.append(el('th', 'Gana')); head.append(hr); table.append(head); const body = el('tbody'); state.diferencias.forEach((difference) => { const row = el('tr'); row.append(cell('Elemento', 'servicio', `${labels[difference.tipo] || 'Elemento'} · ${difference.nombre || difference.clave}${difference.borrado ? ' (borrado)' : ''}`)); (state.nodos_consultados || []).forEach((node) => { const value = difference.por_nodo?.[node] || '—'; row.append(cell(node, value === 'no lo tiene' ? 'vacio' : 'puertos', value)); }); row.append(cell('Gana', 'desc', difference.conflicto ? 'Conflicto' : (difference.gana || '—'))); body.append(row); }); table.append(body); const frame = el('div', null, 'marco desliza'); frame.append(table); details.append(frame);
}

async function renew(cert, button) {
  const accepted = await confirmAction({
    title: `Renovar ${cert.nombre}`,
    message: 'El DNS challenge puede tardar más de cinco minutos. Guardian esperará, recargará Nginx si hace falta y comprobará por TLS que el certificado nuevo está servido.',
    confirmText: 'Renovar certificado',
  });
  if (!accepted) return;
  const old = button.textContent; operating = true; button.disabled = true; button.textContent = 'renovando…';
  try {
    const result = await api(`/api/renovar/${cert.id}`, { method: 'POST' });
    const activation = result.activacion;
    if (!result.ok && result.emision_ok === true) {
      notify('Certificado emitido; finalización pendiente', `${cert.nombre}\n${result.error || 'Guardian mantiene la emisión bloqueada hasta completar la autoridad o la réplica del clúster.'}`, 'warning');
    } else if (!result.ok) {
      notify('No se pudo renovar', result.error || `Falló la renovación de ${cert.nombre}.`, 'error');
    } else if (activation?.ok) {
      const expiry = result.servido?.caduca_servido ? `\nCaduca: ${result.servido.caduca_servido}` : '';
      const reload = activation.reload_attempted ? '\nNginx se recargó correctamente.' : '\nNginx ya servía la nueva copia.';
      notify('Certificado renovado y servido', `${cert.nombre}${expiry}${reload}`, 'success');
    } else {
      notify('Certificado emitido, pero no activado', `${cert.nombre}\n${activation?.error || result.servido?.motivo || 'Revisa la recarga de Nginx.'}\nNo se solicitará otra emisión automáticamente.`, 'warning');
    }
  } catch (error) {
    notify('No se pudo renovar', error.message, 'error');
  } finally {
    operating = false; button.disabled = false; button.textContent = old; void refreshDashboard();
  }
}

async function refreshDashboard() {
  if (!session || $('#view-dashboard').classList.contains('oculto')) return;
  try { const state = await api('/api/estado'); paintRole(state.mando || {}); paintNamecheap(state.vigilancia); paintCredentials(state.credenciales); paintCertificates(state.certificados); paintNodes(state.nodos, state.mando || {}); paintDomains(state.dominios); api('/api/sincronia').then(paintSync).catch((error) => paintSync({ error: error.message })); $('#sub').textContent = `atendido por ${state.yo || '?'}${state.certificados ? ` · ${state.certificados.length} certificados` : ''}`; $('#version').textContent = displayVersion(state.version); $('#pie').textContent = `NPM Guardian · ${state.yo || '?'}`; $('#latido').className = 'latido'; $('#latido').textContent = `al día ${new Date().toLocaleTimeString('es-ES')}`; if (state.error) message('#recado', state.error); else clearMessage('#recado'); } catch (error) { if (error.status === 401) { session = null; showLogin(); return; } if (error.code === 'PASSIVE_NODE' || error.code === 'ACTIVE_NODE_UNKNOWN') { window.location.reload(); return; } $('#latido').className = 'latido error'; $('#latido').textContent = 'sin contacto'; message('#recado', `No se pudo leer el estado: ${error.message}`); }
}

const cronPresets = ['*/5 * * * *', '*/15 * * * *', '*/30 * * * *', '0 * * * *', '0 */6 * * *', '0 3 * * *'];
function toggleCron() { const custom = $('#sync-preset').value === 'custom'; $('#sync-custom-wrap').classList.toggle('oculto', !custom); $('#sync-cron').required = custom; }
function toggleNamecheap() { $('#namecheap-fields').classList.toggle('disabled-fields', !$('#namecheap-enabled').checked); }
$('#sync-preset').addEventListener('change', toggleCron); $('#namecheap-enabled').addEventListener('change', toggleNamecheap);

function toggleNodeStandalone() {
  const disabled = $('#node-standalone').checked;
  [
    '#node-keepalived-url', '#node-keepalived-service', '#node-keepalived-token',
    '#node-keepalived-ca', '#node-keepalived-token-clear', '#node-keepalived-ca-clear',
    '#node-keepalived-http',
  ].forEach((selector) => { $(selector).disabled = disabled; });
  $('#node-keepalived-url').required = !disabled;
  $('#node-keepalived-service').required = !disabled;
}
$('#node-standalone').addEventListener('change', toggleNodeStandalone);

function paintNodeSettings(settings) {
  if (!settings) return;
  const localMember = (settings.members || []).find((member) => member.name.toLowerCase() === settings.node.toLowerCase());
  $('#node-name').value = settings.node || '';
  $('#node-address').value = localMember?.address || '';
  $('#node-members').value = formatMembers(settings.members);
  $('#node-standalone').checked = Boolean(settings.standalone);
  $('#node-keepalived-url').value = settings.keepalived?.url || '';
  $('#node-keepalived-service').value = settings.keepalived?.service || '';
  $('#node-keepalived-token').value = '';
  $('#node-keepalived-token-clear').checked = false;
  $('#node-keepalived-token-status').textContent = settings.keepalived?.token_configured ? 'Token configurado.' : 'Sin token configurado.';
  $('#node-keepalived-ca').value = '';
  $('#node-keepalived-ca-clear').checked = false;
  $('#node-keepalived-ca-status').textContent = settings.keepalived?.ca_configured ? 'CA personalizada configurada.' : 'Se utiliza la confianza del sistema.';
  $('#node-keepalived-http').checked = Boolean(settings.keepalived?.allow_http);
  $('#node-public-url').value = settings.portal?.public_url || '';
  $('#node-public-port').value = settings.portal?.public_port ?? 6061;
  $('#node-session-minutes').value = settings.portal?.session_minutes ?? 15;
  $('#node-proxies').value = settings.portal?.trusted_proxies || '';
  $('#node-portal-http').checked = Boolean(settings.portal?.allow_http);
  $('#node-npm-container').value = settings.npm?.container || '';
  $('#node-npm-scheme').value = settings.npm?.scheme || 'https';
  $('#node-npm-api-port').value = settings.npm?.api_port ?? 443;
  $('#node-npm-https-port').value = settings.npm?.https_port ?? 443;
  $('#node-npm-ca').value = '';
  $('#node-npm-ca-clear').checked = false;
  $('#node-npm-ca-status').textContent = settings.npm?.ca_configured ? 'CA personalizada configurada.' : 'Se utiliza la confianza del sistema.';
  $('#node-npm-http').checked = Boolean(settings.npm?.allow_http);
  toggleNodeStandalone();
}

async function loadConfig() {
  try {
    config = await api('/api/config');
    paintNodeSettings(config.node_settings);
    const cron = config.sync.cron;
    $('#sync-enabled').checked = config.sync.enabled;
    $('#sync-preset').value = cronPresets.includes(cron) ? cron : 'custom';
    $('#sync-cron').value = cron;
    toggleCron();
    $('#namecheap-enabled').checked = config.namecheap.enabled;
    $('#namecheap-user').value = config.namecheap.api_user || '';
    $('#namecheap-key').value = '';
    $('#namecheap-key-clear').checked = false;
    $('#namecheap-key-status').textContent = config.namecheap.api_key_configured ? 'Clave configurada.' : 'Sin clave configurada.';
    $('#renew-days').value = config.renewal.days_before_expiry;
    $('#warning-days').value = config.renewal.warning_days;
    $('#renew-attempts').value = String(config.renewal.max_automatic_attempts);
    $('#npm-user').value = config.npm_api.user || '';
    $('#npm-password').value = '';
    $('#npm-password-clear').checked = false;
    $('#npm-password-status').textContent = config.npm_api.password_configured ? 'Contraseña configurada.' : 'Sin contraseña configurada.';
    $('#npm-port').value = config.npm_api.port;
    $('#npm-https-port').value = config.npm_api.https_port;
    $('#npm-timeout').value = config.npm_api.timeout_seconds;
    toggleNamecheap();
    const topology = config.topology || {};
    $('#topology-summary').textContent = `${topology.node || '?'} · ${topology.peers?.length || 0} pares · servicio Keepalived “${topology.keepalived_service || '?'}”${topology.cluster_token_configured ? '' : ' · falta el token de clúster'}`;
    $('#sync-schedule-summary').textContent = config.sync.enabled ? `Programada con “${config.sync.cron}”${config.sync.next_run ? ` · próxima ejecución ${config.sync.next_run.replace('T', ' ')}` : ''}. La copia siempre sale del nodo activo.` : 'La sincronización automática está desactivada; sólo se ejecutará manualmente.';
  } catch (error) {
    message('#config-message', error.message);
  }
}

$('#node-config-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  clearMessage('#node-config-message');
  let members;
  try {
    members = parseMembers($('#node-members').value);
    const nodeName = $('#node-name').value.trim();
    const localMember = members.find((member) => member.name.toLowerCase() === nodeName.toLowerCase());
    if (!localMember) throw new Error('La lista de miembros debe incluir este nodo.');
    localMember.address = $('#node-address').value.trim();
  } catch (error) {
    message('#node-config-message', error.message);
    return;
  }
  const accepted = await confirmAction({
    title: 'Guardar configuración del nodo',
    message: 'NPM Guardian se reiniciará dentro de este mismo contenedor para aplicar los cambios. La sesión se cerrará durante unos segundos.',
    confirmText: 'Guardar y reiniciar',
  });
  if (!accepted) return;
  const button = $('#node-config-save');
  button.disabled = true;
  const standalone = $('#node-standalone').checked;
  const payload = {
    node: $('#node-name').value.trim(),
    members,
    standalone,
    keepalived: {
      url: standalone ? '' : $('#node-keepalived-url').value.trim(),
      service: standalone ? '' : $('#node-keepalived-service').value.trim(),
      token: standalone ? '' : $('#node-keepalived-token').value.trim(),
      ca_certificate: standalone ? '' : $('#node-keepalived-ca').value.trim(),
      clear_token: $('#node-keepalived-token-clear').checked,
      clear_ca_certificate: $('#node-keepalived-ca-clear').checked,
      allow_http: standalone ? false : $('#node-keepalived-http').checked,
    },
    portal: {
      public_url: $('#node-public-url').value.trim(),
      public_port: Number($('#node-public-port').value),
      session_minutes: Number($('#node-session-minutes').value),
      trusted_proxies: $('#node-proxies').value.trim(),
      allow_http: $('#node-portal-http').checked,
    },
    npm: {
      container: $('#node-npm-container').value.trim(),
      scheme: $('#node-npm-scheme').value,
      api_port: Number($('#node-npm-api-port').value),
      https_port: Number($('#node-npm-https-port').value),
      ca_certificate: $('#node-npm-ca').value.trim(),
      clear_ca_certificate: $('#node-npm-ca-clear').checked,
      allow_http: $('#node-npm-http').checked,
    },
  };
  try {
    await api('/api/node-config', { method: 'POST', body: json(payload) });
    message('#node-config-message', 'Configuración guardada. NPM Guardian se está reiniciando.', true);
    window.setTimeout(() => window.location.reload(), 2200);
  } catch (error) {
    message('#node-config-message', error.message);
    button.disabled = false;
  }
});

$('#config-form').addEventListener('submit', async (event) => { event.preventDefault(); const button = $('#config-save'); button.disabled = true; clearMessage('#config-message'); const cron = $('#sync-preset').value === 'custom' ? $('#sync-cron').value.trim() : $('#sync-preset').value; const payload = { sync: { enabled: $('#sync-enabled').checked, cron }, namecheap: { enabled: $('#namecheap-enabled').checked, api_user: $('#namecheap-user').value.trim(), api_key: $('#namecheap-key').value || null, clear_api_key: $('#namecheap-key-clear').checked }, renewal: { days_before_expiry: Number($('#renew-days').value), warning_days: Number($('#warning-days').value), max_automatic_attempts: Number($('#renew-attempts').value) }, npm_api: { user: $('#npm-user').value.trim(), password: $('#npm-password').value || null, clear_password: $('#npm-password-clear').checked, port: Number($('#npm-port').value), https_port: Number($('#npm-https-port').value), timeout_seconds: Number($('#npm-timeout').value) } }; try { const result = await api('/api/config', { method: 'POST', body: json(payload) }); const failures = Object.entries(result.replication?.resultados || {}).filter(([, value]) => !value.ok).map(([name]) => name); message('#config-message', failures.length ? `Configuración guardada, pero no llegó a: ${failures.join(', ')}.` : 'Configuración guardada y replicada.', !failures.length); await loadConfig(); } catch (error) { message('#config-message', error.message); } finally { button.disabled = false; } });

$('#profile-form').addEventListener('submit', async (event) => { event.preventDefault(); try { const result = await api('/api/profile', { method: 'POST', body: json({ display_name: $('#profile-name').value }) }); session.display_name = result.profile.display_name; message('#profile-message', 'Perfil actualizado.', true); } catch (error) { message('#profile-message', error.message); } });

function inputField(label, type = 'text') { const wrapper = el('label'); wrapper.append(el('span', label)); const input = el('input'); input.type = type; input.required = true; wrapper.append(input); return [wrapper, input]; }
function renderTwoFactor() {
  const box = $('#two-factor-content'); box.textContent = ''; if (!session) return;
  if (!session.two_factor_enabled) { const text = el('p', 'Añade TOTP para proteger el acceso. Al activarlo recibirás códigos de recuperación que también permiten entrar si NPM está caído.', 'pista'); const form = el('form', null, 'inline-security-form'); const [field, password] = inputField('Confirma tu contraseña de NPM', 'password'); password.autocomplete = 'current-password'; const button = el('button', 'Configurar 2FA'); button.type = 'submit'; form.append(field, button); form.addEventListener('submit', async (event) => { event.preventDefault(); button.disabled = true; try { const setup = await api('/api/profile/2fa/setup', { method: 'POST', body: json({ current_password: password.value }) }); renderSetup(setup); } catch (error) { message('#profile-message', error.message); } finally { button.disabled = false; } }); box.append(text, form); return; }
  box.append(el('p', `Segundo factor activo. Quedan ${session.recovery_codes_remaining} códigos de recuperación y acceso de emergencia.`, 'veredicto bien'));
  const grid = el('div', null, 'profile-grid');
  const disable = el('form'); disable.append(el('h4', 'Desactivar 2FA')); const [dpw, dpwi] = inputField('Contraseña actual de NPM', 'password'); const [dcode, dcodei] = inputField('Código 2FA o de recuperación'); const db = el('button', 'Desactivar'); db.type = 'submit'; disable.append(dpw, dcode, db); disable.addEventListener('submit', async (event) => { event.preventDefault(); try { await api('/api/profile/2fa/disable', { method: 'POST', body: json({ current_password: dpwi.value, code: dcodei.value }) }); await refreshSession(); renderTwoFactor(); message('#profile-message', '2FA desactivado.', true); } catch (error) { message('#profile-message', error.message); } });
  const regen = el('form'); regen.append(el('h4', 'Nuevos códigos de recuperación')); const [rpw, rpwi] = inputField('Contraseña actual de NPM', 'password'); const [rcode, rcodei] = inputField('Código 2FA'); const rb = el('button', 'Regenerar códigos'); rb.type = 'submit'; regen.append(rpw, rcode, rb); regen.addEventListener('submit', async (event) => { event.preventDefault(); try { const result = await api('/api/profile/2fa/recovery-codes', { method: 'POST', body: json({ current_password: rpwi.value, code: rcodei.value }) }); showRecovery(result.recovery_codes); await refreshSession(); renderTwoFactor(); } catch (error) { message('#profile-message', error.message); } }); grid.append(disable, regen); box.append(grid);
}

function renderSetup(setup) { const box = $('#two-factor-content'); box.textContent = ''; const layout = el('div', null, 'two-factor-setup'); if (setup.qr_data_url) { const image = el('img'); image.src = setup.qr_data_url; image.alt = 'Código QR para configurar TOTP'; layout.append(image); } const form = el('form'); form.append(el('p', 'Escanea el QR o introduce esta clave manualmente:')); form.append(el('code', setup.secret, 'totp-secret')); const [field, code] = inputField('Código de 6 dígitos'); code.inputMode = 'numeric'; code.pattern = '[0-9]{6}'; code.maxLength = 6; const buttons = el('div', null, 'acciones'); const cancel = el('button', 'Cancelar', 'boton-secundario'); cancel.type = 'button'; cancel.addEventListener('click', async () => { await api('/api/profile/2fa/setup', { method: 'DELETE' }); renderTwoFactor(); }); const enable = el('button', 'Verificar y activar'); enable.type = 'submit'; buttons.append(cancel, enable); form.append(field, buttons); form.addEventListener('submit', async (event) => { event.preventDefault(); try { const result = await api('/api/profile/2fa/enable', { method: 'POST', body: json({ code: code.value }) }); showRecovery(result.recovery_codes); await refreshSession(); renderTwoFactor(); message('#profile-message', '2FA activado. Guarda los códigos de recuperación.', true); } catch (error) { message('#profile-message', error.message); } }); layout.append(form); box.append(layout); }

function showRecovery(codes) { const box = $('#recovery-codes'); box.textContent = ''; (codes || []).forEach((code) => box.append(el('code', code))); $('#recovery-card').classList.remove('oculto'); }
$('#copy-recovery').addEventListener('click', async () => { const text = Array.from($('#recovery-codes').querySelectorAll('code')).map((node) => node.textContent).join('\n'); try { if (navigator.clipboard?.writeText && window.isSecureContext) await navigator.clipboard.writeText(text); else { const area = document.createElement('textarea'); area.value = text; area.setAttribute('readonly', ''); area.style.position = 'fixed'; area.style.opacity = '0'; document.body.append(area); area.select(); if (!document.execCommand('copy')) throw new Error('copy failed'); area.remove(); } message('#profile-message', 'Códigos copiados.', true); } catch (_) { message('#profile-message', 'No se pudieron copiar automáticamente. Selecciónalos y guárdalos manualmente.'); } });

function startTimer() { clearInterval(timer); timer = setInterval(refreshDashboard, REFRESH_MS); }
async function start() {
  try {
    try { const bootstrap = await api('/api/bootstrap/status'); if (bootstrap.required) { showSetup(); return; } } catch (error) { if (error.status !== 404) throw error; }
    await refreshSession(); await Promise.all([loadConfig(), refreshDashboard()]); renderTwoFactor(); startTimer();
  } catch (error) { if (error.code === 'PASSIVE_NODE' || error.code === 'ACTIVE_NODE_UNKNOWN') { window.location.reload(); return; } showLogin(); void refreshLoginGuidance(); }
}
document.addEventListener('visibilitychange', () => { if (!document.hidden && session) { void refreshDashboard(); void loadConfig(); } });
void start();
