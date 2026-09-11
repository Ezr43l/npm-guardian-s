'use strict';
const $ = (s) => document.querySelector(s);
async function refreshPassive() {
  try {
    const response = await fetch('/api/public/status', { cache: 'no-store' });
    const status = await response.json();
    $('#passive-node').textContent = status.node || 'Este servidor';
    $('#passive-role').textContent = status.role === 'passive' ? 'Pasivo' : 'Sin determinar';
    $('#passive-active').textContent = status.active_node || 'No disponible';
    const version = String(status.version || '—');
    $('#passive-version').textContent = 'versión ' + (version.startsWith('v') || version === '—' ? version : `v${version}`);
    const health = status.health || {}; const ok = health.ready === true;
    const box = $('#passive-health'); box.className = 'passive-status ' + (ok ? 'ok' : 'warning');
    box.querySelector('strong').textContent = ok ? 'Nodo preparado para el relevo' : 'El nodo necesita atención';
    let detail = 'El estado local no garantiza todavía un relevo seguro.';
    if (ok) detail = 'NPM está en marcha, la base es íntegra y la última réplica se aplicó correctamente.';
    else if (health.detail) detail = health.detail;
    else if (!health.npm_container?.corriendo) detail = 'El contenedor de NPM no está en marcha.';
    else if (!health.replication_receiver) detail = 'El receptor de réplicas no está disponible.';
    else if (!health.last_replica_recent) detail = 'No hay una réplica reciente confirmada.';
    else if (status.last_sync_result?.ok === false) detail = 'La última réplica terminó con error.';
    box.querySelector('span:last-child').textContent = detail;
    const link = $('#active-link'); if (status.active_url) { link.href = status.active_url; link.classList.remove('oculto'); } else link.classList.add('oculto');
    $('#passive-refresh').textContent = 'al día ' + new Date().toLocaleTimeString('es-ES');
    if (status.role === 'active') window.location.reload();
  } catch (error) { $('#passive-health').className = 'passive-status warning'; $('#passive-health').querySelector('strong').textContent = 'Sin contacto con Guardian'; $('#passive-health').querySelector('span:last-child').textContent = error.message; }
}
refreshPassive(); setInterval(refreshPassive, 15000);
