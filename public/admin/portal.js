const $ = id => document.getElementById(id);
let config, token = '', selected = null, busy = false;
let recoveringPassword = false;
const incoming = new URLSearchParams(location.hash.slice(1));
history.replaceState(null, '', location.pathname);
const labels = { pending: 'Pendiente de autorización', approved: 'Autorizada: continúa en CoreS3',
  rejected: 'Rechazada', cancelled: 'Cancelada en el equipo', consumed: 'Autorización entregada al equipo; comprueba allí el resultado', expired: 'Caducada' };
function status(text) { $('status').textContent = text; }
function locked(value) { busy = value; for (const control of document.querySelectorAll('button, input, select')) control.disabled = value; }
function signedOut() {
  token = ''; selected = null; clearAdministration(); $('password').value = ''; $('code').value = '';
  $('new-password').value = $('repeat-password').value = ''; $('activation').hidden = true;
  $('password-recovery').hidden = true; $('recovery-email').value = ''; recoveringPassword = false;
  $('requests').replaceChildren(); $('workspace').hidden = $('decision').hidden = true; $('login').hidden = false;
}
async function json(url, options = {}) {
  const response = await fetch(url, { ...options, redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(10000) });
  const body = await response.json();
  if (!response.ok) {
    if (response.status === 401 && token) signedOut();
    const error = new Error(response.status === 401 ? 'Sesión no válida. Vuelve a entrar.' :
      response.status === 403 ? 'Tu cuenta no tiene permiso para esta operación.' :
      response.status === 409 ? 'La solicitud cambió o caducó. Actualiza la lista.' :
      'No se pudo completar la operación. Comprueba la conexión y vuelve a intentarlo.');
    error.status = response.status; throw error;
  }
  return body;
}
function api(method = 'GET', body) {
  return json('/api/ota/pin', { method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {}) });
}
function line(parent, text) { const p = document.createElement('p'); p.textContent = text; parent.append(p); }
async function refresh() {
  $('requests').replaceChildren(); $('empty').hidden = true;
  const result = await api();
  $('requests').replaceChildren(); $('empty').hidden = result.recoveries.length > 0;
  for (const r of result.recoveries) {
    const card = document.createElement('article'); card.className = 'request';
    const h = document.createElement('h3'); h.textContent = r.device_label; card.append(h);
    line(card, `Equipo: ${r.device_code}`);
    const code = document.createElement('code'); code.textContent = r.request_id.slice(0, 12); card.append(code);
    line(card, labels[r.status] || 'Estado no reconocido');
    line(card, `Válida hasta ${new Date(r.expires_at * 1000).toLocaleString()}`);
    if (r.status === 'pending') {
      const approve = document.createElement('button'); approve.textContent = 'Revisar y autorizar';
      approve.onclick = () => { selected = r; $('decision-detail').textContent = `${r.device_label} · ${r.device_code}`;
        $('code').value = ''; $('workspace').hidden = true; $('decision').hidden = false; $('code').focus(); };
      card.append(approve);
      const reject = document.createElement('button'); reject.textContent = 'Rechazar'; reject.className = 'secondary';
      reject.onclick = () => run(async () => { await api('POST', { request_id: r.request_id, action: 'reject' });
        await refresh(); status('Solicitud rechazada. El PIN permanece igual.'); });
      card.append(' ', reject);
    }
    $('requests').append(card);
  }
}
async function run(operation) {
  if (busy) return;
  locked(true);
  try { await operation(); } catch (error) { status(error.message || 'No se pudo completar la operación.'); }
  finally { locked(false); }
}
$('login-form').onsubmit = event => { event.preventDefault(); run(async () => {
  const password = $('password').value; $('password').value = '';
  const session = await json(`${config.supabase_url}/auth/v1/token?grant_type=password`, {
    method: 'POST', headers: { apikey: config.publishable_key, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: $('email').value.trim(), password })
  });
  if (typeof session.access_token !== 'string' || session.user?.is_anonymous === true) throw new Error('Cuenta no válida.');
  token = session.access_token; $('login').hidden = true; $('workspace').hidden = false;
  await loadWorkspace(); status('Sesión iniciada. Selecciona un equipo o una sección.');
}); };
$('forgot-password').onclick = () => {
  const email = $('email').value.trim();
  signedOut(); $('login').hidden = true; $('password-recovery').hidden = false;
  $('recovery-email').value = email; $('recovery-email').focus();
  status('Introduce el correo de tu cuenta para recuperar la contraseña.');
};
$('recovery-back').onclick = () => { signedOut(); status('Has vuelto al acceso del portal.'); };
$('recovery-form').onsubmit = event => { event.preventDefault(); run(async () => {
  const email = $('recovery-email').value.trim();
  if (!email || !$('recovery-email').checkValidity()) { status('Introduce un correo válido.'); return; }
  const redirect = new URL('/admin/', location.origin);
  if (redirect.protocol !== 'https:') throw new Error('Abre el portal HTTPS para recuperar tu contraseña.');
  await json(`${config.supabase_url}/auth/v1/recover?redirect_to=${encodeURIComponent(redirect.href)}`, {
    method: 'POST', headers: { apikey: config.publishable_key, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email })
  });
  status('Si la cuenta permite recuperar el acceso, recibirás un enlace. Revisa también correo no deseado. Puedes volver al acceso.');
}); };
$('decision-form').onsubmit = event => { event.preventDefault(); run(async () => {
  if (!selected || $('code').value.toLowerCase() !== selected.request_id.slice(0, 12)) {
    status('El código no coincide. Comprueba la solicitud en CoreS3.'); return;
  }
  await api('POST', { request_id: selected.request_id, action: 'approve' });
  selected = null; $('code').value = ''; $('decision').hidden = true; $('workspace').hidden = false;
  await refresh(); status('Autorizada. Confirma físicamente en CoreS3 y crea allí el nuevo PIN.');
}); };
$('refresh').onclick = () => run(async () => { await refresh(); status('Solicitudes actualizadas.'); });
$('activation-form').onsubmit = event => { event.preventDefault(); run(async () => {
  const password=$('new-password').value;
  if (password.length < 12) {status('Usa al menos 12 caracteres.');return;}
  if(password!==$('repeat-password').value) {status('Las contraseñas no coinciden.');return;}
  $('new-password').value=$('repeat-password').value='';
  await json(`${config.supabase_url}/auth/v1/user`, {method:'PUT',headers:{apikey:config.publishable_key,
    Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:JSON.stringify({password})});
  if (recoveringPassword) {
    signedOut(); status('Contraseña guardada. Entra con tu nueva contraseña. El PIN del CoreS3 no ha cambiado.'); return;
  }
  $('activation').hidden=true;$('workspace').hidden=false;await loadWorkspace();status('Cuenta preparada. Ya puedes administrar tus equipos.');
}); };
$('activation-back').onclick = () => {signedOut();status('Cambio cancelado. Puedes abrir otro enlace vigente o pedir uno nuevo.');};
$('back').onclick = () => { selected = null; $('code').value = ''; $('decision').hidden = true; $('workspace').hidden = false; status('Has vuelto sin autorizar.'); };
$('logout').onclick = () => run(async () => {
  const oldToken = token; signedOut();
  try { await json(`${config.supabase_url}/auth/v1/logout`, { method: 'POST', headers: { apikey: config.publishable_key, Authorization: `Bearer ${oldToken}` } }); }
  catch { /* Local session is always removed, even without connectivity. */ }
  status('Sesión cerrada en este navegador.');
});
run(async () => { try {
  config = await json('/api/ota/pin?action=config');
  if (!/^https:\/\/[a-z0-9-]+\.supabase\.co$/.test(config.supabase_url) ||
      !/^sb_publishable_[A-Za-z0-9_-]+$/.test(config.publishable_key)) throw new Error('Configuración de acceso no válida.');
  signedOut(); status('Entra con tu cuenta de administrador.');
  if (incoming.has('error') || incoming.has('error_code')) {
    status('El enlace no es válido o ha caducado. Solicita otro desde Olvidé mi contraseña.'); return;
  }
  const incomingToken=incoming.get('access_token');
  if(incomingToken && ['invite','recovery'].includes(incoming.get('type'))) {
    const user=await json(`${config.supabase_url}/auth/v1/user`, {headers:{apikey:config.publishable_key,Authorization:`Bearer ${incomingToken}`}});
    if(typeof user?.id !== 'string' || !user.id || user.is_anonymous===true)throw new Error('Enlace no válido. Solicita otro desde Olvidé mi contraseña.');
    recoveringPassword = incoming.get('type') === 'recovery';
    token=incomingToken;$('login').hidden=true;$('activation').hidden=false;
    status(recoveringPassword ? 'Enlace verificado. Elige una nueva contraseña para el portal.' : 'Invitación verificada. Elige tu contraseña para el portal.');
  }
} finally {
  // Also release tokens when configuration or verification fails.
  for (const key of [...incoming.keys()]) incoming.delete(key);
}
});

// Administration uses the existing user-scoped API; no browser-side role grants.
let scopes = [], scopeOffset = 0, deviceOffset = 0, devices = [], currentDevice = null;
let currentLicense = null, licenseLoaded = false, pendingOperation = null;
const pageSize = 25;
const actionNames = { register: 'Registrar equipo', approve_identity: 'Vincular identidad',
  grant: 'Conceder o renovar licencia', revoke: 'Revocar licencia',
  revoke_credential: 'Retirar credencial', replace_credential: 'Reemplazar credencial' };
const reasonNames = { lost: 'Clave perdida', compromised: 'Clave comprometida', maintenance: 'Mantenimiento' };
const dateText = value => value == null ? 'Sin fecha' : new Date(value * 1000).toLocaleString();
function clearAdministration() {
  scopes = []; devices = []; currentDevice = null; currentLicense = null; licenseLoaded = false;
  pendingOperation = null; scopeOffset = deviceOffset = 0;
  for (const id of ['device-detail', 'operation', 'operation-review']) $(id).hidden = true;
  for (const id of ['scope-select', 'devices', 'license-state', 'operation-fields', 'operation-summary', 'releases']) $(id).replaceChildren();
}
function scope() { return scopes.find(s => s.id === $('scope-select').value); }
function admin() { return scope()?.role === 'admin'; }
function callApi(path, method = 'GET', body) {
  return json(path, { method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {}) });
}
function showView(view) {
  for (const name of ['devices', 'pin', 'releases']) {
    $(`${name}-view`).hidden = name !== view;
    $(`nav-${name}`).className = name === view ? 'active' : 'secondary';
    $(`nav-${name}`).setAttribute('aria-current', name === view ? 'page' : 'false');
  }
  $('workspace-title').textContent = {devices:'Dispositivos',pin:'Recuperación PIN',releases:'Versiones OTA'}[view];
}
function option(parent, value, text) {
  const node = document.createElement('option'); node.value = value; node.textContent = text; parent.append(node);
}
async function loadWorkspace() { showView('devices'); await loadScopes(); }
async function loadScopes() {
  $('devices').replaceChildren(); $('scope-select').replaceChildren(); scopes = []; devices = [];
  $('register-open').hidden = true; $('devices-empty').hidden = true;
  $('scope-role').textContent = ''; $('devices-page').textContent = '';
  for (const id of ['scope-prev','scope-next','devices-prev','devices-next']) $(id).hidden = true;
  const result = await callApi(`/api/ota/devices?action=context&limit=${pageSize}&offset=${scopeOffset}`);
  if (!Array.isArray(result.scopes)) throw new Error('No se pudieron cargar tus ámbitos.');
  scopes = result.scopes;
  for (const s of scopes) option($('scope-select'), s.id, s.name);
  $('scope-prev').hidden = scopeOffset === 0; $('scope-next').hidden = scopes.length < pageSize;
  deviceOffset = 0;
  if (!scopes.length) { $('devices-empty').hidden = false; $('devices-empty').textContent = 'No hay ámbitos asignados a tu cuenta en esta página.'; return; }
  $('scope-select').value = scopes[0].id;
  await loadDevices();
}
async function loadDevices() {
  devices = []; $('devices').replaceChildren(); $('devices-empty').hidden = true;
  $('devices-page').textContent = ''; $('devices-next').hidden = $('devices-prev').hidden = true;
  $('register-open').hidden = true;
  const s = scope(); if (!s) return;
  $('scope-role').textContent = s.role === 'admin' ? 'Administrador' : 'Sólo lectura';
  const result = await callApi(`/api/ota/devices?scope_id=${encodeURIComponent(s.id)}&limit=${pageSize}&offset=${deviceOffset}`);
  if (!Array.isArray(result.devices)) throw new Error('No se pudieron cargar los equipos.');
  devices = result.devices;
  $('devices-empty').hidden = devices.length > 0; $('devices-empty').textContent = 'No hay dispositivos registrados en esta página.';
  $('register-open').hidden = !admin();
  $('devices-prev').hidden = deviceOffset === 0; $('devices-next').hidden = devices.length < pageSize;
  $('devices-page').textContent = devices.length ? `Equipos ${deviceOffset+1}–${deviceOffset+devices.length}` : '';
  for (const d of devices) {
    const card = document.createElement('article'); card.className = 'device-card';
    const info = document.createElement('div'), title = document.createElement('h3'); title.textContent = d.label; info.append(title);
    line(info, `${d.model} · ${d.device_id}`); card.append(info);
    const button = document.createElement('button'); button.type = 'button'; button.className = 'secondary'; button.textContent = 'Abrir ficha';
    button.onclick = () => run(() => openDevice(d)); card.append(button); $('devices').append(card);
  }
}
async function openDevice(d) {
  currentDevice = d; $('workspace').hidden = true; $('device-detail').hidden = false;
  $('device-title').textContent = d.label; $('device-code').textContent = `${d.model} · ${d.device_id}`;
  await loadLicense();
}
async function loadLicense() {
  licenseLoaded = false; currentLicense = null; $('license-actions').hidden = true;
  $('license-state').replaceChildren(); $('license-error').hidden = true;
  try {
    const result = await callApi(`/api/ota/licenses?device_id=${encodeURIComponent(currentDevice.id)}`);
    if (!Object.hasOwn(result, 'license')) throw new Error('Estado de licencia no disponible.');
    currentLicense = result.license; licenseLoaded = true; renderLicense();
  } catch (error) {
    $('license-error').hidden = false; $('license-error').textContent = 'No se pudo consultar la licencia. Actualiza la ficha para reintentar.';
    throw error;
  }
}
function renderLicense() {
  const container = $('license-state'), l = currentLicense; container.replaceChildren();
  $('license-action').replaceChildren(); option($('license-action'), '', 'Selecciona una acción');
  if (!l) {
    line(container, 'Identidad pendiente de vinculación. Este registro aún no tiene una credencial aprobada.');
    option($('license-action'), 'approve_identity', actionNames.approve_identity);
  } else {
    const now = Math.floor(Date.now()/1000);
    let label = { unlicensed:'Sin licencia concedida', revoked:'Licencia revocada', granted:'Licencia concedida' }[l.status] || 'Estado desconocido';
    if (l.status === 'granted') label = now < l.not_before ? 'Concesión futura' : now >= l.expires_at ? 'Licencia vencida' : 'Concesión dentro de vigencia';
    const badge = document.createElement('p'); badge.className = 'license-badge'; badge.textContent = label; container.append(badge);
    line(container, `Credencial: ${l.credential_status === 'active' ? 'Activa' : 'Retirada'}`);
    line(container, `MAC: ${l.mac}`); line(container, `Huella pública SHA-256: ${l.device_key_sha256}`);
    line(container, `Vigencia: ${dateText(l.not_before)} → ${dateText(l.expires_at)}`);
    line(container, `Revisión ${l.revision} · Actualizada ${new Date(l.updated_at).toLocaleString()}`);
    if (l.credential_status === 'active') option($('license-action'), 'grant', actionNames.grant);
    if (l.status === 'granted') option($('license-action'), 'revoke', actionNames.revoke);
    if (l.credential_status === 'active') option($('license-action'), 'revoke_credential', actionNames.revoke_credential);
    option($('license-action'), 'replace_credential', actionNames.replace_credential);
  }
  $('license-actions').hidden = !admin();
}
function field(id, label, type = 'text', choices) {
  const wrapper = document.createElement('label'); wrapper.textContent = label;
  const input = document.createElement(choices ? 'select' : 'input'); input.id = id; input.required = true;
  if (choices) { option(input, '', 'Selecciona un motivo'); for (const [value,text] of Object.entries(choices)) option(input,value,text); }
  else { input.type = type; input.autocomplete = 'off'; }
  wrapper.append(input); $('operation-fields').append(wrapper); return input;
}
function beginOperation(action) {
  if (!admin() || (action !== 'register' && (!currentDevice || !licenseLoaded))) return;
  pendingOperation = { action, submitted: false, applied: false };
  $('workspace').hidden = $('device-detail').hidden = true; $('operation').hidden = false;
  $('operation-title').textContent = actionNames[action];
  $('operation-target').textContent = action === 'register' ? scope().name : `${currentDevice.label} · ${currentDevice.device_id}`;
  $('operation-fields').replaceChildren();
  if (action === 'register') {
    field('edit-code','Identificador del equipo (tal como lo muestra CoreS3)').maxLength = 64;
    field('edit-label','Nombre del equipo').maxLength = 80;
  }
  if (action === 'approve_identity') field('edit-mac','MAC del equipo').placeholder = 'AA:BB:CC:DD:EE:FF';
  if (['approve_identity','replace_credential'].includes(action)) {
    field('edit-fingerprint','Huella pública SHA-256, contrastada con el equipo').maxLength = 64;
    line($('operation-fields'),'Introduce sólo la huella pública. La clave privada permanece en el equipo.');
  }
  if (action === 'grant') {
    field('edit-start','Inicio de vigencia (tu hora local)','datetime-local');
    field('edit-end','Fin de vigencia (tu hora local)','datetime-local');
  }
  if (['replace_credential','revoke_credential'].includes(action)) field('edit-reason','Motivo','',reasonNames);
  if (action === 'revoke') line($('operation-fields'),'Revoca la concesión administrativa. No detiene una ronda activa ni retira la credencial.');
  if (action === 'revoke_credential') line($('operation-fields'),'Impide nuevas entregas online a esta clave. No invalida instantáneamente documentos offline ya emitidos.');
  if (action === 'replace_credential') line($('operation-fields'),'La clave anterior deja de autorizar nuevas entregas online. La licencia conserva su vigencia; el equipo deberá usar la nueva clave.');
}
function prepareOperation() {
  const op = pendingOperation; if (!op || op.submitted || !admin()) return;
  const a = op.action; let body;
  if (a === 'register') {
    body = {scope_id:scope().id,device_id:$('edit-code').value.trim(),label:$('edit-label').value.trim()};
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(body.device_id) || !body.label || [...body.label].length > 80 || /[\u0000-\u001f\u007f]/.test(body.label)) throw new Error('Revisa el identificador y el nombre del equipo.');
  } else {
    body = {device_id:currentDevice.id,request_id:crypto.randomUUID(),action:a};
    if (a !== 'approve_identity') body.expected_revision = currentLicense.revision;
    if (a === 'approve_identity') {
      body.mac = $('edit-mac').value.trim().toUpperCase();
      if (!/^[0-9A-F]{2}(:[0-9A-F]{2}){5}$/.test(body.mac)) throw new Error('La MAC debe tener seis pares separados por dos puntos.');
    }
    if (['approve_identity','replace_credential'].includes(a)) {
      body.device_key_sha256 = $('edit-fingerprint').value.trim().toLowerCase();
      if (!/^[0-9a-f]{64}$/.test(body.device_key_sha256)) throw new Error('La huella debe tener 64 caracteres hexadecimales.');
    }
    if (a === 'grant') {
      body.not_before = Math.floor(new Date($('edit-start').value).getTime()/1000);
      body.expires_at = Math.floor(new Date($('edit-end').value).getTime()/1000);
      if (![body.not_before,body.expires_at].every(n => Number.isInteger(n) && n > 0 && n <= 4294967295) || body.not_before >= body.expires_at || body.expires_at <= Date.now()/1000) throw new Error('Indica un inicio anterior al fin y un vencimiento futuro.');
    }
    if (['replace_credential','revoke_credential'].includes(a)) {
      body.expected_credential_id = currentLicense.credential_id; body.reason = $('edit-reason').value;
      if (!Object.hasOwn(reasonNames,body.reason)) throw new Error('Selecciona el motivo del cambio.');
    }
  }
  op.body = body; $('operation-summary').replaceChildren();
  line($('operation-summary'), actionNames[a]);
  line($('operation-summary'), a === 'register' ? `${body.label} · ${body.device_id} · ${scope().name}` : `${currentDevice.label} · ${currentDevice.device_id}`);
  if (body.mac) line($('operation-summary'), `MAC: ${body.mac}`);
  if (body.device_key_sha256) line($('operation-summary'), `Nueva huella: ${body.device_key_sha256}`);
  if (body.not_before) line($('operation-summary'), `${dateText(body.not_before)} → ${dateText(body.expires_at)}`);
  if (body.reason) line($('operation-summary'), reasonNames[body.reason]);
  if (body.expected_revision !== undefined) line($('operation-summary'), `Revisión que se modificará: ${body.expected_revision}`);
  $('operation-message').textContent = 'Revisa el equipo y los datos. Confirmar aplica el cambio en el servidor.';
  $('operation-confirm').textContent = 'Confirmar cambio'; $('operation-confirm').hidden = false;
  $('operation-return').textContent = 'Volver sin aplicar'; $('operation').hidden = true; $('operation-review').hidden = false;
}
async function finishOperation() {
  const op = pendingOperation; if (!op) return;
  if (op.action === 'register') { deviceOffset = 0; await loadDevices(); }
  else await loadLicense();
  pendingOperation = null; $('operation-review').hidden = true;
  $(op.action === 'register' ? 'workspace' : 'device-detail').hidden = false;
  status('Cambio confirmado. Se ha consultado el estado actual.');
}
async function submitOperation() {
  const op = pendingOperation; if (!op?.body || !admin()) return;
  if (op.applied) { await finishOperation(); return; }
  op.submitted = true;
  try {
    await callApi(op.action === 'register' ? '/api/ota/devices' : '/api/ota/licenses', 'POST', op.body);
    op.applied = true;
    $('operation-message').textContent = 'El servidor confirmó la operación. Consultando el estado actual…';
    $('operation-confirm').textContent = 'Consultar estado actual';
    $('operation-return').textContent = 'Volver al equipo';
    await finishOperation();
  } catch (error) {
    if (!token) throw error;
    if (op.applied) {
      $('operation-message').textContent = 'Cambio confirmado, pero no se pudo consultar el estado actual. Reintenta la consulta; no se repetirá la escritura.';
    } else if ([400,403,409,413,415].includes(error.status)) {
      op.rejected = true; $('operation-confirm').hidden = true;
      $('operation-return').textContent = 'Volver y actualizar';
      $('operation-message').textContent = error.status === 409 ? 'El estado cambió o la operación entra en conflicto. Vuelve, actualiza y prepara una nueva decisión.' : 'Operación rechazada. Vuelve para revisar los datos y tus permisos.';
    } else {
      $('operation-message').textContent = 'Resultado sin confirmar. Reintenta esta misma operación para recuperar su resultado. No cierres ni recargues esta página.';
      $('operation-confirm').textContent = 'Reintentar misma operación'; $('operation-return').textContent = 'Conservar y resolver aquí';
    }
    throw error;
  }
}
async function returnFromOperation() {
  const op = pendingOperation; if (!op) return;
  if (op.submitted && !op.applied && !op.rejected) { status('Resuelve el resultado mediante Reintentar misma operación antes de salir.'); return; }
  if (op.submitted) {
    // A new command requires a fresh read, never an automatic revision change.
    if (op.action === 'register') await loadDevices(); else await loadLicense();
  }
  pendingOperation = null; $('operation').hidden = $('operation-review').hidden = true;
  $(op.action === 'register' ? 'workspace' : 'device-detail').hidden = false;
  status(op.applied ? 'Cambio aplicado. Estado actualizado.' : 'Has vuelto. No se ha enviado otra operación.');
}
async function loadReleases() {
  $('releases').replaceChildren();
  for (const channel of ['stable','beta','dev']) {
    const card = document.createElement('article'); card.className = 'request';
    const heading = document.createElement('h3'); heading.textContent = channel.toUpperCase(); card.append(heading); $('releases').append(card);
    try {
      const r = await json(`/api/releases/${channel}`);
      if (r.channel !== channel || typeof r.version !== 'string' || typeof r.sha256 !== 'string') throw new Error('Manifiesto no válido');
      if (r.version === '0.0.0' && r.size === 0) { line(card,'Canal sin publicación activa.'); continue; }
      line(card, `Versión ${r.version}`); line(card, `${Number(r.size).toLocaleString()} bytes`); line(card, `SHA-256: ${r.sha256}`);
    } catch { line(card,'No se pudo consultar este canal. Actualiza para reintentar.'); }
  }
}
$('nav-devices').onclick = () => run(async () => {showView('devices'); if (!scopes.length) await loadScopes();});
$('nav-pin').onclick = () => run(async () => {showView('pin'); await refresh(); status('Solicitudes accesibles de tus equipos.');});
$('nav-releases').onclick = () => run(async () => {showView('releases'); await loadReleases(); status('Versiones publicadas por canal.');});
$('refresh-releases').onclick = () => run(loadReleases);
$('refresh-devices').onclick = () => run(async () => {if (!scopes.length) await loadScopes(); else await loadDevices(); status('Equipos actualizados.');});
$('scope-select').onchange = () => run(async () => {deviceOffset = 0; await loadDevices();});
$('scope-prev').onclick = () => run(async () => {scopeOffset = Math.max(0,scopeOffset-pageSize); await loadScopes();});
$('scope-next').onclick = () => run(async () => {scopeOffset += pageSize; await loadScopes();});
$('devices-prev').onclick = () => run(async () => {deviceOffset = Math.max(0,deviceOffset-pageSize); await loadDevices();});
$('devices-next').onclick = () => run(async () => {deviceOffset += pageSize; await loadDevices();});
$('device-refresh').onclick = () => run(loadLicense);
$('device-back').onclick = () => {currentDevice = null; currentLicense = null; licenseLoaded = false; $('device-detail').hidden = true; $('workspace').hidden = false;};
$('register-open').onclick = () => beginOperation('register');
$('action-open').onclick = () => {const action=$('license-action').value; if (action) beginOperation(action); else status('Selecciona una acción.');};
$('operation-form').onsubmit = e => {e.preventDefault(); run(async () => prepareOperation());};
$('operation-cancel').onclick = () => run(returnFromOperation);
$('operation-return').onclick = () => run(returnFromOperation);
$('operation-confirm').onclick = () => run(submitOperation);
window.addEventListener('beforeunload', event => {
  if (pendingOperation?.submitted && !pendingOperation.applied && !pendingOperation.rejected) {event.preventDefault(); event.returnValue = '';}
});
