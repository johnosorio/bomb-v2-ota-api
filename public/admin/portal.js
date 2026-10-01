const $ = id => document.getElementById(id);
let config, token = '', selected = null, busy = false;
const incoming = new URLSearchParams(location.hash.slice(1));
history.replaceState(null, '', location.pathname);
const labels = { pending: 'Pendiente de autorización', approved: 'Autorizada: continúa en CoreS3',
  rejected: 'Rechazada', cancelled: 'Cancelada en el equipo', consumed: 'Autorización entregada al equipo; comprueba allí el resultado', expired: 'Caducada' };
function status(text) { $('status').textContent = text; }
function locked(value) { busy = value; for (const button of document.querySelectorAll('button')) button.disabled = value; }
function signedOut() {
  token = ''; selected = null; $('password').value = ''; $('code').value = '';
  $('new-password').value = $('repeat-password').value = ''; $('activation').hidden = true;
  $('requests').replaceChildren(); $('workspace').hidden = $('decision').hidden = true; $('login').hidden = false;
}
async function json(url, options = {}) {
  const response = await fetch(url, { ...options, redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(10000) });
  const body = await response.json();
  if (!response.ok) {
    if (response.status === 401 && token) signedOut();
    throw new Error(response.status === 401 ? 'Sesión no válida. Vuelve a entrar.' :
      response.status === 403 ? 'Tu cuenta no tiene permiso para esta operación.' :
      response.status === 409 ? 'La solicitud cambió o caducó. Actualiza la lista.' :
      'No se pudo completar la operación. Comprueba la conexión y vuelve a intentarlo.');
  }
  return body;
}
function api(method = 'GET', body) {
  return json('/api/ota/pin', { method, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {}) });
}
function line(parent, text) { const p = document.createElement('p'); p.textContent = text; parent.append(p); }
async function refresh() {
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
  await refresh(); status('Sesión iniciada. Selecciona la solicitud que muestra CoreS3.');
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
  if(password!==$('repeat-password').value) {status('Las contraseñas no coinciden.');return;}
  $('new-password').value=$('repeat-password').value='';
  await json(`${config.supabase_url}/auth/v1/user`, {method:'PUT',headers:{apikey:config.publishable_key,
    Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:JSON.stringify({password})});
  $('activation').hidden=true;$('workspace').hidden=false;await refresh();status('Cuenta preparada. Ya puedes administrar tus solicitudes.');
}); };
$('activation-back').onclick = () => {signedOut();status('Activación cancelada. Puedes volver a abrir tu invitación si sigue vigente.');};
$('back').onclick = () => { selected = null; $('code').value = ''; $('decision').hidden = true; $('workspace').hidden = false; status('Has vuelto sin autorizar.'); };
$('logout').onclick = () => run(async () => {
  const oldToken = token; signedOut();
  try { await json(`${config.supabase_url}/auth/v1/logout`, { method: 'POST', headers: { apikey: config.publishable_key, Authorization: `Bearer ${oldToken}` } }); }
  catch { /* Local session is always removed, even without connectivity. */ }
  status('Sesión cerrada en este navegador.');
});
run(async () => {
  config = await json('/api/ota/pin?action=config');
  if (!/^https:\/\/[a-z0-9-]+\.supabase\.co$/.test(config.supabase_url) ||
      !/^sb_publishable_[A-Za-z0-9_-]+$/.test(config.publishable_key)) throw new Error('Configuración de acceso no válida.');
  signedOut(); status('Entra con tu cuenta de administrador.');
  const incomingToken=incoming.get('access_token');
  if(incomingToken && ['invite','recovery'].includes(incoming.get('type'))) {
    const user=await json(`${config.supabase_url}/auth/v1/user`, {headers:{apikey:config.publishable_key,Authorization:`Bearer ${incomingToken}`}});
    if(!user.id || user.is_anonymous===true)throw new Error('Invitación no válida.');
    token=incomingToken;$('login').hidden=true;$('activation').hidden=false;status('Invitación verificada. Elige tu contraseña para el portal.');
  }
  incoming.delete('access_token');incoming.delete('refresh_token');
});
