import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const root = new URL('../', import.meta.url);
const source = readFileSync(new URL('public/admin/portal.js', root), 'utf8');
const markup = readFileSync(new URL('public/admin/index.html', root), 'utf8');
export const auth = 'https://fixture.supabase.co';
export const config = { supabase_url: auth, publishable_key: 'sb_publishable_fixture' };

class Element {
  constructor(register) {
    this._register = register; this.children = []; this.value = ''; this.hidden = true;
    this.textContent = ''; this.disabled = false; this.className = ''; this.attributes = {};
  }
  set id(value) { this._id = value; this._register(value, this); }
  get id() { return this._id; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = nodes; }
  focus() { this.focused = true; }
  setAttribute(name, value) { this.attributes[name] = value; }
  checkValidity() { return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(this.value); }
}

export async function portal({ hash = '', reply = () => ({}) } = {}) {
  const elements = new Map();
  const register = (id, element) => elements.set(id, element);
  for (const [, id] of markup.matchAll(/id="([^"]+)"/g)) register(id, new Element(register));
  const calls = [], historyCalls = [], listeners = new Map(); let uuid = 0;
  const context = vm.createContext({ URL, URLSearchParams, AbortSignal, Date, crypto: { randomUUID: () => `00000000-0000-4000-8000-${String(++uuid).padStart(12, '0')}` },
    location: { hash, pathname: '/admin/', origin: 'https://portal.example' },
    history: { replaceState(...args) { historyCalls.push(args); } },
    window: { addEventListener(name, callback) { listeners.set(name, callback); } },
    document: { getElementById: id => { assert.ok(elements.has(id), `HTML is missing ${id}`); return elements.get(id); },
      querySelectorAll: () => [...elements.values()], createElement: () => new Element(register) },
    fetch: async (url, options) => {
      calls.push({ url, options });
      if (url === '/api/ota/pin?action=config') return { ok: true, status: 200, json: async () => config };
      const value = await reply(url, options, calls);
      return { ok: !value?.failure, status: value?.failure || 200, json: async () => value };
    }
  });
  vm.runInContext(source, context);
  const idle = async () => { for (let i = 0; i < 40; ++i) await Promise.resolve(); };
  await idle();
  const click = async id => { elements.get(id).onclick(); await idle(); };
  const submit = async id => { elements.get(id).onsubmit({ preventDefault() {} }); await idle(); };
  return { elements, calls, historyCalls, listeners, context, click, submit, idle };
}

export function requests(calls, url, method) {
  return calls.filter(call => call.url === url && (!method || call.options.method === method));
}
