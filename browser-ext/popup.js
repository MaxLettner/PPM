// Lists vault entries for the active tab's site. Fills only on click, never on load.
const HOST = "dev.peerpass.nmhost";
const $ = (id) => document.getElementById(id);
// Catppuccin Macchiato accents for letter avatars.
const ACCENTS = ["#c6a0f6", "#8aadf4", "#a6da95", "#f5a97f", "#f5bde6", "#8bd5ca", "#eed49f"];

async function call(msg) {
  const r = await browser.runtime.sendNativeMessage(HOST, msg);
  if (r.error) throw new Error(r.error);
  return r.ok;
}

async function activeTab() {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  return tab;
}

// Runs in the page. Refuses if the page navigated to another host meanwhile.
function fillPage(expectedHost, username, password) {
  if (location.hostname !== expectedHost) return false;
  const visible = (el) => el.offsetParent !== null && !el.disabled && !el.readOnly;
  const set = (el, v) => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    setter.call(el, v);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const pw = [...document.querySelectorAll("input[type=password]")].find(visible);
  const inputs = [...document.querySelectorAll("input")].filter(visible);
  let user = null;
  const end = pw ? inputs.indexOf(pw) : inputs.length;
  for (let i = end - 1; i >= 0; i--) {
    const t = (inputs[i].type || "text").toLowerCase();
    if (["text", "email", "tel", ""].includes(t)) { user = inputs[i]; break; }
  }
  if (user && username) set(user, username);
  if (pw) set(pw, password);
  return Boolean(pw || user);
}

async function fill(entry) {
  const tab = await activeTab(); // re-check at click time
  const cred = await call({ method: "fill", id: entry.id, index: entry.index, url: tab.url });
  const host = new URL(tab.url).hostname;
  const [res] = await browser.scripting.executeScript({
    target: { tabId: tab.id },
    func: fillPage,
    args: [host, cred.username, cred.password],
  });
  if (res && res.result) window.close();
  else $("msg").textContent = "No login form found on this page.";
}

async function copyTotp(entry, btn) {
  const tab = await activeTab();
  const t = await call({ method: "totp", id: entry.id, index: entry.index, url: tab.url });
  await navigator.clipboard.writeText(t.code);
  btn.textContent = `Copied (${t.remaining}s)`;
  btn.classList.add("copied");
}

function render(entries) {
  const list = $("list");
  list.replaceChildren();
  for (const e of entries) {
    const row = document.createElement("div");
    row.className = "item";
    const av = document.createElement("div");
    av.className = "avatar";
    av.textContent = (e.title.match(/[\p{L}\p{N}]/u) || ["?"])[0].toUpperCase();
    av.style.background = ACCENTS[[...e.title].reduce((a, c) => (a * 31 + c.charCodeAt(0)) >>> 0, 0) % ACCENTS.length];
    row.append(av);
    const who = document.createElement("div");
    who.className = "who";
    who.title = "Fill username and password";
    const a = document.createElement("div");
    a.className = "title";
    a.textContent = e.title + (e.label ? ` — ${e.label}` : "");
    const b = document.createElement("div");
    b.className = "sub";
    b.textContent = e.username;
    who.append(a, b);
    who.addEventListener("click", () => fill(e).catch((x) => ($("msg").textContent = x.message)));
    row.append(who);
    if (e.has_totp) {
      const t = document.createElement("button");
      t.textContent = "Copy code";
      t.addEventListener("click", () => copyTotp(e, t).catch((x) => ($("msg").textContent = x.message)));
      row.append(t);
    }
    list.append(row);
  }
}

(async () => {
  try {
    const tab = await activeTab();
    let url;
    try { url = new URL(tab.url); } catch { url = null; }
    if (!url || !/^https?:$/.test(url.protocol)) { $("msg").textContent = "Not a web page."; return; }
    $("site").textContent = url.hostname;
    const st = await call({ method: "status" });
    if (!st.has_vault || !st.unlocked) { $("msg").textContent = "Unlock in peerpass"; return; }
    const entries = await call({ method: "find", url: tab.url });
    $("msg").textContent = entries.length ? "" : "No logins for this site.";
    render(entries);
  } catch (e) {
    $("msg").textContent = /locked/i.test(e.message) ? "Unlock in peerpass" : e.message;
  }
})();
