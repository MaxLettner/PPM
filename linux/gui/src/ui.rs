//! Page builders. Each page is rebuilt from `App` state; inputs are read on click.
use crate::{rpc_once, App, Msg, Page};
use relm4::gtk::{self, gdk, glib, prelude::*};
use relm4::ComponentSender;
use serde_json::{json, Value};
use std::cell::Cell;
use std::rc::Rc;

type S = ComponentSender<App>;

/// Callbacks run every second (TOTP countdown).
#[derive(Default)]
pub struct Live(Vec<Box<dyn Fn()>>);

impl Live {
    pub fn tick(&self) {
        for f in &self.0 {
            f();
        }
    }
}

pub fn banner(l: &gtk::Label, text: &str, is_err: bool) {
    l.set_text(text);
    l.set_visible(true);
    if is_err {
        l.add_css_class("error");
    } else {
        l.remove_css_class("error");
    }
}

fn btn(label: &str, s: &S, f: impl Fn() -> Msg + 'static) -> gtk::Button {
    let b = gtk::Button::builder().label(label).halign(gtk::Align::Start).build();
    let s = s.clone();
    b.connect_clicked(move |_| s.input(f()));
    b
}

fn hbox(spacing: i32) -> gtk::Box {
    gtk::Box::new(gtk::Orientation::Horizontal, spacing)
}

fn vbox(spacing: i32) -> gtk::Box {
    gtk::Box::new(gtk::Orientation::Vertical, spacing)
}

fn heading(t: &str) -> gtk::Label {
    let l = gtk::Label::builder().label(t).xalign(0.0).build();
    l.add_css_class("title-2");
    l
}

fn text(t: &str) -> gtk::Label {
    gtk::Label::builder().label(t).xalign(0.0).wrap(true).wrap_mode(gtk::pango::WrapMode::WordChar).selectable(true).build()
}

fn dim(t: &str) -> gtk::Label {
    let l = text(t);
    l.add_css_class("dim-label");
    l
}

fn entry(placeholder: &str, value: &str) -> gtk::Entry {
    gtk::Entry::builder().placeholder_text(placeholder).text(value).hexpand(true).build()
}

fn password(placeholder: &str) -> gtk::PasswordEntry {
    gtk::PasswordEntry::builder().placeholder_text(placeholder).show_peek_icon(true).hexpand(true).build()
}

fn textview(value: &str) -> gtk::TextView {
    let tv = gtk::TextView::builder().wrap_mode(gtk::WrapMode::WordChar).height_request(70).build();
    tv.buffer().set_text(value);
    tv.add_css_class("card");
    tv
}

fn tv_text(tv: &gtk::TextView) -> String {
    let b = tv.buffer();
    b.text(&b.start_iter(), &b.end_iter(), false).to_string()
}

fn labeled(label: &str, w: &impl IsA<gtk::Widget>) -> gtk::Box {
    let b = vbox(2);
    b.append(&dim(label));
    b.append(w);
    b
}

fn ago(ts: Option<i64>) -> String {
    let Some(ts) = ts else { return "never".into() };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    match now - ts {
        d if d < 60 => "just now".into(),
        d if d < 3600 => format!("{} min ago", d / 60),
        d if d < 86400 => format!("{} h ago", d / 3600),
        d => format!("{} days ago", d / 86400),
    }
}

pub fn header_buttons(b: &gtk::Box, app: &App, s: &S) {
    while let Some(c) = b.first_child() {
        b.remove(&c);
    }
    if !app.unlocked() {
        return;
    }
    if app.page != Page::List {
        b.append(&btn("← Back", s, || Msg::Nav(Page::List)));
    }
    b.append(&btn("+ New", s, || Msg::Nav(Page::Edit(None))));
    let menu = gtk::Box::new(gtk::Orientation::Horizontal, 2);
    menu.append(&btn("Generator", s, || Msg::Nav(Page::Generator)));
    menu.append(&btn("Devices", s, || Msg::Nav(Page::Devices)));
    menu.append(&btn("Import", s, || Msg::Nav(Page::Import)));
    menu.append(&btn("Settings", s, || Msg::Nav(Page::Settings)));
    menu.append(&btn("Lock", s, || Msg::Lock));
    b.append(&menu);
}

pub fn render(app: &App, c: &gtk::Box, live: &mut Live, s: &S) {
    match app.page.clone() {
        Page::NoDaemon => {
            c.append(&heading("peerpassd is not running"));
            c.append(&text("Start it with:  systemctl --user enable --now peerpassd"));
        }
        Page::Setup => setup(app, c, s),
        Page::Unlock => unlock(app, c, s),
        Page::List => list(app, c, s),
        Page::Entry(_) => entry_view(app, c, live, s),
        Page::Edit(id) => edit(app, id, c, s),
        Page::Conflicts => conflicts(app, c, s),
        Page::Resolve(id) => resolve(app, id, c, s),
        Page::Devices => devices(app, c, s),
        Page::Settings => settings(app, c, s),
        Page::Generator => {
            c.append(&heading("Password generator"));
            c.append(&generator(None, s));
        }
        Page::Import => import(c, s),
    }
}

fn setup(app: &App, c: &gtk::Box, s: &S) {
    let join = &app.pair["join"];
    if !join.is_null() && join["done"] != true {
        c.append(&heading("Joining vault…"));
        match join["code"].as_str() {
            Some(code) => {
                c.append(&text("Check that the other device shows the same code, then accept there:"));
                let l = gtk::Label::new(Some(code));
                l.add_css_class("title-1");
                c.append(&l);
            }
            None => c.append(&text("Connecting to the other device…")),
        }
        return;
    }
    if let Some(e) = join["error"].as_str() {
        c.append(&dim(&format!("Joining failed: {e}")));
    }
    c.append(&heading("Create a new vault"));
    c.append(&text("Use this on your first device."));
    let name = entry("Device name, e.g. Laptop", "");
    let pw = password("Master password");
    let pw2 = password("Repeat master password");
    for w in [name.upcast_ref::<gtk::Widget>(), pw.upcast_ref(), pw2.upcast_ref()] {
        c.append(w);
    }
    {
        let (name, pw, pw2) = (name.clone(), pw.clone(), pw2.clone());
        c.append(&btn("Create vault", s, move || Msg::Create {
            name: name.text().to_string(),
            pw: pw.text().to_string(),
            pw2: pw2.text().to_string(),
        }));
    }
    c.append(&gtk::Separator::new(gtk::Orientation::Horizontal));
    c.append(&heading("Join an existing vault"));
    c.append(&text("On a paired device open Devices → Pair new device, then paste the pairing text here."));
    let jname = entry("Device name, e.g. Desktop", "");
    let code = textview("");
    c.append(&jname);
    c.append(&labeled("Pairing text", &code));
    c.append(&btn("Join", s, move || Msg::Join { name: jname.text().to_string(), text: tv_text(&code) }));
}

fn unlock(app: &App, c: &gtk::Box, s: &S) {
    c.append(&heading("Unlock"));
    if let Some(n) = app.status["device_name"].as_str() {
        c.append(&dim(&format!("This device: {n}")));
    }
    let pw = password("Master password");
    {
        let s2 = s.clone();
        pw.connect_activate(move |e| s2.input(Msg::Unlock(e.text().to_string())));
    }
    c.append(&pw);
    let p2 = pw.clone();
    c.append(&btn("Unlock", s, move || Msg::Unlock(p2.text().to_string())));
    pw.grab_focus();
}

fn matches(item: &Value, q: &str) -> bool {
    if q.is_empty() {
        return true;
    }
    let q = q.to_lowercase();
    let f = |k: &str| item[k].as_str().unwrap_or("").to_lowercase().contains(&q);
    f("title") || f("username") || item["urls"].as_array().is_some_and(|u| u.iter().any(|x| x.as_str().unwrap_or("").to_lowercase().contains(&q)))
}

fn list(app: &App, c: &gtk::Box, s: &S) {
    let mut items: Vec<&Value> = app.items.iter().filter(|i| matches(i, &app.search)).collect();
    items.sort_by_key(|i| i["title"].as_str().unwrap_or("").to_lowercase());
    if items.is_empty() {
        c.append(&dim(if app.items.is_empty() { "No entries yet. Use “+ New” or Import." } else { "Nothing matches." }));
        return;
    }
    let lb = gtk::ListBox::new();
    lb.add_css_class("boxed-list");
    let ids: Vec<String> = items.iter().map(|i| i["id"].as_str().unwrap_or("").to_string()).collect();
    for i in &items {
        let row = vbox(2);
        row.set_margin_top(6);
        row.set_margin_bottom(6);
        row.set_margin_start(8);
        let mut title = i["title"].as_str().unwrap_or("").to_string();
        if i["conflict"] == true {
            title = format!("⚠ {title}");
        }
        row.append(&gtk::Label::builder().label(&title).xalign(0.0).build());
        row.append(&dim(i["username"].as_str().unwrap_or("")));
        lb.append(&row);
    }
    let s = s.clone();
    lb.connect_row_activated(move |_, r| s.input(Msg::Nav(Page::Entry(ids[r.index() as usize].clone()))));
    c.append(&lb);
}

fn field_row(c: &gtk::Box, label: &str, value: &str, secret: bool, s: &S) {
    if value.is_empty() {
        return;
    }
    let row = hbox(6);
    let col = vbox(2);
    col.set_hexpand(true);
    col.append(&dim(label));
    let shown = Rc::new(Cell::new(!secret));
    let mask = "•".repeat(value.chars().count().min(16));
    let l = text(if secret { &mask } else { value });
    col.append(&l);
    row.append(&col);
    if secret {
        let b = gtk::Button::with_label("Show");
        let (v, l2, shown2) = (value.to_string(), l.clone(), shown.clone());
        b.connect_clicked(move |b| {
            shown2.set(!shown2.get());
            l2.set_text(if shown2.get() { &v } else { &mask });
            b.set_label(if shown2.get() { "Hide" } else { "Show" });
        });
        row.append(&b);
    }
    let v = value.to_string();
    row.append(&btn("Copy", s, move || Msg::Copy(v.clone())));
    c.append(&row);
}

fn entry_view(app: &App, c: &gtk::Box, live: &mut Live, s: &S) {
    let Some(cur) = &app.current else { return };
    let id = cur["id"].as_str().unwrap_or("").to_string();
    let sibs = cur["siblings"].as_array().cloned().unwrap_or_default();
    if sibs.len() > 1 {
        let warn = hbox(8);
        warn.append(&text(&format!("⚠ This entry has {} conflicting versions from different devices.", sibs.len())));
        let id2 = id.clone();
        warn.append(&btn("Resolve…", s, move || Msg::Nav(Page::Resolve(id2.clone()))));
        c.append(&warn);
    }
    let Some((idx, e)) = sibs.iter().enumerate().find_map(|(i, x)| (!x["entry"].is_null()).then(|| (i, &x["entry"]))) else {
        c.append(&text("All versions of this entry are deleted."));
        return;
    };
    let g = |k: &str| e[k].as_str().unwrap_or("").to_string();
    c.append(&heading(&g("title")));
    field_row(c, "Username", &g("username"), false, s);
    field_row(c, "Password", &g("password"), true, s);
    for u in e["urls"].as_array().into_iter().flatten() {
        field_row(c, "URL", u.as_str().unwrap_or(""), false, s);
    }
    if !e["totp"].is_null() {
        totp_row(c, &id, idx, live, s);
    }
    for f in e["custom_fields"].as_array().into_iter().flatten() {
        field_row(c, f["name"].as_str().unwrap_or(""), f["value"].as_str().unwrap_or(""), true, s);
    }
    if !g("notes").is_empty() {
        c.append(&labeled("Notes", &text(&g("notes"))));
    }
    let actions = hbox(6);
    let id2 = id.clone();
    actions.append(&btn("Edit", s, move || Msg::Nav(Page::Edit(Some(id2.clone())))));
    let del = gtk::Button::with_label("Delete");
    del.add_css_class("destructive-action");
    let armed = Cell::new(false);
    let s2 = s.clone();
    del.connect_clicked(move |b| {
        if armed.replace(true) {
            s2.input(Msg::Delete(id.clone()));
        } else {
            b.set_label("Click again to delete");
        }
    });
    actions.append(&del);
    c.append(&actions);
}

fn totp_row(c: &gtk::Box, id: &str, idx: usize, live: &mut Live, s: &S) {
    let row = hbox(6);
    let col = vbox(2);
    col.set_hexpand(true);
    col.append(&dim("One-time code (TOTP)"));
    let l = gtk::Label::builder().xalign(0.0).build();
    l.add_css_class("title-3");
    col.append(&l);
    row.append(&col);
    let code = Rc::new(std::cell::RefCell::new(String::new()));
    let (id, l2, code2) = (id.to_string(), l.clone(), code.clone());
    let update = move || match rpc_once("totp", json!({ "id": id, "index": idx })) {
        Ok(v) => {
            let cd = v["code"].as_str().unwrap_or("").to_string();
            l2.set_text(&format!("{cd}   ({} s)", v["remaining"].as_u64().unwrap_or(0)));
            *code2.borrow_mut() = cd;
        }
        Err(e) => l2.set_text(&e),
    };
    update();
    live.0.push(Box::new(update));
    let b = gtk::Button::with_label("Copy");
    let s2 = s.clone();
    b.connect_clicked(move |_| s2.input(Msg::Copy(code.borrow().clone())));
    row.append(&b);
    c.append(&row);
}

/// Edit form; reads back into the JSON shape of `core::model::Entry`.
struct Form {
    title: gtk::Entry,
    username: gtk::Entry,
    password: gtk::PasswordEntry,
    urls: gtk::TextView,
    totp: gtk::Entry,
    notes: gtk::TextView,
    fields: gtk::TextView,
}

impl Form {
    fn value(&self) -> Value {
        let lines = |t: &str| t.lines().map(str::trim).filter(|l| !l.is_empty()).map(String::from).collect::<Vec<_>>();
        let totp = self.totp.text().trim().to_string();
        let custom: Vec<Value> = lines(&tv_text(&self.fields))
            .iter()
            .map(|l| {
                let (n, v) = l.split_once(':').unwrap_or((l, ""));
                json!({ "name": n.trim(), "value": v.trim() })
            })
            .collect();
        json!({
            "title": self.title.text().trim(), "username": self.username.text().trim(),
            "password": self.password.text().as_str(), "urls": lines(&tv_text(&self.urls)),
            "notes": tv_text(&self.notes), "totp": if totp.is_empty() { Value::Null } else { json!(totp) },
            "custom_fields": custom, "updated_at": 0,
        })
    }
}

fn edit(app: &App, id: Option<String>, c: &gtk::Box, s: &S) {
    let e = id
        .as_ref()
        .and_then(|_| app.current.as_ref())
        .and_then(|cur| cur["siblings"].as_array()?.iter().find(|x| !x["entry"].is_null()).map(|x| x["entry"].clone()))
        .unwrap_or(Value::Null);
    let g = |k: &str| e[k].as_str().unwrap_or("").to_string();
    c.append(&heading(if id.is_some() { "Edit entry" } else { "New entry" }));
    let urls = e["urls"].as_array().map(|u| u.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n")).unwrap_or_default();
    let fields = e["custom_fields"]
        .as_array()
        .map(|f| f.iter().map(|x| format!("{}: {}", x["name"].as_str().unwrap_or(""), x["value"].as_str().unwrap_or(""))).collect::<Vec<_>>().join("\n"))
        .unwrap_or_default();
    let f = Rc::new(Form {
        title: entry("Title", &g("title")),
        username: entry("Username", &g("username")),
        password: password("Password"),
        urls: textview(&urls),
        totp: entry("otpauth://totp/… or base32 secret", &g("totp")),
        notes: textview(&g("notes")),
        fields: textview(&fields),
    });
    f.password.set_text(&g("password"));
    c.append(&labeled("Title", &f.title));
    c.append(&labeled("Username", &f.username));
    c.append(&labeled("Password", &f.password));
    let gen_target = f.password.clone();
    let exp = gtk::Expander::new(Some("Generate password"));
    exp.set_child(Some(&generator(Some(gen_target), s)));
    c.append(&exp);
    c.append(&labeled("Websites (one per line)", &f.urls));
    c.append(&labeled("TOTP", &f.totp));
    c.append(&labeled("Custom fields (one “name: value” per line)", &f.fields));
    c.append(&labeled("Notes", &f.notes));
    let actions = hbox(6);
    let (f2, id2) = (f.clone(), id.clone());
    let save = btn("Save", s, move || Msg::Save { id: id2.clone(), entry: f2.value() });
    save.add_css_class("suggested-action");
    actions.append(&save);
    actions.append(&btn("Cancel", s, move || match &id {
        Some(i) => Msg::Nav(Page::Entry(i.clone())),
        None => Msg::Nav(Page::List),
    }));
    c.append(&actions);
}

/// Generator widget. With `target`, "Use" fills that password field.
fn generator(target: Option<gtk::PasswordEntry>, s: &S) -> gtk::Box {
    let b = vbox(6);
    let len = gtk::SpinButton::with_range(4.0, 128.0, 1.0);
    len.set_value(20.0);
    let opts = hbox(8);
    let checks: Vec<gtk::CheckButton> = ["a-z", "A-Z", "0-9", "!#$…"]
        .iter()
        .map(|l| gtk::CheckButton::builder().label(*l).active(true).build())
        .collect();
    opts.append(&gtk::Label::new(Some("Length")));
    opts.append(&len);
    for ch in &checks {
        opts.append(ch);
    }
    b.append(&opts);
    let out = text("");
    out.add_css_class("monospace");
    b.append(&out);
    let row = hbox(6);
    let gen = gtk::Button::with_label("Generate");
    let (out2, s2) = (out.clone(), s.clone());
    gen.connect_clicked(move |_| {
        let p = json!({
            "length": len.value() as u32, "lower": checks[0].is_active(), "upper": checks[1].is_active(),
            "digits": checks[2].is_active(), "symbols": checks[3].is_active(),
        });
        match rpc_once("generate", p) {
            Ok(v) => out2.set_text(v.as_str().unwrap_or("")),
            Err(e) => s2.input(Msg::Error(e)),
        }
    });
    row.append(&gen);
    let o3 = out.clone();
    row.append(&btn("Copy", s, move || Msg::Copy(o3.text().to_string())));
    if let Some(t) = target {
        let u = gtk::Button::with_label("Use");
        let o4 = out.clone();
        u.connect_clicked(move |_| t.set_text(&o4.text()));
        row.append(&u);
    }
    b.append(&row);
    gen.emit_clicked();
    b
}

fn conflicts(app: &App, c: &gtk::Box, s: &S) {
    c.append(&heading("Conflicts"));
    c.append(&text("These entries were changed on two devices before they synced. Pick a version or merge fields."));
    for i in app.items.iter().filter(|i| i["conflict"] == true) {
        let id = i["id"].as_str().unwrap_or("").to_string();
        let row = hbox(8);
        let l = text(i["title"].as_str().unwrap_or(""));
        l.set_hexpand(true);
        row.append(&l);
        row.append(&btn("Resolve…", s, move || Msg::Nav(Page::Resolve(id.clone()))));
        c.append(&row);
    }
}

const FIELDS: [(&str, &str); 7] = [
    ("title", "Title"),
    ("username", "Username"),
    ("password", "Password"),
    ("urls", "Websites"),
    ("totp", "TOTP"),
    ("custom_fields", "Custom fields"),
    ("notes", "Notes"),
];

fn show_field(e: &Value, k: &str) -> String {
    match &e[k] {
        Value::String(s) => s.clone(),
        Value::Array(a) if k == "custom_fields" => {
            a.iter().map(|f| format!("{}: {}", f["name"].as_str().unwrap_or(""), f["value"].as_str().unwrap_or(""))).collect::<Vec<_>>().join("\n")
        }
        Value::Array(a) => a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n"),
        _ => String::new(),
    }
}

fn resolve(app: &App, id: String, c: &gtk::Box, s: &S) {
    let Some(cur) = &app.current else { return };
    let sibs = cur["siblings"].as_array().cloned().unwrap_or_default();
    c.append(&heading("Resolve conflict"));
    c.append(&text("Keep one version as is, or choose each field and save the merge. The result replaces all versions on every device."));
    let grid = gtk::Grid::builder().column_spacing(12).row_spacing(8).build();
    for (col, sb) in sibs.iter().enumerate() {
        let head = vbox(4);
        head.append(&gtk::Label::builder().label(sb["label"].as_str().unwrap_or("")).xalign(0.0).build());
        let id2 = id.clone();
        if sb["entry"].is_null() {
            head.append(&btn("Keep deletion", s, move || Msg::Delete(id2.clone())));
        } else {
            let e = sb["entry"].clone();
            head.append(&btn("Keep this version", s, move || Msg::Save { id: Some(id2.clone()), entry: e.clone() }));
        }
        grid.attach(&head, col as i32 + 1, 0, 1, 1);
    }
    let live: Vec<(usize, &Value)> = sibs.iter().enumerate().filter(|(_, x)| !x["entry"].is_null()).map(|(i, x)| (i, &x["entry"])).collect();
    let mut choices: Vec<(&str, Vec<(gtk::CheckButton, usize)>)> = Vec::new();
    for (row, (k, name)) in FIELDS.iter().enumerate() {
        grid.attach(&dim(name), 0, row as i32 + 1, 1, 1);
        let mut group: Vec<(gtk::CheckButton, usize)> = Vec::new();
        for (col, e) in &live {
            let cb = gtk::CheckButton::builder().label(show_field(e, k)).active(group.is_empty()).build();
            if let Some((first, _)) = group.first() {
                cb.set_group(Some(first));
            }
            grid.attach(&cb, *col as i32 + 1, row as i32 + 1, 1, 1);
            group.push((cb, *col));
        }
        choices.push((k, group));
    }
    c.append(&grid);
    if live.len() > 1 {
        let sibs2 = sibs.clone();
        let choices: Vec<(String, Vec<(gtk::CheckButton, usize)>)> = choices.into_iter().map(|(k, g)| (k.to_string(), g)).collect();
        let save = btn("Save merged version", s, move || {
            let mut merged = json!({ "updated_at": 0 });
            for (k, group) in &choices {
                let pick = group.iter().find(|(cb, _)| cb.is_active()).map(|(_, i)| *i).unwrap_or(group[0].1);
                merged[k.as_str()] = sibs2[pick]["entry"][k.as_str()].clone();
            }
            Msg::Save { id: Some(id.clone()), entry: merged }
        });
        save.add_css_class("suggested-action");
        c.append(&save);
    }
}

fn qr_picture(data: &str) -> Option<gtk::Picture> {
    let code = qrcode::QrCode::new(data.as_bytes()).ok()?;
    let n = code.width();
    let colors = code.to_colors();
    let (quiet, scale) = (4usize, 6usize);
    let side = (n + 2 * quiet) * scale;
    let mut buf = vec![255u8; side * side * 3];
    for y in 0..n {
        for x in 0..n {
            if colors[y * n + x] == qrcode::Color::Dark {
                for dy in 0..scale {
                    for dx in 0..scale {
                        let (px, py) = ((x + quiet) * scale + dx, (y + quiet) * scale + dy);
                        let i = (py * side + px) * 3;
                        buf[i..i + 3].copy_from_slice(&[0, 0, 0]);
                    }
                }
            }
        }
    }
    let tex = gdk::MemoryTexture::new(side as i32, side as i32, gdk::MemoryFormat::R8g8b8, &glib::Bytes::from(&buf), side * 3);
    let p = gtk::Picture::for_paintable(&tex);
    p.set_size_request(280, 280);
    p.set_can_shrink(true);
    Some(p)
}

fn devices(app: &App, c: &gtk::Box, s: &S) {
    c.append(&heading("Paired devices"));
    if let Some(p) = app.pair["pending"].as_object() {
        let b = vbox(6);
        b.add_css_class("card");
        let code = p.get("code").and_then(Value::as_str).unwrap_or("");
        b.append(&text(&format!(
            "Accept device “{}”?\nCode {code} — it must match the code on the other device.",
            p.get("name").and_then(Value::as_str).unwrap_or("")
        )));
        let r = hbox(6);
        let a = btn("Accept", s, || Msg::PairRespond(true));
        a.add_css_class("suggested-action");
        r.append(&a);
        r.append(&btn("Reject", s, || Msg::PairRespond(false)));
        b.append(&r);
        c.append(&b);
    }
    match &app.offer {
        Some(o) => {
            let t = o["text"].as_str().unwrap_or("").to_string();
            c.append(&text("Scan this code with the new device, or paste the text below into it. Valid for 5 minutes, once."));
            if let Some(p) = qr_picture(&t) {
                c.append(&p);
            }
            let l = text(&t);
            l.add_css_class("monospace");
            c.append(&l);
            let r = hbox(6);
            let t2 = t.clone();
            r.append(&btn("Copy text", s, move || Msg::Copy(t2.clone())));
            r.append(&btn("Cancel", s, || Msg::PairCancel));
            c.append(&r);
        }
        None => c.append(&btn("Pair new device", s, || Msg::PairBegin)),
    }
    if app.peers.is_empty() {
        c.append(&dim("No other devices yet."));
    }
    for p in &app.peers {
        let row = hbox(8);
        let col = vbox(2);
        col.set_hexpand(true);
        col.append(&text(p["name"].as_str().unwrap_or("")));
        col.append(&dim(&format!(
            "last sync: {} · {}",
            ago(p["last_sync"].as_i64()),
            p["last_addr"].as_str().unwrap_or("address unknown")
        )));
        row.append(&col);
        let d = p["device_id"].as_str().unwrap_or("").to_string();
        let rm = gtk::Button::with_label("Remove");
        rm.add_css_class("destructive-action");
        let armed = Cell::new(false);
        let s2 = s.clone();
        rm.connect_clicked(move |b| {
            if armed.replace(true) {
                s2.input(Msg::RemovePeer(d.clone()));
            } else {
                b.set_label("Click again to remove");
            }
        });
        row.append(&rm);
        c.append(&row);
    }
    c.append(&btn("Sync now", s, || Msg::SyncNow));
    c.append(&dim("Removing a device stops syncing with it. It keeps any data it already has, and the vault key is not rotated."));
}

fn settings(app: &App, c: &gtk::Box, s: &S) {
    c.append(&heading("Settings"));
    c.append(&dim(&format!(
        "This device: {} ({}) · sync port {}",
        app.status["device_name"].as_str().unwrap_or("?"),
        app.status["device_id"].as_str().unwrap_or(""),
        app.status["port"]
    )));
    let r = hbox(6);
    r.append(&gtk::Label::new(Some("Auto-lock after (minutes)")));
    let spin = gtk::SpinButton::with_range(1.0, 240.0, 1.0);
    spin.set_value((app.status["auto_lock_secs"].as_u64().unwrap_or(300) / 60) as f64);
    r.append(&spin);
    r.append(&btn("Apply", s, move || Msg::SetAutoLock(spin.value() as u64 * 60)));
    c.append(&r);

    c.append(&heading("Sync status"));
    for p in &app.peers {
        c.append(&text(&format!("{} — last sync {}", p["name"].as_str().unwrap_or(""), ago(p["last_sync"].as_i64()))));
    }
    c.append(&btn("Sync now", s, || Msg::SyncNow));

    c.append(&heading("Change master password"));
    c.append(&text("The new password applies to all devices after they sync."));
    let (old, new, new2) = (password("Current password"), password("New password"), password("Repeat new password"));
    c.append(&old);
    c.append(&new);
    c.append(&new2);
    c.append(&btn("Change password", s, move || Msg::ChangePassword {
        old: old.text().to_string(),
        new: new.text().to_string(),
        new2: new2.text().to_string(),
    }));
}

fn import(c: &gtk::Box, s: &S) {
    c.append(&heading("Import"));
    c.append(&text("Entries with the same title, username and website as an existing entry are skipped."));
    let fmt = gtk::DropDown::from_strings(&["KeePass (.kdbx, KDBX4)", "Bitwarden (unencrypted .json export)"]);
    c.append(&labeled("Format", &fmt));
    let path = entry("File path", "");
    let row = hbox(6);
    row.append(&path);
    let browse = gtk::Button::with_label("Browse…");
    let p2 = path.clone();
    browse.connect_clicked(move |b| {
        #[allow(deprecated)]
        {
            let win = b.root().and_downcast::<gtk::Window>();
            let fc = gtk::FileChooserNative::new(Some("Choose file"), win.as_ref(), gtk::FileChooserAction::Open, None, None);
            let p3 = p2.clone();
            fc.connect_response(move |fc, r| {
                if r == gtk::ResponseType::Accept {
                    if let Some(f) = fc.file().and_then(|f| f.path()) {
                        p3.set_text(&f.to_string_lossy());
                    }
                }
            });
            fc.show();
            // Keep the dialog alive until it responds.
            std::mem::forget(fc);
        }
    });
    row.append(&browse);
    c.append(&labeled("File", &row));
    let pw = password("KeePass database password (KeePass only)");
    c.append(&pw);
    c.append(&btn("Import", s, move || Msg::Import {
        format: if fmt.selected() == 0 { "kdbx".into() } else { "bitwarden".into() },
        path: path.text().to_string(),
        password: pw.text().to_string(),
    }));
}
