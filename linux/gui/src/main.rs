//! peerpass GUI: a thin relm4 client of peerpassd. Holds no keys; every action is an RPC.
//! Pages are rebuilt from model state on navigation/data changes (simple, no factories).
mod ui;

use peerpassd::Client;
use relm4::gtk::{self, gdk, glib, prelude::*};
use relm4::{Component, ComponentParts, ComponentSender, RelmApp};
use serde_json::{json, Value};

const CLIPBOARD_CLEAR_SECS: u32 = 30;

#[derive(Debug, Clone, PartialEq)]
pub enum Page {
    NoDaemon,
    Setup,
    Unlock,
    List,
    Entry(String),
    Edit(Option<String>),
    Conflicts,
    Resolve(String),
    Devices,
    Settings,
    Generator,
    Import,
}

#[derive(Debug)]
pub enum Msg {
    Tick,
    Nav(Page),
    Create { name: String, pw: String, pw2: String },
    Join { name: String, text: String },
    Unlock(String),
    Lock,
    Search(String),
    Save { id: Option<String>, entry: Value },
    Delete(String),
    Copy(String),
    ClearClipboard(u64),
    PairBegin,
    PairCancel,
    PairRespond(bool),
    RemovePeer(String),
    SyncNow,
    SetAutoLock(u64),
    ChangePassword { old: String, new: String, new2: String },
    Import { format: String, path: String, password: String },
    Error(String),
}

/// Results of slow calls run off the main thread.
#[derive(Debug)]
pub enum Done {
    Unlocked(Result<Value, String>),
    Created(Result<Value, String>),
    Synced(Result<Value, String>),
    PasswordChanged(Result<Value, String>),
    Imported(Result<Value, String>),
}

pub struct App {
    client: Option<Client>,
    pub status: Value,
    pub page: Page,
    pub search: String,
    pub items: Vec<Value>,
    pub current: Option<Value>,
    pub peers: Vec<Value>,
    pub offer: Option<Value>,
    pub pair: Value,
    pub error: Option<String>,
    pub info: Option<String>,
    pub busy: bool,
    clip_gen: u64,
    rev: u64,
    dirty: std::cell::Cell<bool>,
}

pub struct Widgets {
    content: gtk::Box,
    banner: gtk::Label,
    search: gtk::SearchEntry,
    header_btns: gtk::Box,
    conflicts: gtk::Button,
    /// Labels that tick every second (TOTP countdown), rebuilt with the page.
    pub live: ui::Live,
}

/// Runs a blocking RPC on a fresh connection (for background commands).
pub fn rpc_once(method: &str, params: Value) -> Result<Value, String> {
    Client::connect_default().map_err(|e| format!("daemon not reachable: {e}"))?.call(method, params)
}

impl App {
    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        if self.client.is_none() {
            self.client = Client::connect_default().ok();
        }
        let r = match self.client.as_mut() {
            Some(c) => c.call(method, params),
            None => Err("peerpassd is not running".into()),
        };
        if matches!(&r, Err(e) if e.starts_with("daemon not reachable")) {
            self.client = None;
        }
        r
    }

    fn set_err(&mut self, r: Result<Value, String>) -> Option<Value> {
        match r {
            Ok(v) => Some(v),
            Err(e) => {
                self.error = Some(e);
                None
            }
        }
    }

    fn is_form_page(&self) -> bool {
        match self.page {
            Page::Edit(_) | Page::Resolve(_) | Page::Settings | Page::Unlock | Page::Generator | Page::Import => true,
            Page::Setup => self.pair["join"].is_null(),
            _ => false,
        }
    }

    pub fn unlocked(&self) -> bool {
        self.status["unlocked"] == true
    }

    /// Reloads status and the data the current page needs.
    fn refresh(&mut self) {
        // Every path below (including early returns) changes what is shown.
        self.dirty.set(true);
        match self.call("status", Value::Null) {
            Ok(s) => self.status = s,
            Err(_) => {
                self.page = Page::NoDaemon;
                return;
            }
        }
        if self.page == Page::NoDaemon {
            self.page = Page::List;
        }
        let joining = !self.pair["join"].is_null() && self.pair["join"]["done"] != true;
        if self.status["has_vault"] != true || joining {
            self.page = Page::Setup;
            return;
        }
        if !self.unlocked() {
            if !matches!(self.page, Page::Unlock) {
                self.offer = None;
                self.current = None;
            }
            self.page = Page::Unlock;
            return;
        }
        if matches!(self.page, Page::Unlock | Page::Setup) {
            self.page = Page::List;
        }
        if let Ok(v) = self.call("list", Value::Null) {
            self.items = v.as_array().cloned().unwrap_or_default();
        }
        match self.page.clone() {
            Page::Entry(id) | Page::Resolve(id) | Page::Edit(Some(id)) => match self.call("get", json!({ "id": id })) {
                Ok(v) => self.current = Some(v),
                Err(_) => {
                    self.current = None;
                    self.page = Page::List;
                }
            },
            Page::Devices | Page::Settings => {
                if let Ok(v) = self.call("peers", Value::Null) {
                    self.peers = v.as_array().cloned().unwrap_or_default();
                }
            }
            _ => {}
        }
        self.dirty.set(true);
    }

    fn copy(&mut self, text: String, sender: &ComponentSender<Self>) {
        let Some(display) = gdk::Display::default() else { return };
        display.clipboard().set_text(&text);
        self.clip_gen += 1;
        let g = self.clip_gen;
        let s = sender.clone();
        glib::timeout_add_seconds_local_once(CLIPBOARD_CLEAR_SECS, move || s.input(Msg::ClearClipboard(g)));
        self.info = Some(format!("Copied. Clipboard clears in {CLIPBOARD_CLEAR_SECS} s."));
    }
}

impl Component for App {
    type CommandOutput = Done;
    type Input = Msg;
    type Output = ();
    type Init = ();
    type Root = gtk::ApplicationWindow;
    type Widgets = Widgets;

    fn init_root() -> Self::Root {
        gtk::ApplicationWindow::builder().title("peerpass").default_width(900).default_height(640).build()
    }

    fn init(_: (), root: Self::Root, sender: ComponentSender<Self>) -> ComponentParts<Self> {
        if let Some(st) = gtk::Settings::default() {
            st.set_gtk_application_prefer_dark_theme(true);
        }
        let header = gtk::HeaderBar::new();
        let search = gtk::SearchEntry::builder().placeholder_text("Search").width_request(260).build();
        {
            let s = sender.clone();
            search.connect_search_changed(move |e| s.input(Msg::Search(e.text().to_string())));
        }
        header.set_title_widget(Some(&search));
        let header_btns = gtk::Box::new(gtk::Orientation::Horizontal, 4);
        let conflicts = gtk::Button::with_label("Conflicts");
        conflicts.add_css_class("destructive-action");
        {
            let s = sender.clone();
            conflicts.connect_clicked(move |_| s.input(Msg::Nav(Page::Conflicts)));
        }
        header.pack_start(&header_btns);
        header.pack_end(&conflicts);
        root.set_titlebar(Some(&header));

        let outer = gtk::Box::new(gtk::Orientation::Vertical, 0);
        let banner = gtk::Label::builder().wrap(true).margin_top(6).margin_bottom(6).visible(false).build();
        let scroller = gtk::ScrolledWindow::builder().vexpand(true).hscrollbar_policy(gtk::PolicyType::Never).build();
        let content = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(10)
            .margin_start(18)
            .margin_end(18)
            .margin_top(12)
            .margin_bottom(18)
            .build();
        scroller.set_child(Some(&content));
        outer.append(&banner);
        outer.append(&scroller);
        root.set_child(Some(&outer));

        let s = sender.clone();
        glib::timeout_add_seconds_local(1, move || {
            s.input(Msg::Tick);
            glib::ControlFlow::Continue
        });

        let mut model = App {
            client: None,
            status: Value::Null,
            page: Page::List,
            search: String::new(),
            items: vec![],
            current: None,
            peers: vec![],
            offer: None,
            pair: Value::Null,
            error: None,
            info: None,
            busy: false,
            clip_gen: 0,
            rev: u64::MAX,
            dirty: std::cell::Cell::new(true),
        };
        model.refresh();
        let mut widgets = Widgets { content, banner, search, header_btns, conflicts, live: ui::Live::default() };
        model.update_view(&mut widgets, sender);
        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Msg, sender: ComponentSender<Self>, _root: &Self::Root) {
        let mut nav_refresh = true;
        let is_tick = matches!(msg, Msg::Tick);
        let page_before = self.page.clone();
        if !matches!(msg, Msg::Tick | Msg::ClearClipboard(_) | Msg::Search(_)) {
            self.error = None;
            self.info = None;
        }
        match msg {
            Msg::Tick => {
                nav_refresh = false;
                let pairing = matches!(self.page, Page::Devices | Page::Setup) || self.offer.is_some();
                if pairing {
                    if let Ok(p) = self.call("pair_status", Value::Null) {
                        if p != self.pair {
                            self.pair = p;
                            self.dirty.set(true);
                        }
                    }
                }
                match self.call("status", Value::Null) {
                    Ok(s) => {
                        let rev = s["rev"].as_u64().unwrap_or(0);
                        let lock_changed = s["unlocked"] != self.status["unlocked"] || s["has_vault"] != self.status["has_vault"];
                        if rev != self.rev || lock_changed || self.page == Page::NoDaemon {
                            self.rev = rev;
                            nav_refresh = true;
                        }
                    }
                    Err(_) if self.page != Page::NoDaemon => {
                        self.page = Page::NoDaemon;
                        self.dirty.set(true);
                    }
                    Err(_) => {}
                }
            }
            Msg::Nav(p) => {
                if self.offer.is_some() && p != Page::Devices {
                    let _ = self.call("pair_cancel", Value::Null);
                    self.offer = None;
                }
                self.page = p;
            }
            Msg::Search(q) => {
                self.search = q;
                if !matches!(self.page, Page::List) && self.unlocked() {
                    self.page = Page::List;
                }
            }
            Msg::Create { name, pw, pw2 } => {
                if pw != pw2 {
                    self.error = Some("Passwords do not match.".into());
                } else if pw.len() < 8 {
                    self.error = Some("Use at least 8 characters for the master password.".into());
                } else {
                    self.busy = true;
                    sender.spawn_oneshot_command(move || {
                        Done::Created(rpc_once("create", json!({ "password": pw, "device_name": name })))
                    });
                }
            }
            Msg::Join { name, text } => {
                let r = self.call("pair_join", json!({ "text": text, "device_name": name }));
                if self.set_err(r).is_some() {
                    self.pair = json!({ "join": { "code": null, "done": false } });
                }
            }
            Msg::Unlock(pw) => {
                self.busy = true;
                sender.spawn_oneshot_command(move || Done::Unlocked(rpc_once("unlock", json!({ "password": pw }))));
            }
            Msg::Lock => {
                let r = self.call("lock", Value::Null);
                self.set_err(r);
                self.items.clear();
                self.current = None;
            }
            Msg::Save { id, entry } => {
                let r = self.call("put", json!({ "id": id, "entry": entry }));
                if let Some(v) = self.set_err(r) {
                    self.page = Page::Entry(v.as_str().unwrap_or_default().to_string());
                }
            }
            Msg::Delete(id) => {
                let r = self.call("delete", json!({ "id": id }));
                if self.set_err(r).is_some() {
                    self.page = Page::List;
                }
            }
            Msg::Copy(t) => {
                nav_refresh = false;
                self.copy(t, &sender);
                self.dirty.set(true);
            }
            Msg::ClearClipboard(g) => {
                nav_refresh = false;
                if g == self.clip_gen {
                    if let Some(d) = gdk::Display::default() {
                        d.clipboard().set_text("");
                    }
                }
            }
            Msg::PairBegin => {
                let r = self.call("pair_begin", Value::Null);
                self.offer = self.set_err(r);
            }
            Msg::PairCancel => {
                let _ = self.call("pair_cancel", Value::Null);
                self.offer = None;
            }
            Msg::PairRespond(accept) => {
                let r = self.call("pair_respond", json!({ "accept": accept }));
                self.set_err(r);
                self.offer = None;
                self.info = Some(if accept { "Device added." } else { "Pairing rejected." }.into());
            }
            Msg::RemovePeer(d) => {
                let r = self.call("remove_peer", json!({ "device_id": d }));
                self.set_err(r);
            }
            Msg::SyncNow => {
                self.busy = true;
                sender.spawn_oneshot_command(|| Done::Synced(rpc_once("sync_now", Value::Null)));
            }
            Msg::SetAutoLock(secs) => {
                let r = self.call("set_auto_lock", json!({ "secs": secs }));
                if self.set_err(r).is_some() {
                    self.info = Some("Auto-lock updated.".into());
                }
            }
            Msg::ChangePassword { old, new, new2 } => {
                if new != new2 {
                    self.error = Some("New passwords do not match.".into());
                } else {
                    self.busy = true;
                    sender.spawn_oneshot_command(move || {
                        Done::PasswordChanged(rpc_once("change_password", json!({ "old": old, "new": new })))
                    });
                }
            }
            Msg::Import { format, path, password } => {
                self.busy = true;
                sender.spawn_oneshot_command(move || {
                    Done::Imported(rpc_once("import", json!({ "format": format, "path": path, "password": password })))
                });
            }
            Msg::Error(e) => self.error = Some(e),
        }
        if nav_refresh {
            self.refresh();
        }
        // Background changes must not wipe a form the user is typing into.
        if is_tick && self.page == page_before && self.is_form_page() {
            self.dirty.set(false);
        }
    }

    fn update_cmd(&mut self, done: Done, _sender: ComponentSender<Self>, _root: &Self::Root) {
        self.busy = false;
        self.error = None;
        match done {
            Done::Unlocked(r) | Done::Created(r) => {
                self.set_err(r);
            }
            Done::Synced(r) => {
                if let Some(v) = self.set_err(r) {
                    let res = v.as_array().cloned().unwrap_or_default();
                    let failed: Vec<String> = res
                        .iter()
                        .filter(|x| x["ok"] != true)
                        .map(|x| format!("{}: {}", x["name"].as_str().unwrap_or("?"), x["error"].as_str().unwrap_or("")))
                        .collect();
                    self.info = Some(if res.is_empty() {
                        "No paired devices.".into()
                    } else if failed.is_empty() {
                        format!("Synced with {} device(s).", res.len())
                    } else {
                        format!("Some devices were not reachable — {}", failed.join("; "))
                    });
                }
            }
            Done::PasswordChanged(r) => {
                if self.set_err(r).is_some() {
                    self.info = Some("Master password changed. Other devices pick it up on their next sync.".into());
                }
            }
            Done::Imported(r) => {
                if let Some(v) = self.set_err(r) {
                    self.info = Some(format!(
                        "Imported {} entries, skipped {} duplicates.",
                        v["imported"].as_u64().unwrap_or(0),
                        v["skipped"].as_u64().unwrap_or(0)
                    ));
                    self.page = Page::List;
                }
            }
        }
        self.refresh();
    }

    fn update_view(&self, w: &mut Self::Widgets, sender: ComponentSender<Self>) {
        // Banner (errors/info) is cheap to update every time.
        match (&self.error, &self.info, self.busy) {
            (Some(e), _, _) => ui::banner(&w.banner, e, true),
            (_, _, true) => ui::banner(&w.banner, "Working…", false),
            (_, Some(i), _) => ui::banner(&w.banner, i, false),
            _ => w.banner.set_visible(false),
        }
        let n = self.status["conflicts"].as_u64().unwrap_or(0);
        w.conflicts.set_visible(n > 0 && self.unlocked());
        w.conflicts.set_label(&format!("⚠ {n} conflict{}", if n == 1 { "" } else { "s" }));
        w.search.set_visible(self.unlocked());
        w.live.tick();
        if !self.dirty.replace(false) {
            return;
        }
        ui::header_buttons(&w.header_btns, self, &sender);
        while let Some(c) = w.content.first_child() {
            w.content.remove(&c);
        }
        w.live = ui::Live::default();
        ui::render(self, &w.content, &mut w.live, &sender);
    }
}

fn main() {
    let app = RelmApp::new("dev.peerpass.Peerpass");
    relm4::set_global_css(include_str!("theme.css"));
    app.run::<App>(());
}
