//! UI-facing pairing state shared by the Linux daemon and the Android app:
//! a pending "accept this device?" question and the progress of a join.
use super::node::{Approver, Node};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JoinState {
    pub code: Option<String>,
    pub done: bool,
    pub error: Option<String>,
    pub peer: Option<String>,
}

struct Pending {
    name: String,
    code: String,
    decision: Option<bool>,
}

#[derive(Default)]
pub struct PairingUi {
    pending: Mutex<Option<Pending>>,
    cv: Condvar,
    join: Mutex<Option<JoinState>>,
}

impl PairingUi {
    /// Approver for `Node::new`: publishes the request, then blocks until `respond`
    /// (or rejects after 2 minutes). `notify` lets the UI know something is pending.
    pub fn approver(self: &Arc<Self>, notify: impl Fn() + Send + Sync + 'static) -> Approver {
        let me = Arc::clone(self);
        Box::new(move |name: &str, code: &str| {
            *me.pending.lock().unwrap() = Some(Pending { name: name.into(), code: code.into(), decision: None });
            notify();
            let g = me.pending.lock().unwrap();
            let (mut g, _) = me
                .cv
                .wait_timeout_while(g, APPROVAL_TIMEOUT, |p| p.as_ref().is_some_and(|p| p.decision.is_none()))
                .unwrap();
            g.take().and_then(|p| p.decision).unwrap_or(false)
        })
    }

    /// (device name, 6-digit code) of an undecided request.
    pub fn pending(&self) -> Option<(String, String)> {
        self.pending.lock().unwrap().as_ref().filter(|p| p.decision.is_none()).map(|p| (p.name.clone(), p.code.clone()))
    }

    pub fn respond(&self, accept: bool) {
        if let Some(p) = self.pending.lock().unwrap().as_mut() {
            p.decision = Some(accept);
        }
        self.cv.notify_all();
    }

    pub fn join_state(&self) -> Option<JoinState> {
        self.join.lock().unwrap().clone()
    }

    /// Starts joining in the background; progress via `join_state`.
    pub fn start_join(self: &Arc<Self>, node: Arc<Node>, text: String, name: String, notify: impl Fn() + Send + Sync + 'static) {
        *self.join.lock().unwrap() = Some(JoinState::default());
        let me = Arc::clone(self);
        let notify = Arc::new(notify);
        std::thread::spawn(move || {
            let (me2, n2) = (Arc::clone(&me), Arc::clone(&notify));
            let r = node.join(&text, &name, &move |c| {
                if let Some(j) = me2.join.lock().unwrap().as_mut() {
                    j.code = Some(c.to_string());
                }
                n2();
            });
            if let Some(j) = me.join.lock().unwrap().as_mut() {
                j.done = true;
                match r {
                    Ok(n) => j.peer = Some(n),
                    Err(e) => j.error = Some(e.to_string()),
                }
            }
            notify();
        });
    }
}
