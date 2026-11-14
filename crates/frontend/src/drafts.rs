//! Input ownership for safe document language changes; never persists input.
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum State {
    Clean,
    Unsaved,
    Busy,
}
type Probe = Box<dyn Fn() -> State>;
thread_local! {
    static PROBES: RefCell<BTreeMap<u64, Probe>> = RefCell::new(BTreeMap::new());
    static NEXT: Cell<u64> = const { Cell::new(0) };
    static EDIT_REVISION: Cell<u64> = const { Cell::new(0) };
}
pub fn track(scope: &glory::Scope, probe: impl Fn() -> State + 'static) {
    let id = NEXT.with(|next| {
        let id = next.get().wrapping_add(1);
        next.set(id);
        id
    });
    let owner = scope.downgrade();
    PROBES.with(|probes| {
        probes.borrow_mut().insert(
            id,
            Box::new(move || {
                if owner.upgrade().is_some() {
                    probe()
                } else {
                    State::Clean
                }
            }),
        );
    });
    if scope
        .on_cleanup(move || {
            PROBES.with(|probes| {
                probes.borrow_mut().remove(&id);
            });
        })
        .is_err()
    {
        PROBES.with(|probes| {
            probes.borrow_mut().remove(&id);
        });
    }
}
pub fn state() -> State {
    PROBES.with(|probes| {
        probes
            .borrow()
            .values()
            .map(|probe| probe())
            .max()
            .unwrap_or(State::Clean)
    })
}

/// Counts input proposals without retaining any input value.
pub fn edited() {
    EDIT_REVISION.with(|value| value.set(value.get().wrapping_add(1)));
}
pub fn revision() -> u64 {
    EDIT_REVISION.with(Cell::get)
}
