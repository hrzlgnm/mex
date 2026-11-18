// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

#[test]
fn pause_and_resume_log_once_per_transition() {
    use PauseLog::{Paused, Resumed};
    let state = TransmitState::new(true, true);
    // Starting with links: nothing to say.
    assert_eq!(state.update(None, Some(true)), [None, None]);
    // Links gone: one pause line, then silence while it stays empty.
    assert_eq!(state.update(None, Some(false)), [None, Some(Paused)]);
    assert_eq!(state.update(None, Some(false)), [None, None]);
    // Back: one resume line, then silence.
    assert_eq!(state.update(None, Some(true)), [None, Some(Resumed)]);
    assert_eq!(state.update(None, Some(true)), [None, None]);
    // Families are independent; starting empty logs the pause once,
    // and a closed socket (None) keeps its family as is.
    assert_eq!(state.update(Some(false), None), [Some(Paused), None]);
    assert_eq!(state.update(Some(false), None), [None, None]);
    assert_eq!(state.flags(), (false, true));
}

#[test]
fn handoff_publishes_both_families_in_one_step() {
    // v4 goes down while v6 comes up in the same refresh: both
    // flags change in one store, so a reader never sees "no family".
    let state = TransmitState::new(true, false);
    assert_eq!(
        state.update(Some(false), Some(true)),
        [Some(PauseLog::Paused), Some(PauseLog::Resumed)]
    );
    assert_eq!(state.flags(), (false, true));
    assert!(state.any());
}

#[test]
fn pinned_flags_ignore_listener_updates() {
    let state = TransmitState::new(true, true);
    state.pin(false, true);
    assert_eq!(state.update(Some(true), Some(false)), [None, None]);
    assert_eq!(state.flags(), (false, true));
}
