// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

#[test]
fn denied_types_are_scoped_to_their_host() {
    // An RFC denial for host X must not suppress the lookup for an
    // alternate SRV target Y; a legacy denial (None) covers every host.
    let denied = vec![(28, Some("knulp.local".to_string())), (1, None)];
    assert_eq!(denied_for_host(&denied, "knulp.local."), vec![1, 28]);
    assert_eq!(denied_for_host(&denied, "KNULP.local"), vec![1, 28]);
    assert_eq!(denied_for_host(&denied, "other.local"), vec![1]);
    assert!(denied_for_host(&[], "knulp.local").is_empty());
}
