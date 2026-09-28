#[derive(Clone, Copy, Debug)]
struct CapabilityState {
    authenticated: bool,
    tenant_match: bool,
    mutating: bool,
    admin: bool,
}

fn admitted(state: CapabilityState) -> bool {
    return state.authenticated
        && state.tenant_match
        && (!state.mutating || state.admin);
}

fn imperative_oracle(state: CapabilityState) -> bool {
    if !state.authenticated {
        return false;
    }

    if !state.tenant_match {
        return false;
    }

    if state.mutating && !state.admin {
        return false;
    }

    return true;
}

#[test]
fn preserves_capability_boundary_examples() {
    assert!(admitted(CapabilityState {
        authenticated: true,
        tenant_match: true,
        mutating: false,
        admin: false,
    }));

    assert!(!admitted(CapabilityState {
        authenticated: true,
        tenant_match: true,
        mutating: true,
        admin: false,
    }));

    assert!(!admitted(CapabilityState {
        authenticated: true,
        tenant_match: false,
        mutating: false,
        admin: true,
    }));
}

#[test]
fn exhaustively_checks_all_boolean_capability_states() {
    for authenticated in [false, true] {
        for tenant_match in [false, true] {
            for mutating in [false, true] {
                for admin in [false, true] {
                    let state = CapabilityState {
                        authenticated,
                        tenant_match,
                        mutating,
                        admin,
                    };
                    let allowed = admitted(state);

                    assert_eq!(
                        allowed,
                        imperative_oracle(state),
                        "capability admission mismatch for {state:?}"
                    );

                    if allowed {
                        assert!(state.authenticated);
                        assert!(state.tenant_match);

                        if state.mutating {
                            assert!(state.admin);
                        }
                    }
                }
            }
        }
    }
}
