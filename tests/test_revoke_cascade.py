"""D2 — revoking a delegator must also revoke what it delegated (it used to edit root grants only)."""

from __future__ import annotations

from decision_os_min.attenuation import AuthorityGraph


def _graph() -> AuthorityGraph:
    g = AuthorityGraph(root_key=b"k" * 32)
    g.grant("alice", "tool:a")
    g.grant("alice", "tool:b")
    return g


def test_revoking_the_delegator_kills_the_delegation():
    g = _graph()
    g.delegate("alice", "bob", ["a"])
    assert g.holds("bob", "tool:a")
    g.revoke("alice", "tool:a")
    assert not g.holds("alice", "tool:a")
    assert not g.holds("bob", "tool:a"), "bob kept authority alice no longer has (D2)"


def test_cascade_reaches_grandchildren():
    g = _graph()
    g.delegate("alice", "bob", ["a"])
    g.delegate("bob", "carol", ["a"])
    assert g.holds("carol", "tool:a")
    g.revoke("alice", "tool:a")
    assert not g.holds("bob", "tool:a")
    assert not g.holds("carol", "tool:a")


def test_revoked_holder_cannot_mint_new_delegations():
    import pytest

    from decision_os_min import AttenuationError

    g = _graph()
    g.delegate("alice", "bob", ["a"])
    g.revoke("alice", "tool:a")
    with pytest.raises(AttenuationError):
        g.delegate("bob", "carol", ["a"])


def test_partial_revocation_is_all_or_nothing_and_fail_closed():
    # A macaroon's allowlist cannot be edited without the root key, so a delegation of {a, b} dies as a whole
    # when alice loses a. bob does NOT keep b.
    g = _graph()
    g.delegate("alice", "bob", ["a", "b"])
    g.revoke("alice", "tool:a")
    assert g.holds("alice", "tool:b")
    assert not g.holds("bob", "tool:a")
    assert not g.holds("bob", "tool:b")


def test_unrelated_delegations_are_untouched():
    g = _graph()
    g.delegate("alice", "bob", ["a"])
    g.delegate("alice", "carol", ["b"])
    g.revoke("alice", "tool:a")
    assert not g.holds("bob", "tool:a")
    assert g.holds("carol", "tool:b")


def test_delegation_survives_while_minter_still_holds_via_another_credential():
    g = _graph()
    g.grant("dave", "tool:a")
    g.delegate("dave", "alice", ["a"])  # alice now also holds a through dave's macaroon
    g.delegate("alice", "bob", ["a"])
    g.revoke("alice", "tool:a")  # drops alice's ROOT grant only
    assert g.holds("alice", "tool:a")
    assert g.holds("bob", "tool:a")
    g.revoke("dave", "tool:a")  # now alice's last credential is gone
    assert not g.holds("alice", "tool:a")
    assert not g.holds("bob", "tool:a")


def test_revoking_a_capability_nobody_delegated_changes_nothing_else():
    g = _graph()
    g.delegate("alice", "bob", ["a"])
    g.revoke("alice", "tool:b")
    assert g.holds("bob", "tool:a")
    assert g.holds("alice", "tool:a")


def test_wildcard_revocation_cascades():
    g = AuthorityGraph(root_key=b"k" * 32)
    g.grant("root", "*")
    g.delegate("root", "bob", ["anything"])
    assert g.holds("bob", "tool:anything")
    g.revoke("root", "*")
    assert not g.holds("bob", "tool:anything")
