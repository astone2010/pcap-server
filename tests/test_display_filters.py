"""The operator's own saved display filters.

The same three properties as the saved capture filters (test_custom_filters.py)
-- private, validated on the way in, a duplicate name is a 409 -- plus the one
that makes them a separate thing: they are checked as display filters, not as
BPF, and the two lists never mix.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from backend import main
from backend.database import MAX_CUSTOM_FILTERS_PER_USER
from backend.models import FILTER_MAX_LEN, DisplayFilterRequest
from tests.test_custom_filters import _enrol, enrolled, secure_client  # noqa: F401  (fixtures)


def test_a_saved_display_filter_comes_back_in_the_list(secure_client, enrolled):
    resp = secure_client.post("/api/display-filters",
                              json={"label": "retransmits", "expression": "tcp.analysis.retransmission"})
    assert resp.status_code == 200, resp.text
    listed = secure_client.get("/api/display-filters").json()
    assert [(f["label"], f["expression"]) for f in listed] == [("retransmits", "tcp.analysis.retransmission")]


def test_display_and_capture_filters_are_separate_lists(secure_client, enrolled):
    secure_client.post("/api/display-filters", json={"label": "same name", "expression": "dns"})
    resp = secure_client.post("/api/filters", json={"label": "same name", "expression": "port 53"})
    assert resp.status_code == 200, "a name used by a display filter blocked a capture filter"
    assert [f["expression"] for f in secure_client.get("/api/filters").json()] == ["port 53"]
    assert [f["expression"] for f in secure_client.get("/api/display-filters").json()] == ["dns"]


def test_wireshark_operators_the_bpf_rule_would_refuse_are_allowed():
    """&& and || are ordinary display-filter syntax."""
    req = DisplayFilterRequest(label="x", expression="tcp.flags.syn == 1 && !(ip.addr == 10.0.0.1)")
    assert req.expression.startswith("tcp.flags.syn")


@pytest.mark.parametrize("expr", ["dns; rm -rf /", "$(id)", "`id`", "a\\b"])
def test_the_display_filter_rule_is_applied(expr):
    with pytest.raises(ValidationError):
        DisplayFilterRequest(label="x", expression=expr)


def test_an_over_long_expression_is_refused():
    with pytest.raises(ValidationError):
        DisplayFilterRequest(label="x", expression="a" * (FILTER_MAX_LEN + 1))


@pytest.mark.parametrize("expr", ["", "   "])
def test_it_needs_an_expression(expr):
    with pytest.raises(ValidationError):
        DisplayFilterRequest(label="x", expression=expr)


def test_the_same_name_twice_is_a_409(secure_client, enrolled):
    body = {"label": "twice", "expression": "http"}
    assert secure_client.post("/api/display-filters", json=body).status_code == 200
    assert secure_client.post("/api/display-filters", json=body).status_code == 409


def test_one_users_display_filters_are_invisible_to_another(secure_client, enrolled):
    secure_client.post("/api/display-filters", json={"label": "mine", "expression": "arp"})
    other = _enrol(secure_client)
    try:
        assert secure_client.get("/api/display-filters").json() == []
    finally:
        main.db.delete_user(other)


def test_another_user_cannot_delete_yours(secure_client, enrolled):
    fid = secure_client.post("/api/display-filters", json={"label": "keep", "expression": "icmp"}).json()["id"]
    other = _enrol(secure_client)
    try:
        assert secure_client.delete(f"/api/display-filters/{fid}").status_code == 404
    finally:
        main.db.delete_user(other)
    assert [f["id"] for f in main.db.list_custom_filters(enrolled, "display")] == [fid]


def test_deleting_one_removes_it(secure_client, enrolled):
    fid = secure_client.post("/api/display-filters", json={"label": "gone", "expression": "udp"}).json()["id"]
    assert secure_client.delete(f"/api/display-filters/{fid}").status_code == 200
    assert secure_client.get("/api/display-filters").json() == []


def test_the_cap_applies_to_display_filters_too(secure_client, enrolled):
    for i in range(MAX_CUSTOM_FILTERS_PER_USER):
        main.db.add_custom_filter(enrolled, f"f{i}", "dns", "display")
    resp = secure_client.post("/api/display-filters", json={"label": "one more", "expression": "dns"})
    assert resp.status_code == 409


def test_an_unknown_kind_is_refused_before_any_sql():
    with pytest.raises(ValueError, match="unknown filter kind"):
        main.db.list_custom_filters("u", "users; DROP TABLE users")


def test_deleting_the_account_deletes_its_display_filters(secure_client):
    user_id = _enrol(secure_client)
    main.db.add_custom_filter(user_id, "x", "dns", "display")
    main.db.delete_user(user_id)
    assert main.db.list_custom_filters(user_id, "display") == []
