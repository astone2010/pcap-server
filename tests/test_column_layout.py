"""The packet list's column layout.

Columns became a preference rather than markup, which puts three things under
test that the fixed table never needed:

  * **The layout is private and per account.** It is stored server-side so it
    follows the operator between browsers, which means the same scoping rule
    the saved filters and views get -- one account's arrangement is invisible
    to another, enforced in the statement rather than beside it.
  * **A field name never reaches tshark's argv unchecked.** An added column is
    a `-e <name>` on the packet list's own tshark pass. A name starting with
    "-" would arrive as a flag instead, so the pattern is refused at the model,
    at the save route and again on every packet list -- not once at the edge.
  * **A field tshark does not know is refused when saved.** The alternative is
    a column that is simply always empty, with nothing to say why.
"""

from __future__ import annotations

import shutil

import pytest
from pydantic import ValidationError

from backend import main
from backend.models import (
    DEFAULT_PACKET_COLUMNS,
    MAX_PACKET_COLUMNS,
    ColumnLayout,
    PacketColumn,
)
from tests.test_custom_filters import _enrol, enrolled, secure_client  # noqa: F401  (fixtures)

needs_tshark = pytest.mark.skipif(
    shutil.which("tshark") is None,
    reason="tshark is not installed in this environment",
)

TCP_PORT = {"id": "field:tcp.srcport", "title": "Src port", "field": "tcp.srcport"}


# --- the model: what a column may be ----------------------------------------


def test_a_builtin_column_carries_no_field():
    """Its id decides what it shows. A field beside it would be a second,
    contradictory answer that the renderer would have to choose between."""
    assert PacketColumn(id="source", title="Source").field == ""
    with pytest.raises(ValidationError):
        PacketColumn(id="source", title="Source", field="ip.src")


def test_a_custom_column_is_named_after_its_own_field():
    col = PacketColumn(**TCP_PORT)
    assert col.field == "tcp.srcport"
    with pytest.raises(ValidationError):
        PacketColumn(id="field:tcp.srcport", title="x", field="udp.srcport")


@pytest.mark.parametrize("field", ["-r", "-e", "--version", "tcp.srcport;id", "$(id)", "a b", ""])
def test_a_field_that_is_not_a_field_name_is_refused(field):
    """The argv rule, at the model. "-r" is the case that matters: as a `-e`
    argument it is a field, but one character out of place and tshark reads it
    as the flag that chooses which file to open."""
    with pytest.raises(ValidationError):
        PacketColumn(id=f"field:{field}", title="x", field=field)


def test_an_unknown_builtin_id_is_refused():
    with pytest.raises(ValidationError):
        PacketColumn(id="bogus", title="x")


def test_a_title_is_collapsed_to_one_line():
    """A heading is rendered into a table header; a newline in one is either a
    mistake or an attempt to break the layout."""
    assert PacketColumn(id="info", title="  two \n\t lines ").title == "two lines"
    with pytest.raises(ValidationError):
        PacketColumn(id="info", title="   ")


def test_the_same_column_twice_is_refused():
    with pytest.raises(ValidationError):
        ColumnLayout(columns=[TCP_PORT, dict(TCP_PORT)])


def test_a_layout_needs_at_least_one_column_and_not_too_many():
    with pytest.raises(ValidationError):
        ColumnLayout(columns=[])
    too_many = [
        {"id": f"field:ip.x{n}", "title": str(n), "field": f"ip.x{n}"}
        for n in range(MAX_PACKET_COLUMNS + 1)
    ]
    with pytest.raises(ValidationError):
        ColumnLayout(columns=too_many)


# --- the routes -------------------------------------------------------------


def test_an_account_starts_on_the_default_and_says_so(secure_client, enrolled):
    """Absent, not a stored copy of the built-in list: the difference is what
    lets a later change to the default reach everyone who never customised."""
    body = secure_client.get("/api/column-layout").json()
    assert body == {"columns": None, "default": True}
    assert secure_client.get("/api/column-layout/default").json() == {
        "columns": DEFAULT_PACKET_COLUMNS
    }


def test_a_saved_layout_comes_back(secure_client, enrolled):
    columns = [
        {"id": "number", "title": "No.", "field": ""},
        TCP_PORT,
        {"id": "info", "title": "Summary", "field": ""},
    ]
    resp = secure_client.put("/api/column-layout", json={"columns": columns})
    assert resp.status_code == 200, resp.text
    got = secure_client.get("/api/column-layout").json()
    assert got["default"] is False
    assert [c["id"] for c in got["columns"]] == ["number", "field:tcp.srcport", "info"]
    assert [c["title"] for c in got["columns"]] == ["No.", "Src port", "Summary"]


def test_resetting_goes_back_to_the_default(secure_client, enrolled):
    secure_client.put("/api/column-layout", json={"columns": [TCP_PORT]})
    assert secure_client.delete("/api/column-layout").status_code == 200
    assert secure_client.get("/api/column-layout").json() == {"columns": None, "default": True}


def test_one_accounts_layout_is_invisible_to_another(secure_client, enrolled):
    secure_client.put("/api/column-layout", json={"columns": [TCP_PORT]})
    other = _enrol(secure_client)  # swaps the session cookie to a second account
    try:
        assert secure_client.get("/api/column-layout").json()["default"] is True
    finally:
        main.db.delete_user(other)


def test_a_field_shaped_like_a_flag_is_refused_by_the_route(secure_client, enrolled):
    resp = secure_client.put(
        "/api/column-layout",
        json={"columns": [{"id": "field:-r", "title": "x", "field": "-r"}]},
    )
    assert resp.status_code == 422, resp.text
    assert secure_client.get("/api/column-layout").json()["default"] is True


@needs_tshark
def test_a_field_tshark_does_not_know_is_refused(secure_client, enrolled):
    """Rather than saved and left to render an empty column on every packet."""
    resp = secure_client.put(
        "/api/column-layout",
        json={"columns": [{
            "id": "field:definitely.not.a.real.field",
            "title": "x",
            "field": "definitely.not.a.real.field",
        }]},
    )
    assert resp.status_code == 400, resp.text
    assert "definitely.not.a.real.field" in resp.json()["detail"]
    assert secure_client.get("/api/column-layout").json()["default"] is True


@needs_tshark
def test_a_real_field_is_accepted(secure_client, enrolled):
    resp = secure_client.put("/api/column-layout", json={"columns": [TCP_PORT]})
    assert resp.status_code == 200, resp.text


def test_the_layout_survives_a_field_the_client_repeats(secure_client, enrolled):
    """Two columns on the same field are the same column: the id is derived
    from the field precisely so a duplicate cannot be created by accident."""
    resp = secure_client.put(
        "/api/column-layout", json={"columns": [TCP_PORT, dict(TCP_PORT)]}
    )
    assert resp.status_code == 422, resp.text
