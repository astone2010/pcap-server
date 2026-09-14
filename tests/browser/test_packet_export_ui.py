"""Export Packet Bytes: Wireshark's per-packet raw-bytes download.

Entirely client-side -- the frame's hex is already in memory for the hex
pane, so this is built from it directly rather than round-tripping to the
server. currentDetail and selectedPacketRow are set straight into the page,
as in the other detail-pane tests, so this runs without a real capture
pipeline behind it.
"""

from __future__ import annotations

from tests.browser.conftest import needs_browser

pytestmark = needs_browser


async def _select_fake_packet(page, frame_number: int, hex_bytes: str):
    await page.evaluate(
        """([frameNumber, hex]) => {
            activatePanel("viewer");
            hide("viewer-empty");
            show("packet-viewer");
            document.getElementById("packet-tbody").innerHTML =
                `<tr data-frame="${frameNumber}"></tr>`;
            selectedPacketRow = document.querySelector(`tr[data-frame="${frameNumber}"]`);
            currentDetail = { frame_hex: hex };
            setDetailVisible(true);
        }""",
        [frame_number, hex_bytes],
    )


async def test_the_export_button_is_hidden_until_a_packet_is_selected(app_page):
    assert await app_page.is_hidden("#btn-export-packet-bytes")
    await _select_fake_packet(app_page, 1, "48656c6c6f")
    assert await app_page.is_visible("#btn-export-packet-bytes")


async def test_export_downloads_the_frames_exact_bytes(app_page):
    """"Hello" in hex, byte for byte -- not re-encoded, not truncated."""
    await _select_fake_packet(app_page, 7, "48656c6c6f")
    async with app_page.expect_download() as dl_info:
        await app_page.click("#btn-export-packet-bytes")
    download = await dl_info.value
    assert download.suggested_filename == "frame-7.bin"
    path = await download.path()
    assert path.read_bytes() == b"Hello"


async def test_clicking_export_with_nothing_selected_does_nothing(app_page):
    """currentDetail is null before any packet is chosen -- the handler must
    not throw building a Blob from nothing."""
    await app_page.evaluate("() => { currentDetail = null; exportPacketBytes(); }")
    assert app_page.console_errors == []
