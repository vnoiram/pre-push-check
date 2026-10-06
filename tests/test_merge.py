import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import pre_push_check as ppc

LINE = "test_it(csrf_token = param.token || param.csrf_token, foobar)"


def secret(location: str, detail: str = LINE) -> ppc.Finding:
    return ppc.Finding("Blocker", "secret", location, "Possible secret in tracked file.", "rec", detail)


def test_line_shift_keeps_fingerprint():
    assert ppc.finding_fingerprint(secret("a.rb:10")) == ppc.finding_fingerprint(secret("a.rb:42"))


def test_changed_content_changes_fingerprint():
    assert ppc.finding_fingerprint(secret("a.rb:10")) != ppc.finding_fingerprint(secret("a.rb:10", "other"))


def test_identical_content_merges_across_files_and_lines():
    merged = ppc.merge_findings([secret("a.rb:1"), secret("a.rb:9"), secret("b.rb:3")])
    assert len(merged) == 1
    assert merged[0].locations == ["a.rb:1", "a.rb:9", "b.rb:3"]
    assert merged[0].location.startswith("[x3] ")


def test_contentless_findings_anchor_on_file():
    a = ppc.Finding("Warning", "ci", "w.yml:3", "m", "r")
    b = ppc.Finding("Warning", "ci", "w.yml:30", "m", "r")
    c = ppc.Finding("Warning", "ci", "x.yml:3", "m", "r")
    assert len(ppc.merge_findings([a, b, c])) == 2


def test_sync_survives_line_shift_and_checked_stays():
    with tempfile.TemporaryDirectory() as d:
        repo = Path(d)
        ppc.sync_ignore_file(repo, ppc.merge_findings([secret("a.rb:1")]))
        path = ppc.ignore_file_path(repo)
        path.write_text(path.read_text().replace("[ ]", "[x]"))
        checked, added, _ = ppc.sync_ignore_file(repo, ppc.merge_findings([secret("a.rb:7"), secret("c.rb:2")]))
        assert added == 0 and list(checked.values()) == [True]
        assert "a.rb:7; c.rb:2" in path.read_text()


def test_display_groups_lines_per_file_and_keeps_all_files():
    text = ppc.format_locations(["a.rb:1", "a.rb:9", "b.rb:3"])
    assert text == "[x3] a.rb:1,9; b.rb:3"
    many = ppc.format_locations([f"a.rb:{i}" for i in range(1, 16)] + ["z.rb:1"])
    assert "a.rb:1,2,3,4,5,6,7,8,9,10,...(+5)" in many and "z.rb:1" in many


def test_mark_match_highlights_assignment():
    out = ppc.mark_match(LINE, ppc.SECRET_PATTERN, extend=True)
    assert out == "test_it(**csrf_token = param.token** || param.csrf_token, foobar)"


def test_marked_does_not_change_fingerprint():
    a = secret("a.rb:1")
    b = secret("a.rb:1")
    b.marked = ppc.mark_match(LINE, ppc.SECRET_PATTERN, extend=True)
    assert ppc.finding_fingerprint(a) == ppc.finding_fingerprint(b)
