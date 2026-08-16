import pytest

import main


def test_prepare_send_capability_file_requires_0600(tmp_path):
    cap = tmp_path / "cap.json"
    cap.write_text('{"namespace":"briar-send-cap"}')
    cap.chmod(0o600)
    assert main._prepare_send_capability_file(str(cap)) == str(cap)

    cap.chmod(0o644)
    with pytest.raises(ValueError, match="0600"):
        main._prepare_send_capability_file(str(cap))


def test_cleanup_send_capability_file_deletes(tmp_path):
    cap = tmp_path / "cap.json"
    cap.write_text("{}")
    cap.chmod(0o600)
    main._cleanup_send_capability_file(str(cap))
    assert not cap.exists()


def test_prepare_empty_path_ok():
    assert main._prepare_send_capability_file("") == ""
