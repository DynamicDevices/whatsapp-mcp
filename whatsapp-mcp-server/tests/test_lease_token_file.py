import pytest

import main


def test_read_lease_token_file_requires_private_regular_file(tmp_path):
    token = tmp_path / "lease-token"
    token.write_text("capability")
    token.chmod(0o600)
    assert main._read_lease_token_file(str(token)) == "capability"

    token.chmod(0o644)
    with pytest.raises(ValueError, match="0600"):
        main._read_lease_token_file(str(token))


def test_read_lease_token_file_rejects_empty(tmp_path):
    token = tmp_path / "lease-token"
    token.write_text("")
    token.chmod(0o600)
    with pytest.raises(ValueError, match="empty"):
        main._read_lease_token_file(str(token))


def test_no_token_file_means_unleased_call():
    assert main._read_lease_token_file("") == ""
