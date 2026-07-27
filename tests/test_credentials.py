"""Tests for core/credentials.py -- named credential storage for T3 tools."""

import json
import os
import stat

import pytest

from core.credentials import Credential, CredentialError, CredentialStore


def _write(path, data, mode=0o600):
    path.write_text(json.dumps(data), encoding="utf-8")
    os.chmod(path, mode)


def test_loads_a_well_formed_credential(tmp_path):
    _write(
        tmp_path / "creds-vm-lab-01-admin.json",
        {"username": "admin", "secret": "hunter2", "allowed_asset_ids": ["asset:vm-lab-01"]},
    )
    store = CredentialStore(tmp_path)

    credential = store.load("creds-vm-lab-01-admin")

    assert credential.credential_id == "creds-vm-lab-01-admin"
    assert credential.username == "admin"
    assert credential.secret == "hunter2"
    assert credential.authorizes("asset:vm-lab-01") is True
    assert credential.authorizes("asset:other-host") is False


def test_repr_and_str_never_expose_the_secret(tmp_path):
    credential = Credential(
        credential_id="x", username="admin", secret="hunter2", allowed_asset_ids=("asset:x",)
    )

    assert "hunter2" not in repr(credential)
    assert "hunter2" not in str(credential)
    assert "<redacted>" in repr(credential)


def test_unknown_credential_id_fails_closed(tmp_path):
    store = CredentialStore(tmp_path)

    with pytest.raises(CredentialError, match="unknown credential"):
        store.load("does-not-exist")


def test_wrong_permissions_are_rejected(tmp_path):
    _write(
        tmp_path / "creds-loose.json",
        {"username": "admin", "secret": "x", "allowed_asset_ids": ["asset:x"]},
        mode=0o644,
    )
    store = CredentialStore(tmp_path)

    with pytest.raises(CredentialError, match="mode 0600"):
        store.load("creds-loose")


@pytest.mark.parametrize(
    "data",
    [
        {"secret": "x", "allowed_asset_ids": ["asset:x"]},  # missing username
        {"username": "admin", "allowed_asset_ids": ["asset:x"]},  # missing secret
        {"username": "admin", "secret": "x"},  # missing allowed_asset_ids
        {"username": "admin", "secret": "x", "allowed_asset_ids": []},  # empty scope
    ],
)
def test_incomplete_credential_fails_closed(tmp_path, data):
    _write(tmp_path / "creds-bad.json", data)
    store = CredentialStore(tmp_path)

    with pytest.raises(CredentialError):
        store.load("creds-bad")


@pytest.mark.parametrize("credential_id", ["../escape", "a/b", "a\\b", "", "."])
def test_path_traversal_and_invalid_ids_are_rejected(tmp_path, credential_id):
    store = CredentialStore(tmp_path)

    with pytest.raises(CredentialError, match="invalid credential id"):
        store.load(credential_id)


def test_malformed_json_fails_closed(tmp_path):
    path = tmp_path / "creds-broken.json"
    path.write_text("{not json", encoding="utf-8")
    os.chmod(path, 0o600)
    store = CredentialStore(tmp_path)

    with pytest.raises(CredentialError):
        store.load("creds-broken")
