"""Hard-coded secret precision on Bluesky repos (#385).

IPLD content identifiers, empty env-template values, GitHub Actions
permission levels and random-looking test fixtures were reported as
hard-coded secrets. Real credentials must still be found.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from attackmap.analyzers import analyze_repository

_CID_V1 = "bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
_CID_RAW = "bafkreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy"
_CID_V0 = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
_RANDOM_SECRET = "Zx9Qw3Er7Ty1Ui5Op8As2Df6Gh4Jk0LmNbVcXz7Qa3Ws"
_AWS_KEY = "AKIA" + "QZ7RYV3M5TW2XK4P"


def _secrets(tmp_path: Path, files: dict[str, str]) -> set[tuple[str, str]]:
    for rel, text in files.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    # The full analyzer set: config files are read by the built-in config analyzer.
    return {(h.file, h.kind or "") for h in analyze_repository(tmp_path).secret_hints}


@pytest.mark.parametrize("cid", [_CID_V1, _CID_RAW, _CID_V0])
def test_content_identifiers_are_not_secrets(tmp_path: Path, cid: str) -> None:
    found = _secrets(tmp_path, {"src/feed.ts": f"export const FAKE_CID = '{cid}'\nconst post = {{ cid: '{cid}' }}\n"})
    assert ("src/feed.ts", "high_entropy") not in found


def test_a_random_high_entropy_literal_is_still_a_secret(tmp_path: Path) -> None:
    found = _secrets(tmp_path, {"src/client.ts": f"const signingKey = '{_RANDOM_SECRET}'\n"})
    assert ("src/client.ts", "high_entropy") in found


def test_empty_env_template_values_are_not_secrets(tmp_path: Path) -> None:
    found = _secrets(
        tmp_path,
        {"sample.env": "PDS_HOSTNAME=\nPDS_JWT_SECRET=\nPDS_ADMIN_PASSWORD=\nPDS_DATA_DIRECTORY=/pds\n"},
    )
    assert ("sample.env", "config_literal") not in found


def test_a_filled_env_secret_is_still_a_secret(tmp_path: Path) -> None:
    found = _secrets(tmp_path, {"prod.env": "PDS_HOSTNAME=pds.example.com\nPDS_JWT_SECRET=5f2b9c7e1a4d8f3b6e0c9a2d7f1b4e8c\n"})
    assert ("prod.env", "config_literal") in found


def test_workflow_permission_levels_are_not_secrets(tmp_path: Path) -> None:
    workflow = (
        "on: push\npermissions:\n  contents: read\n  id-token: write\n  packages: write\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
    )
    found = _secrets(tmp_path, {".github/workflows/build.yaml": workflow})
    assert not [f for f in found if f[0] == ".github/workflows/build.yaml"]


def test_a_token_literal_in_a_workflow_is_still_a_secret(tmp_path: Path) -> None:
    workflow = "on: push\nenv:\n  deploy_token: 8f3b6e0c9a2d7f1b4e8c5f2b9c7e1a4d\njobs: {}\n"
    found = _secrets(tmp_path, {".github/workflows/deploy.yaml": workflow})
    assert (".github/workflows/deploy.yaml", "config_literal") in found


def test_test_fixtures_skip_the_entropy_guess_but_not_provider_keys(tmp_path: Path) -> None:
    found = _secrets(
        tmp_path,
        {
            "packages/api/tests/mocker.test.ts": f"const token = '{_RANDOM_SECRET}'\n",
            "packages/api/tests/aws.test.ts": f"const key = '{_AWS_KEY}'\n",
        },
    )
    assert ("packages/api/tests/mocker.test.ts", "high_entropy") not in found
    assert any(f == "packages/api/tests/aws.test.ts" for f, _ in found)
