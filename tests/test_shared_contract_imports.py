from attackmap.analyzer_contracts import AnalyzerMetadata as SharedAnalyzerMetadata
from attackmap.recon_models import Route as SharedRoute
from attackmap.recon_models import ScanResult as SharedScanResult
from attackmap.sdk.contracts import AnalyzerMetadata as SdkAnalyzerMetadata
from attackmap.sdk.models import Route as SdkRoute
from attackmap.sdk.models import ScanResult as SdkScanResult

from attackmap.analyzers import AnalyzerMetadata, AnalyzerResult
from attackmap.models import Route, ScanResult


def test_shared_recon_model_import_paths_alias_core_models() -> None:
    assert SharedRoute is Route
    assert SharedScanResult is ScanResult
    assert SdkRoute is Route
    assert SdkScanResult is ScanResult


def test_shared_contract_import_paths_alias_core_contracts() -> None:
    assert SharedAnalyzerMetadata is AnalyzerMetadata
    assert SdkAnalyzerMetadata is AnalyzerMetadata


def test_legacy_analyzers_imports_remain_compatible() -> None:
    result = AnalyzerResult(root=".")
    metadata = AnalyzerMetadata(
        name="example",
        description="example metadata",
        scope="example scope",
        ecosystems=("python",),
    )

    assert isinstance(result, ScanResult)
    assert metadata.name == "example"
