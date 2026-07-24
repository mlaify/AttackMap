from attackmap.analyzer_contracts import AnalyzerMetadata as SharedAnalyzerMetadata
from attackmap.recon_models import ServiceHint as SharedServiceHint
from attackmap.recon_models import Route as SharedRoute
from attackmap.recon_models import ScanResult as SharedScanResult
from attackmap.sdk.contracts import AnalyzerMetadata as SdkAnalyzerMetadata
from attackmap.sdk.models import Route as SdkRoute
from attackmap.sdk.models import ScanResult as SdkScanResult
from attackmap.sdk.models import ServiceHint as SdkServiceHint

from attackmap.analyzers import AnalyzerMetadata, AnalyzerResult
from attackmap.models import Route, ScanResult, ServiceHint


def test_shared_recon_model_import_paths_alias_core_models() -> None:
    assert SharedRoute is Route
    assert SharedScanResult is ScanResult
    assert SdkRoute is Route
    assert SdkScanResult is ScanResult
    assert SharedServiceHint is ServiceHint
    assert SdkServiceHint is ServiceHint


def test_shared_contract_import_paths_alias_core_contracts() -> None:
    assert SharedAnalyzerMetadata is AnalyzerMetadata
    assert SdkAnalyzerMetadata is AnalyzerMetadata


def test_dependency_hint_is_exported_through_the_sdk() -> None:
    # External analyzers (e.g. attackmap-analyzer-swift) must be able to emit
    # SBOM entries via the stable contract, not an internal module (#186).
    from attackmap.models import DependencyHint as CoreDependencyHint
    from attackmap.sdk import DependencyHint as SdkTop
    from attackmap.sdk.models import DependencyHint as SdkModels

    assert SdkTop is CoreDependencyHint
    assert SdkModels is CoreDependencyHint
    assert SdkTop(name="vapor", version="4.89.0", ecosystem="swiftpm", file="Package.resolved")


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
