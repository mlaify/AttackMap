# The repositories published to PyPI, sourced by the other scripts in this folder.
# Analyzers come first: `attackmap[all]` depends on them, so they are published before AttackMap.
OWNER=mlaify
REVIEWER=mlaifyxyz
ANALYZERS=(
  attackmap-analyzer-atproto
  attackmap-analyzer-c
  attackmap-analyzer-cpp
  attackmap-analyzer-dotnet
  attackmap-analyzer-go
  attackmap-analyzer-iac
  attackmap-analyzer-java-spring
  attackmap-analyzer-node-service
  attackmap-analyzer-omeka-s
  attackmap-analyzer-php-laminas
  attackmap-analyzer-php-web
  attackmap-analyzer-python
  attackmap-analyzer-rust
  attackmap-analyzer-swift
  attackmap-analyzer-terraform
)
CORE=AttackMap

# PyPI project name for a repository: the repository name in lower case.
project_of() { tr '[:upper:]' '[:lower:]' <<<"$1"; }
