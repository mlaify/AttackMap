# Defensive Review — bluesky-social/pds (deployment)

## Notable Observations

OBSERVED: This is a deployment repo, not application code. The scanned surface
is a single Node TLS shim (`service/index.js`), plus the operational surface
in the surrounding files. See asset:pds-deployment for the full inventory.

OBSERVED: The Dockerfile builds the container image the operator will actually
run; every hardening decision — non-root user, minimal base, pinned
dependencies — has to happen here. See asset:pds-dockerfile.

INFERRED: Because the actual PDS server binary lives inside `bluesky-social/atproto`
under `packages/pds/`, most application-level review needs to happen there;
this deployment repo covers only how it's shipped. Any control-absence
finding for e.g. `csrf_protection` or `rate_limiting` should be tagged
`infra-layer` here — those live at the reverse proxy in front of the
container, not in this repo.

## Strengths

- The `Dockerfile` uses a minimal base image and pins its dependency versions
  in the pnpm lockfile, giving the operator a reproducible build.
- The `compose.yaml` service composition includes a Caddy reverse proxy
  and a Watchtower auto-updater — the operator gets TLS termination and
  container refresh out of the box without having to run either themselves.

## Weaknesses / Risk Hotspots

- The `installer.sh` shell script pulls remote content over HTTPS and
  executes it as part of setup (curl | bash pattern). See surface:installer-remote-exec.
- The `sample.env` env template documents every secret the deployment needs
  but doesn't emit any control-absence signal in the current scanner —
  every credential in there is a manual injection responsibility for the
  operator. See finding:env-template-inventory.
- The docker-compose service graph exposes ports 80 and 443 from the Caddy
  container to `0.0.0.0`. This is intentional for public-facing PDS operation
  but should be called out so the operator knows to firewall the host
  interface if they wanted internal-only. See surface:compose-public-ports.

## Prioritized Recommendations

- Pin the container base image and the Caddy image by SHA rather than by
  tag so a compromised upstream tag can't silently ship into the operator's
  next deployment. See detect:image-pinning.
- Verify the `installer.sh` remote fetch is signed or checksummed; add
  an explicit checksum verification step before the fetched material is
  executed. See detect:installer-integrity.
- Audit the GitHub Actions build-and-push workflow to confirm it pins
  third-party actions by SHA and doesn't run under `pull_request_target`
  with checkout of PR content. See detect:ci-third-party-actions.

## Analyst Notes

INFERRED to be low-signal: several control-absence findings from the
generic scanner (`encryption_at_rest`, `rate_limiting`, `csrf_protection`)
are `infra-layer` concerns here — the reverse proxy in front of the
container handles them, and they don't belong at the container level.
Reader should treat those as no application code — deployment repo,
not application source.
