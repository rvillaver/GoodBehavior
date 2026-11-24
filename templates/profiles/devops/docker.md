---
name: devops/docker
use-when: the project builds container images (Dockerfiles, Containerfiles); install next to the baseline
---

# Dockerfiles and images: rules for small, safe, fast images, each with its probe

Probes marked "tested" were run in October 2026 with hadolint 2.12 (in its container image) and trivy 0.75 on a
sample Dockerfile. Building and scanning are local and read-only. Pushing an image is a publish: a **(pause point)**.

Run hadolint from its image if it isn't installed, so nothing is installed on the machine:
`docker run --rm -i hadolint/hadolint:v2.12.0 < Dockerfile`.

## Build

- **rule:** Every Dockerfile passes hadolint and `trivy config`. They catch different things (tested): hadolint
  flags `latest`, unpinned packages, pip caches and shell-form `CMD`; trivy flags a missing `USER`, secrets in `ENV`
  and a missing `HEALTHCHECK`.
  **probe:** `hadolint Dockerfile` (or the container command above) and `trivy config --severity HIGH,CRITICAL <dir>`
  print no findings, or each has a written reason.
- **rule:** Base images are pinned to a version and a digest (`FROM python:3.13-slim@sha256:...`), so a rebuild gets
  the same base. A tag alone can move; `latest` always does.
  **probe:** `grep -nE '^FROM ' Dockerfile* | grep -v '@sha256:'` prints nothing. Something like Renovate or
  Dependabot keeps the digests current.
- **rule:** Multi-stage builds: compilers, package managers and build caches stay in the build stage; the final
  stage is a small runtime base (distroless, `-slim`, alpine where it fits). Smaller images pull faster, start
  faster, cost less to store and carry fewer vulnerabilities.
  **probe:** `grep -c '^FROM' Dockerfile` is 2 or more for compiled or bundled apps; the final image size from
  `docker image ls <image>` is in line with the app (tens of MB for Go or static sites, low hundreds for Python or
  Node). Compare with the previous build to catch growth.
- **rule:** Layers are ordered for the cache: copy the dependency manifest and install dependencies before copying
  the source, so a code change doesn't reinstall everything.
  **probe:** read the Dockerfile: the lock file (`package-lock.json`, `requirements.txt`, `go.sum`) is copied and
  installed before `COPY . .`. A second build after a source-only change reuses the install layer (`CACHED` in
  `docker build` output).
- **rule:** `.dockerignore` keeps the build context small and secret-free: `.git`, `.env*`, `*.secret`, local build
  output, `node_modules`.
  **probe:** `cat .dockerignore` lists them; `docker build` reports a small context transfer.
- **rule:** Package installs are pinned and cleaned up in the same layer: `--no-install-recommends`, versions
  pinned, lists removed (`rm -rf /var/lib/apt/lists/*`), `pip install --no-cache-dir`.
  **probe:** hadolint DL3008, DL3009, DL3015, DL3042 don't appear (tested).

## Runtime

- **rule:** The container runs as a non-root user.
  **probe:** `docker inspect --format '{{.Config.User}}' <image>` prints a non-root user or UID (empty means root);
  trivy DS-0002 doesn't appear (tested).
- **rule:** No secrets in the image: no `ENV` or `ARG` holding a key, no copied `.env`. Build-time secrets use
  BuildKit secret mounts (`RUN --mount=type=secret,id=<name> ...`); runtime secrets come from the secret manager.
  **probe:** `grep -nE '^(ARG|ENV)[[:space:]]+[A-Za-z_]*(PASSWORD|SECRET|TOKEN|KEY)' Dockerfile*` prints nothing
  (tested: it caught `ENV API_TOKEN=...`, as did trivy DS-0031); `trivy image --scanners secret <image>` finds
  nothing in the layers.
- **rule:** `CMD` and `ENTRYPOINT` use the exec (JSON) form, so the app receives stop signals and shuts down
  cleanly instead of being killed after the grace period.
  **probe:** `grep -nE '^(CMD|ENTRYPOINT)[[:space:]]+[^[]' Dockerfile*` prints nothing; hadolint DL3025 doesn't
  appear (tested).
- **rule:** The image reports its health: a `HEALTHCHECK`, or readiness and liveness probes where an orchestrator
  runs it.
  **probe:** `grep -n '^HEALTHCHECK' Dockerfile`, or the probes in the Kubernetes manifest or chart.
- **rule:** Images in use are scanned and rebuilt when the base gets a fix.
  **probe:** `trivy image --severity HIGH,CRITICAL <image>` for each image in use; HIGH or CRITICAL findings with a
  fixed version have an owner and a date.
