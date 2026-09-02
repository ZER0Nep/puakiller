# Non-root, read-only-friendly image for the public intel factory.
#
# The container needs no network in its default mode: `puakiller-intel run --mode fixture`
# reaches nothing at all, which `puakiller-intel policy --mode fixture` will print. Run it with
# --network none until you have reviewed what a live mode would contact.
FROM python:3.12-slim

# A dedicated unprivileged user. Nothing in this pipeline needs root, and the container may be
# handed public web content, so it should not be able to write to its own code.
RUN useradd --create-home --uid 10001 intel

WORKDIR /app
COPY --chown=root:root pyproject.toml ./
COPY --chown=root:root src ./src
COPY --chown=root:root fixtures ./fixtures

RUN pip install --no-cache-dir . && rm -rf /root/.cache

# Written output goes to a mounted volume, never into the image.
RUN mkdir -p /data && chown intel:intel /data
VOLUME ["/data"]

USER intel
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# Prompts are mounted read-only, not baked in. Installed into site-packages the package cannot
# find them by walking up from its own file, and PromptLibrary would report every stamp as
# "+missing" -- a run whose provenance says the prompt is unknown is not reproducible. The
# mount also means the deployed prompt is the versioned artifact in the repository rather than
# a snapshot of whatever the image happened to be built from.
ENV PUAKILLER_INTEL_PROMPTS=/repo/prompts

# No secrets are baked in, and none are needed: fixture mode is the default.
ENTRYPOINT ["puakiller-intel"]
CMD ["policy", "--mode", "fixture"]
