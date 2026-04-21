# Security-Detections-MCP — server image (stdio MCP + supergateway HTTP wrapper).
# Built by .github/workflows/build.yml, published to ghcr.io.
# Pin base image digest on each dependabot/renovate cycle.

# ---------- Stage 1: build from fork ----------
FROM node:22-alpine AS builder

ARG FORK_REF=main

RUN apk add --no-cache git

WORKDIR /build
COPY . /build/src

WORKDIR /build/src
RUN if [ -n "${FORK_REF}" ] && [ "${FORK_REF}" != "main" ]; then git checkout "${FORK_REF}" || true; fi \
 && git log -1 --pretty='sha=%H date=%ci subject=%s' > /build/build-info.txt 2>/dev/null || echo "unknown" > /build/build-info.txt

RUN npm ci \
 && npm run build \
 && npm pack \
 && mv security-detections-mcp-*.tgz /build/pkg.tgz

# ---------- Stage 2: runtime ----------
FROM node:22-alpine

RUN apk add --no-cache tini wget \
 && npm install -g supergateway@latest \
 && mkdir -p /home/node/.cache/security-detections-mcp \
 && chown -R node:node /home/node/.cache

COPY --from=builder /build/pkg.tgz /tmp/pkg.tgz
COPY --from=builder /build/build-info.txt /etc/security-detections-mcp.build-info

RUN npm install -g /tmp/pkg.tgz && rm /tmp/pkg.tgz

ENV SIGMA_PATHS=/rules/sigma/rules,/rules/sigma/rules-threat-hunting \
    SPLUNK_PATHS=/rules/security_content/detections \
    STORY_PATHS=/rules/security_content/stories \
    ELASTIC_PATHS=/rules/detection-rules/rules \
    KQL_PATHS=/rules/KQL-Bert-JanP,/rules/KQL-jkerai1 \
    SUBLIME_PATHS=/rules/sublime-rules/detection-rules \
    CQL_HUB_PATHS=/rules/Query-Hub/queries \
    ATTACK_STIX_PATH=/rules/attack-stix-data/enterprise-attack/enterprise-attack.json \
    FRESHNESS_MAX_AGE_DAYS=14 \
    MCP_TRANSPORT=stdio \
    MCP_HTTP_PORT=8000 \
    MCP_HTTP_PATH=/mcp \
    MCP_HEALTH_PATH=/healthz

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER node
WORKDIR /home/node

EXPOSE 8000
ENTRYPOINT ["/sbin/tini", "--", "/entrypoint.sh"]
