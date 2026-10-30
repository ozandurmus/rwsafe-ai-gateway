# ADR-003: Reverse proxy and host-based routing, including the exact neXus change

Status: PROPOSED
Date: 2026-10-30
Answers: brief section 2 (Browser access), section 4 rules 3 and 4; council ARCH-3, Argon P0-3, offensive seat "shared
ingress" P1; brief 10.6 question 2 (LLM gateway on 443)

## Context

The PO decided that a reverse proxy in front routes by host name on 443: `nexus.<corp-domain>` to neXus and
`rwsafe.<corp-domain>` to rwsafe; nobody types a port; cookies, sessions and CSP stay separate. Brief rule 4 prefers the
existing k3s ingress controller (Traefik) over a new component; any neXus ingress change is a separate neXus PR with zero
downtime. Measured 2026-10-30: one Traefik (k3s bundled) with the Kubernetes Ingress and CRD providers, HTTP→HTTPS
redirect, a default certificate from a local CA (one DNS SAN, one IP SAN, valid to 2028-12), **no default backend**, and
neXus's Ingress `ui2` with a **host-less catch-all rule** and a host rule, both to `ui2-service`. neXus's
`tools/delivery/hosta_deploy.sh` health-checks `https://127.0.0.1/` with no Host header, which only works because of the
catch-all. The corporate platform fronts with Nginx/OpenShift Routes.

## Decision

1. **Traefik stays the single reverse proxy on HOST-A**; no Nginx, no second ingress controller. Routing is by host name
   on the existing 443 entrypoint. rwsafe adds **two** host names: `rwsafe.<corp-domain>` (admin UI and API) and
   `ai-api.<corp-domain>` (LLM API gateway, council Q2 recommendation: yes). An optional third, `agent.<corp-domain>`, is
   reserved for the off-net agent channel (ADR-006) and is not created until that ADR is accepted.
2. **Per-host TLS**: each product owns a `kubernetes.io/tls` Secret in its own namespace and lists it in its own Ingress
   `tls:` block (SNI binding); Traefik's default certificate stays as the fallback for name-less requests. Certificates
   come from the corporate CA when the host names exist in DNS (brief: "the PO can register a host name"); until then the
   neXus local CA issues them (same as today's default certificate). rwsafe never reads the neXus TLS Secret.
3. **Explicit 404 for unknown hosts**: once the host-less catch-all rule is removed from the neXus Ingress, Traefik
   itself answers `404 Not Found` for any request whose Host matches no Ingress rule, bare IP included (PLAT-F8); no extra
   default-backend workload is deployed. The neXus PR's test asserts `curl -sk https://<node-address>/` returns 404 with
   the default certificate.
4. **Browser isolation**: rwsafe sets `__Host-` prefixed session and CSRF cookies (no `Domain`, `Secure`, `Path=/`), a
   host-only CSP (`default-src 'self'`, no parent-domain allowances), HSTS (max-age 1 year once the corporate certificate
   is in place; before that `max-age=0` is not set either, the header is simply absent), `Referrer-Policy:
   same-origin`, `X-Frame-Options: DENY`. Ingress snippet annotations and Traefik middleware that inject headers are not
   used: headers come from the application so the behaviour is identical under OpenShift Routes (ARCH-3).
5. **HTTP/2 and streaming**: the gateway host serves HTTP/2 to clients; Traefik terminates TLS and forwards HTTP/1.1
   upstream; SSE works through Traefik unchanged (flush per event, no response buffering). WebSocket is not needed on the
   gateway host.

## The exact neXus change (separate neXus PR, zero downtime)

Two files change in the neXus repository; rwsafe never applies them.

**`deploy/ui2/60-ingress.yaml`** (remove the catch-all, add the corporate host, bind TLS by SNI):

```diff
 spec:
+  tls:
+    - hosts: [ui2.nexus.local, nexus.<corp-domain>]   # the value comes from ui2-config ingress_host and a new key ingress_host_corp
+      secretName: ui2-tls
   rules:
-    # Product Owner, 2026-09-22: the console must also answer on the bare
-    # node address (https://<node-ip>/) until the DNS record exists -- a
-    # host-less rule matches any Host header, on both 80 and 443 (Traefik
-    # serves its default certificate when no SNI name matches).
-    - http:
-        paths:
-          - path: /
-            pathType: Prefix
-            backend:
-              service:
-                name: ui2-service
-                port:
-                  name: http
     - host: ui2.nexus.local
       http:
         paths:
           - path: /
             pathType: Prefix
             backend:
               service:
                 name: ui2-service
                 port:
                   name: http
+    - host: nexus.<corp-domain>
+      http:
+        paths:
+          - path: /
+            pathType: Prefix
+            backend:
+              service:
+                name: ui2-service
+                port:
+                  name: http
```

The host names are per-stage values and arrive from the ConfigMap at render time, never as a repository literal (neXus
PORT-2 and the privacy gate).

**`tools/delivery/hosta_deploy.sh`** line 121 (the health check must send the Host header once the catch-all is gone):

```diff
-echo "site $(curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' https://127.0.0.1/)"
+SITE_HOST=$(kubectl -n ui2 get configmap ui2-config -o jsonpath='{.data.ingress_host}')
+echo "site $(curl -sk --noproxy '*' --resolve "$SITE_HOST:443:127.0.0.1" -o /dev/null -w '%{http_code}' "https://$SITE_HOST/")"
```

Also in the same neXus PR: the `ui2-tls` Secret contract file (`26-secret-tls.yaml`, name and type only), the operator
step that creates the certificate, and the shared build lock `flock ~/.locks/hosta-build.lock` in `hosta_deploy.sh`
(ADR-011, PLAT-F9). **How the host name reaches the Ingress without touching the tree** (PLAT-F8): `module_deploy.py`
reads `ingress_host` and `ingress_host_corp` from the in-cluster ConfigMap and streams a transient patch of the Ingress
to `kubectl diff`/`kubectl apply -f -`; the committed file keeps a placeholder. Rollout order for zero downtime: (a)
create `ui2-tls`; (b) apply the new Ingress (Traefik reloads routes without dropping connections; the host rule already exists, so `ui2.nexus.local`
requests are unaffected; bare-IP requests start getting 404, which is the intended behaviour and is announced to
operators beforehand); (c) merge the `hosta_deploy.sh` change in the same PR so the next deploy's health check uses the
Host header. Nothing restarts.

## Alternatives considered

- A new Nginx reverse proxy in front of Traefik: a second TLS terminator, a second config to drift, no gain; rejected by
  brief rule 4.
- Keeping the catch-all and adding rwsafe hosts: a request with an unknown Host still lands on neXus; the offensive seat's
  host-confusion risk stays; rejected.
- The LLM gateway on its own TCP port (brief section 4 asked for a proposal): one more firewall exception, SDK users type
  a port, no benefit over a host name; the council's "443 by host name" is adopted. The decision is presented to the PO
  in OPEN_QUESTIONS Q-2 because the brief asked for a port.
- Path-based routing (`rwsafe.<corp>/api/ai`): cookie and CSP isolation is weaker on one host; rejected.

## Consequences

- neXus loses bare-IP access to its console: operators need DNS or a hosts entry for `nexus.<corp-domain>` or
  `ui2.nexus.local`. This is the one user-visible neXus change and is stated in OPEN_QUESTIONS Q-13 for the PO's
  go-ahead and timing.
- Each product's certificate lifecycle is its own.
- Under OpenShift the same host names become Routes with edge TLS; the base manifests do not change.

## Evidence and UNVERIFIED facts

- Measured: Traefik args, Ingress rules, TLS secret shape (2026-10-30 inventory); neXus `60-ingress.yaml` and
  `hosta_deploy.sh` read in the neXus checkout.
- UNVERIFIED: whether the corporate DNS and CA can issue for `ai-api.<corp-domain>` as a third name (the PO registers
  host names per the hardening record).

## Open questions

OPEN_QUESTIONS Q-2 (gateway on 443), Q-13 (neXus bare-IP access ends; when to deliver the neXus PR).
