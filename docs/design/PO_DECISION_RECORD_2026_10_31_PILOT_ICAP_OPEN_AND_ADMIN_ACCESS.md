# PO decision record 2026-10-31: open the pilot's ICAP port now, source addresses later; admin UI like the other product

**Status:** RATIFIED — Product Owner, 2026-10-31 (chat). The PO's words: "şimdi bunları bırakalım. hepsini sen
vereceksin komutların gireeceğim. Şu an için icap portunu açman yeterli src IP'leri sonra tamamlarız. Sonrasında yönetim
ekranı bağlama konusunda nexus için ne yaptıysak aynısını bunun içiny apalım" (let us leave these now; you will give all
the commands and I will enter them. For now it is enough that you open the ICAP port; we complete the source IPs later.
Then, for connecting the admin screen, do for this the same as we did for neXus). Asked about the host name, the PO chose
"DNS olmadan, geçici" (without DNS, temporary).

## Context
PILOT_RUNBOOK step 11 puts a root-only firewall rule (ProxySG addresses only) before the ICAP port opens (step 12),
because plain ICAP has no peer authentication (exception H-2). The PO is not at a terminal and decides to open the port
first.

## Decision
1. The ICAP ServiceLB on the node's 1344 is opened now, without a source restriction; the firewall rule of step 11 follows
   when the PO runs it (the orchestrator gives the exact command).
2. The admin UI is reached like the other product: through the host's Traefik with a host-name rule in the product's own
   namespace, for now the synthetic name `<product>.pilot.test` that the PO maps in his computer's hosts file; a real DNS
   name and certificate come later.

## Consequences
- **Residual risk, accepted by the PO until the firewall rule exists:** any machine that can reach the node can send ICAP
  requests on 1344. It gets the engine's verdicts for its own content and adds events and load; it reads nothing of other
  users. The proxy's AI traffic still passes through the engine only when the PO's proxy rule sends it.
- The orchestrator checks the open port and the in-cluster probe after each change; the firewall step stays the PO's.
- The browser shows a certificate-name warning for `<product>.pilot.test` until a certificate for it exists.

## Amendment 1 (RATIFIED, Product Owner, 2026-10-31, chat): the host name and the pilot's own CA

The PO's words: "devam et abi. ui.rwsafe.local olsun sadece sertifikyıda trust store eklyebiliriz" (go on; let it be
ui.rwsafe.local, and we can add its certificate to the trust store too). This supersedes decision 2's name and the last
consequence above (PR 43 review D-04):

- The admin host is `ui.<product>.local` (`ui.rwsafe.local` today; it follows `deploy/rwsafe/product.env`), mapped by the
  PO's hosts file, still without DNS.
- Its certificate is issued by the pilot's own CA (`tools/pilot/admin_tls.sh`, PILOT_RUNBOOK step 14.1), name-constrained
  to that one host and to no IP address, whose certificate the PO adds to their computer's trust store. No certificate
  warning is expected or clicked through; the other product's certificate in Traefik's default store is not touched.
- **Residual risk, recorded by the orchestrator (PILOT_RUNBOOK step 14.2, read on HOST-A 2026-10-31); not a PO decision
  yet, deferred to go-live:** the host's Traefik
  Service keeps the k3s default external traffic policy `Cluster`, so the ServiceLB hands Traefik every connection from a
  pod-network address and the client's own address is lost before it reaches the product. Traefik trusts no incoming
  forwarded headers (no `forwardedHeaders` argument), so nobody can choose the address the product sees; but the login
  throttle counts every browser as one client: five wrong passwords for one name lock that name for everyone, and twenty
  lock every sign-in, for 15 minutes. In the pilot only the PO signs in. Before go-live the address must be preserved
  (`externalTrafficPolicy: Local` on the shared Traefik Service, a change to the other product's entry point that needs
  its own PO decision) or the throttle keyed differently.
