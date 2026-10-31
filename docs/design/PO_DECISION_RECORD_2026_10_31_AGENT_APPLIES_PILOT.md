# PO decision record 2026-10-31: the orchestrating agent builds and applies the pilot, step by step

**Status:** RATIFIED — Product Owner, 2026-10-31 (chat). The PO's words: "Tamamiyle kendine ait container yapı isim
degistirilebilir olmalı rwsafe dedik ama belki değişir. Tamamiyle ayrı. Asla nexusla çakismayacak. Deploymentlar sende
nasıl bağlanacağını biliyorsun ayağa kaldir bakalım sonrasında adım adım ilerleriz" (a fully own container structure;
the name must be changeable, we said rwsafe but it may change; fully separate; never colliding with neXus; you know how to
connect for the deployments, bring it up and we proceed step by step). Asked with the recommendation first, the PO chose
"Evet, böyle kur (Önerilen)" (yes, install this way).

## Context
DEPLOY_AND_SHARED_HOST_RUNBOOK.md section 7 (ratified by Q-42) says the apply is the PO's step and no agent runs
`kubectl apply` against HOST-A. AGENTS.md section 8 says anything that changes something on the host is asked of the PO
first, every time, and that an agent never holds `sudo`. The PO wants the orchestrator to run the pilot build and apply.

## Decision
1. The orchestrating agent (not a worker) may build the product's images and apply its manifests on HOST-A, only inside
   the product's own namespaces (`<product>`, `<product>-build`, `<product>-security`) and the product's own
   cluster-scoped objects (its namespaces and PriorityClasses, all carrying the product name).
2. Before each host-changing step the agent states the step in one line in chat and waits for the PO's confirmation;
   a deletion is asked separately. Read-only, masked checks need no confirmation.
3. Never: any neXus namespace, object, label, image repository or port; Traefik, the registry or other kube-system
   objects; host settings; `sudo` (a root-only action stays the PO's, in a terminal the agent opens).
4. The product name is a single parameter (default `rwsafe`); renaming the product must not require editing manifests
   by hand, and nothing rendered may collide with neXus (manifest check).
5. Host output is masked before the agent reads it (AGENTS.md 4.3); no real address, host or user name is written to the
   repository or chat.

## Consequences
- AMENDS DEPLOY_AND_SHARED_HOST_RUNBOOK.md section 7 ("the apply is the Product Owner's step") for the pilot: either the
  PO or the orchestrating agent runs each step, under points 1 to 3.
- Workers still never reach the host (AGENTS.md section 13).
- The proxy (ProxySG) steps stay the PO's (Q-20, Q-21).

## Supersedes
Runbook section 7's "No agent runs `kubectl apply` ... against HOST-A" for the product's own namespaces, under this record.
