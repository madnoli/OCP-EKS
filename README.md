# 🚀 cluster-upgrade-snapshot  (v5)

> A safety-net tool that takes a **complete fingerprint** of your Kubernetes / OpenShift
> cluster **before** an upgrade and **after** an upgrade, then highlights every meaningful
> change across **22 resource categories spanning all 3 architectural layers**.
> Works on **Amazon EKS** and **Red Hat OpenShift** with the same script.

---

## 🤔 Why does this exist?

A "successful" cluster upgrade can still silently break workloads. The control plane comes back fine, the API returns 200s — but production breaks in ways `oc adm upgrade status` won't show you:

- A node failed to uncordon, capacity dropped 33%
- A PVC went `Pending`, your database can't mount its data
- A StorageClass lost its default annotation — new PVCs are stuck
- A CRD dropped `v1beta1`, every object on that version is dead
- A ConfigMap got re-rendered by an operator with the wrong values
- A RoleBinding lost a subject, breaking your CI service account
- An OpenShift ClusterOperator went `Degraded=True`

**You will not see any of these in the upgrade success message.** You'll see them as a 3am pager.

This tool gives you a **complete before/after diff in 30 seconds**, organized by the three layers of your cluster.

---

## 📦 What gets captured (22 categories across 3 layers)

### Layer 1 — Platform (cluster-scoped)
| # | Resource | Why it matters |
|---|----------|----------------|
| 1 | Nodes | Detect failed uncordons, capacity loss, kubelet version mismatch |
| 2 | PersistentVolumes | Detect `Released` / `Failed` phase, lost claim binding |
| 3 | StorageClasses | Detect default flag flips, provisioner changes |
| 4 | CustomResourceDefinitions | Detect deprecated API version removal (the silent killer) |
| 5 | APIServices | Detect aggregated APIs going unavailable (metrics-server, etc.) |
| 6 | ClusterOperators *(OCP)* | Direct health signal from OpenShift control plane |

### Layer 2 — Configuration (mostly namespace-scoped)
| # | Resource | Why it matters |
|---|----------|----------------|
| 7 | ConfigMaps | Hash-based drift detection (no raw values stored) |
| 8 | Secrets | Opt-in via flag, hash-only — detect TLS cert rotation, password changes |
| 9 | Services | clusterIP, selector, port changes break service discovery |
| 10 | Routes *(OCP)* | Host, TLS termination, target service changes |
| 11 | Ingresses | EKS equivalent of Routes |
| 12 | NetworkPolicies | Firewall rule changes can silently kill connectivity |
| 13 | RoleBindings | Detect lost service account permissions |
| 14 | PersistentVolumeClaims | Detect `Pending` / `Lost` phases — app data inaccessible |

### Layer 3 — Workloads (namespace-scoped)
| # | Resource | Why it matters |
|---|----------|----------------|
| 15 | Namespaces | Count + list, detect terminated/added namespaces |
| 16 | Deployments | spec.replicas vs ready.replicas mismatch |
| 17 | Pods | `CrashLoopBackOff`, `ImagePullBackOff`, `Pending` regression |
| 18 | StatefulSets | Same as Deployments + governing service drift |
| 19 | CronJobs | Schedule changes, suspended flag flips |
| 20 | HPAs | Min/max replica range, target ref changes |
| 21 | PDBs | Detect breached disruption budgets |
| 22 | ResourceQuotas | Hard limit changes can silently throttle apps |

---

## 🛠️ Installation

```bash
pip3 install -r requirements.txt
chmod +x cluster_upgrade_snapshot_v5.py
```

**Requirements:**
- Python 3.8+
- Network reachability to your cluster API server
- Valid kubeconfig (`~/.kube/config`) OR an in-cluster ServiceAccount
- Read permissions on all 22 resource types (see "Minimum RBAC" below)

---

## ⚡ Quick start

### Step 1 — Authenticate

```bash
# EKS:
aws eks update-kubeconfig --name my-cluster --region us-east-1

# OpenShift:
oc login --token=<sha256~...> --server=https://api.my-ocp.example.com:6443
```

### Step 2 — BEFORE snapshot (right before upgrade)

```bash
python3 cluster_upgrade_snapshot_v5.py capture \
    --label pre-upgrade \
    --output-dir /tmp/upgrade-2026-05-27
```

Add `--include-secrets` if your security policy allows hash-based secret tracking:

```bash
python3 cluster_upgrade_snapshot_v5.py capture \
    --label pre-upgrade \
    --output-dir /tmp/upgrade-2026-05-27 \
    --include-secrets
```

This creates:
```
/tmp/upgrade-2026-05-27/
├── snapshot_pre-upgrade.json
├── snapshot_pre-upgrade_namespaces.csv
├── snapshot_pre-upgrade_deployments.csv
├── snapshot_pre-upgrade_pods.csv
├── snapshot_pre-upgrade_configmaps.csv
├── snapshot_pre-upgrade_rolebindings.csv
├── snapshot_pre-upgrade_cronjobs.csv
├── snapshot_pre-upgrade_statefulsets.csv
├── snapshot_pre-upgrade_services.csv
├── snapshot_pre-upgrade_routes.csv             # OCP only
├── snapshot_pre-upgrade_pvcs.csv
├── snapshot_pre-upgrade_pvs.csv
├── snapshot_pre-upgrade_storageclasses.csv
├── snapshot_pre-upgrade_nodes.csv
├── snapshot_pre-upgrade_ingresses.csv
├── snapshot_pre-upgrade_networkpolicies.csv
├── snapshot_pre-upgrade_hpas.csv
├── snapshot_pre-upgrade_pdbs.csv
├── snapshot_pre-upgrade_resourcequotas.csv
├── snapshot_pre-upgrade_secrets.csv            # only if --include-secrets
├── snapshot_pre-upgrade_crds.csv
├── snapshot_pre-upgrade_apiservices.csv
└── snapshot_pre-upgrade_clusteroperators.csv   # OCP only
```

### Step 3 — Run your upgrade

`oc adm upgrade` / EKS console / Ansible AAP job / whatever your usual process is.

### Step 4 — AFTER snapshot

```bash
python3 cluster_upgrade_snapshot_v5.py capture \
    --label post-upgrade \
    --output-dir /tmp/upgrade-2026-05-27
```

(Use the same `--include-secrets` flag as before if you used it for the pre snapshot.)

> **Want Custom Resources (operator CRs) in the diff too?** Add `--include-custom-resources`
> to **both** the pre and post captures. It auto-discovers every CRD and fingerprints each
> CR's declared state (status churn ignored), then the diff shows them in a dedicated
> `[CR] CUSTOM RESOURCES` table. It's opt-in because discovery makes one API call per CRD
> (slower on big OpenShift clusters). The built-in extras — DaemonSet, Job, ServiceAccount,
> LimitRange, Role, ClusterRole, ClusterRoleBinding, IngressClass, PriorityClass — are always
> captured, no flag needed.

> **Want to verify Redis cluster health across the upgrade?** Add `--redis` to **both**
> captures. It finds pods whose name contains `redis` (override with `--redis-name-contains`),
> exec's `redis-cli CLUSTER INFO` + `CLUSTER NODES` inside each (no auth assumed), and records
> `cluster_state`, slots assigned, known nodes, cluster size, master/replica counts, and
> disconnected nodes. The diff shows a `[REDIS] CLUSTER STATUS` table flagging regressions —
> Redis became unreachable, `cluster_state: ok → fail`, slots/size/masters dropped, or nodes
> disconnected. Needs `pods/exec` permission. Example:
>
> ```bash
> # Scope to the namespace your Redis lives in (e.g. pods redis-0, redis-1 in ns 'redis'):
> python3 cluster_upgrade_snapshot_v5.py capture --label pre-upgrade  --output-dir ./chk \
>     --redis --redis-namespace redis
> python3 cluster_upgrade_snapshot_v5.py capture --label post-upgrade --output-dir ./chk \
>     --redis --redis-namespace redis
> python3 cluster_upgrade_snapshot_v5.py diff \
>     --before ./chk/snapshot_pre-upgrade.json --after ./chk/snapshot_post-upgrade.json
> ```
>
> Omit `--redis-namespace` to scan every namespace. `--redis-name-contains` defaults to
> `redis` (matches `redis-0`, `redis-1`, …); change it if your pods are named differently.

### Step 5 — Diff and verdict

```bash
python3 cluster_upgrade_snapshot_v5.py diff \
    --before /tmp/upgrade-2026-05-27/snapshot_pre-upgrade.json \
    --after  /tmp/upgrade-2026-05-27/snapshot_post-upgrade.json
```

You'll see a colored, tabular report organized by layer:

```
╭ LAYER 1 — PLATFORM ╮
[L1] NODES
[L1] PERSISTENT VOLUMES
[L1] STORAGE CLASSES
[L1] CRDs
[L1] API SERVICES
[L1] CLUSTER OPERATORS         (OpenShift only)

╭ LAYER 2 — CONFIGURATION ╮
[L2] NAMESPACES
[L2] CONFIGMAPS
[L2] SERVICES
[L2] INGRESSES
[L2] NETWORK POLICIES
[L2] ROLEBINDINGS
[L2] PVCs
[L2] ROUTES                    (OpenShift only)
[L2] SECRETS (hashed)          (only if --include-secrets)

╭ LAYER 3 — WORKLOADS ╮
[L3] DEPLOYMENTS
[L3] POD STATUS
[L3] STATEFULSETS
[L3] CRONJOBS
[L3] HPAs
[L3] PDBs
[L3] RESOURCE QUOTAS
```

---

## 📤 Export clean YAML manifests (`export`)

Separate from the snapshot/diff flow, the `export` command dumps **clean, re-applyable
YAML manifests** — one file per object — organized by namespace and kind:

```
<output-dir>/
  <namespace>/
    <Kind>/
      <name>.yaml
```

It strips everything the API server / controllers add at runtime, so the output is
suitable for backup, GitOps seeding, or moving objects between clusters:

- the entire `status` block
- runtime `metadata`: `resourceVersion`, `uid`, `generation`, `creationTimestamp`,
  `managedFields`, `ownerReferences`, `selfLink`, `finalizers`, `generateName`
- auto-injected annotations (last-applied-config, rollout revision, PV bind hints, etc.)
- auto-assigned Service `clusterIP` / `nodePort`

```bash
# Every namespace (including kube-* / openshift-*), all supported kinds:
python3 cluster_upgrade_snapshot_v5.py export --output-dir ./cluster-yaml

# A single namespace:
python3 cluster_upgrade_snapshot_v5.py export --output-dir ./my-app-yaml --namespace my-app

# Skip system namespaces:
python3 cluster_upgrade_snapshot_v5.py export --output-dir ./cluster-yaml --exclude-system

# Skip Secrets (by default Secrets ARE exported, with real base64 values):
python3 cluster_upgrade_snapshot_v5.py export --output-dir ./cluster-yaml --no-secrets
```

**Exported namespaced kinds:** ConfigMap, Secret*, Service, Endpoints, PersistentVolumeClaim,
ServiceAccount, ResourceQuota, LimitRange, Deployment, StatefulSet, DaemonSet, CronJob,
Job, Ingress, NetworkPolicy, Role, RoleBinding, HorizontalPodAutoscaler,
PodDisruptionBudget, and Route (OpenShift).

**Custom Resources (default ON):** every namespaced Custom Resource is auto-discovered by
listing the cluster's CRDs and dumping each CR's storage version — so operator-managed
objects (cert-manager `Certificate`, ArgoCD `Application`, Prometheus, vendor CRs, etc.)
are included. Disable with `--no-custom-resources`.

**Cluster-scoped objects (default ON, into `_cluster-scoped/`):** Namespace, ClusterRole,
ClusterRoleBinding, StorageClass, PriorityClass, IngressClass, CustomResourceDefinition,
plus any cluster-scoped Custom Resources. Cluster-managed defaults are skipped
(`system:*` ClusterRoles, the two built-in PriorityClasses). Disable with
`--no-cluster-scoped`. (Automatically skipped when `--namespace` is set, since it targets
one namespace.) Nodes and PersistentVolumes are intentionally excluded — they're
environment-specific and not portable.

```bash
# Full backup: all namespaces, all CRs, plus cluster-scoped objects (the defaults):
python3 cluster_upgrade_snapshot_v5.py export --output-dir ./cluster-yaml

# Just the built-in namespaced kinds (skip CRs + cluster-scoped):
python3 cluster_upgrade_snapshot_v5.py export --output-dir ./cluster-yaml \
    --no-custom-resources --no-cluster-scoped
```

> **Note:** full discovery makes one API list call per CRD (can be 100–300 on OpenShift),
> so a complete export takes longer than the curated-only run. CRD kinds that can't be
> listed (aggregated API down, RBAC denied, conversion webhook unavailable) are counted as
> "unavailable" and skipped, not fatal.

> ⚠️ **Secrets:** unlike the `capture` command (which only stores hashes), `export`
> writes **real base64 secret values** so the manifests are re-applyable. Files are
> written with `0600` permissions — keep the output directory secure. Use `--no-secrets`
> to skip them.

Controller-generated objects are skipped automatically: SA-token / dockercfg / Helm-release
Secrets, the `kube-root-ca.crt` / `openshift-service-ca.crt` ConfigMaps, and Jobs spawned
by CronJobs. Pods and ReplicaSets are not exported (purely runtime).

---

## 📊 Output formats

| Format | Audience | Use case |
|--------|----------|----------|
| `*.json` | Machines | Input to the `diff` command, automation, archival |
| `*.csv` (~22 files) | Humans | Open in Excel/LibreOffice, attach to tickets |
| Terminal output (rich tables) | Humans | Live review during/after upgrade |

CSVs are flattened (nested fields joined to readable strings). For full structure, use the JSON.

---

## 🎯 Exit codes (for CI/CD pipelines)

The `diff` command returns:

- `0` → No critical regressions
- `1` → One or more critical regressions

Wire it into CloudBees CD / Jenkins / Ansible AAP:

```bash
if ! python3 cluster_upgrade_snapshot_v5.py diff --before pre.json --after post.json; then
    echo "Upgrade verification FAILED — initiating rollback"
    ansible-playbook rollback.yml
    exit 1
fi
```

---

## 🔒 What counts as "critical"?

The script marks changes as critical based on **operational blast radius**. Examples:

| Change | Critical? | Reason |
|--------|-----------|--------|
| **Layer 1 — Platform** | | |
| Node went `NotReady` | ✅ | Capacity lost |
| Node `SchedulingDisabled` after upgrade | ✅ | Failed uncordon |
| PV phase: `Bound` → `Released` | ✅ | Lost binding |
| StorageClass default flag flipped | ✅ | New PVCs will fail |
| CRD version removed | ✅ | Existing objects die |
| APIService `Available: True → False` | ✅ | Aggregated API dead |
| ClusterOperator `Degraded: True` | ✅ | Control plane component broken |
| **Layer 2 — Configuration** | | |
| Namespace removed | ✅ | Workloads gone |
| ConfigMap data hash changed | ✅ | Config drift |
| Secret data hash changed | ✅ | Cred/cert rotated |
| Service clusterIP changed | ✅ | Cached IPs break |
| Ingress hosts changed | ✅ | External traffic broken |
| RoleBinding subjects changed | ✅ | Permissions drift |
| PVC phase: `Bound` → `Pending` | ✅ | App data inaccessible |
| **Layer 3 — Workloads** | | |
| Deployment replica mismatch | ✅ | App degraded |
| Pod regression (new CrashLoopBackOff) | ✅ | Workload failure |
| HPA min/max range changed | ✅ | Scaling broken |
| PDB breached (current < desired) | ✅ | Drains will fail |
| Image changed | ❌ | Often expected (rolling deploy) |
| Versions added to CRD | ❌ | Backward compatible |
| New keys added to ConfigMap | ❌ | Backward compatible |

The exit code only counts critical changes.

---

## 🚫 What's intentionally NOT captured

- **Secret raw values** — only hashes, even with `--include-secrets`
- **MutatingWebhookConfigurations** — could add in future
- **Nodes / PersistentVolumes in `export`** — environment-specific, not portable
- **System namespaces** (`kube-*`, `openshift-*`) — filtered for noise
- **`system:*` ClusterRoles / built-in PriorityClasses** — cluster-managed, filtered as noise
- **Jobs spawned by CronJobs** — ephemeral, filtered as noise

> Note: ClusterRoles, ClusterRoleBindings, and individual operator Custom Resources
> (e.g. `Application`, `Certificate`) **are** now captured/diffed — ClusterRole(Binding)s
> always, CRs via `--include-custom-resources`.

---

## 🧠 Architecture

```
   ┌─────────────────┐
   │  K8s API Server │  (EKS or OpenShift)
   └────────┬────────┘
            │  (one paginated fetch per resource type)
            ▼
   ┌─────────────────┐
   │ Python objects  │  (in memory — single dict)
   │ snap = {...}    │
   └────────┬────────┘
            │
   ┌────────┼─────────────────────────┐
   ▼        ▼                         ▼
 ┌────┐ ┌─────────────┐         ┌────────────┐
 │JSON│ │ ~22 CSVs    │         │ Rich Table │
 │file│ │ (per type)  │         │  (stdout)  │
 └────┘ └─────────────┘         └────────────┘
```

- **One capture phase** → fetches every resource once into an in-memory dict
- **Multiple writers** → projects the same dict into JSON, ~22 CSVs, and a rich summary table
- **Diff is pure data** → operates on saved JSON files only, doesn't re-touch the cluster

---

## 🔐 Minimum RBAC

You need read access on 22 resource types. Example ClusterRole:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-snapshot-reader
rules:
- apiGroups: [""]
  resources: ["namespaces", "nodes", "pods", "configmaps", "services", "endpoints",
              "persistentvolumes", "persistentvolumeclaims", "resourcequotas",
              "serviceaccounts", "limitranges"]
  verbs: ["list", "get"]
- apiGroups: [""]
  resources: ["secrets"]                # only if --include-secrets
  verbs: ["list", "get"]
- apiGroups: [""]
  resources: ["pods/exec"]              # only if --redis
  verbs: ["create", "get"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets", "statefulsets", "daemonsets"]
  verbs: ["list", "get"]
- apiGroups: ["batch"]
  resources: ["cronjobs", "jobs"]
  verbs: ["list", "get"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
  verbs: ["list", "get"]
- apiGroups: ["storage.k8s.io"]
  resources: ["storageclasses"]
  verbs: ["list", "get"]
- apiGroups: ["scheduling.k8s.io"]
  resources: ["priorityclasses"]
  verbs: ["list", "get"]
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses", "networkpolicies", "ingressclasses"]
  verbs: ["list", "get"]
- apiGroups: ["autoscaling"]
  resources: ["horizontalpodautoscalers"]
  verbs: ["list", "get"]
- apiGroups: ["policy"]
  resources: ["poddisruptionbudgets"]
  verbs: ["list", "get"]
- apiGroups: ["apiextensions.k8s.io"]
  resources: ["customresourcedefinitions"]
  verbs: ["list", "get"]
- apiGroups: ["apiregistration.k8s.io"]
  resources: ["apiservices"]
  verbs: ["list", "get"]
- apiGroups: ["route.openshift.io"]       # OpenShift only
  resources: ["routes"]
  verbs: ["list", "get"]
- apiGroups: ["config.openshift.io"]      # OpenShift only
  resources: ["clusteroperators"]
  verbs: ["list", "get"]
- apiGroups: ["apiextensions.k8s.io"]
  resources: ["customresourcedefinitions"]
  verbs: ["list", "get"]
# For --include-custom-resources (capture) and the `export` command, you also need
# read access to the actual CR types you want covered. The simplest grant is a broad
# read-only role (e.g. OpenShift's built-in `cluster-reader`, or `view` per namespace).
# Any CR type the account can't list is reported as "unavailable" and skipped, not fatal.
```

---

## ❓ FAQ

**Q: How long does a snapshot take?**
A: ~15-30 seconds on a 50-namespace cluster; ~45-90 seconds on a 500-namespace cluster.

**Q: Why hash Secrets instead of storing them?**
A: Compliance + leak prevention. A hash tells you "did it change?" without exposing the secret material.

**Q: Why is `--include-secrets` opt-in?**
A: Even storing key names of secrets reveals structural info. Make it an explicit, audited choice.

**Q: Does it work on EKS Fargate / Outposts / OCP HCP?**
A: Yes — anything that exposes a standard Kubernetes API.

**Q: How big are the snapshot files?**
A: Typical: 500 KB - 10 MB JSON. CSVs total similar size. Safe for git or S3.

**Q: Can I run this from inside a pod?**
A: Yes. Mount a ServiceAccount with the RBAC above and `load_incluster_config()` is auto-detected.

**Q: Why three architectural layers?**
A: Upgrades break differently at each layer. Layer 1 (platform) breaks cluster-wide; Layer 2 (config) breaks per-app; Layer 3 (workloads) is the visible symptom. Diagnosing in order means you find the root cause faster.

---

## 🛣️ Roadmap

- [ ] `--namespace` filter for large clusters
- [ ] `--ignore-managed` to silence operator-driven noise (cert-manager, etc.)
- [ ] Markdown report exporter
- [ ] Slack webhook integration
- [ ] ClusterRoleBinding support
- [ ] MutatingWebhookConfiguration tracking
- [ ] Individual CR tracking (not just CRD definitions)
- [ ] Split into multi-file Python package (modules per layer)

---

## 📜 License

MIT — use it, fork it, ship it.

---

## 🙋 Author / Contact

Built for platform engineering.
For issues, feedback, or feature requests: open an issue in this repo or ping `#platform-engineering`.

---

## 📝 Tasks Performed (Changelog)

A running log of changes made via Claude Code. Newest entries on top.

### 2026-05-29
- **Added `--redis-namespace` to scope the Redis check** — limits the Redis pod search to a single namespace (e.g. `--redis-namespace redis` for pods `redis-0`, `redis-1` in the `redis` namespace), so name-substring matching doesn't pick up `redis-*` pods (exporters, sidecars, app clients) elsewhere. Omit it to scan all namespaces. Stored in snapshot metadata.
- **Added Redis cluster health check across upgrades (`--redis`)** — `capture --redis` finds pods whose name contains `redis` (override via `--redis-name-contains`), exec's `redis-cli CLUSTER INFO` + `CLUSTER NODES` inside each (no auth), and records `cluster_state`, slots assigned/ok, known nodes, cluster size, master/replica counts, connected/disconnected nodes, and this pod's role. The diff renders a `[REDIS] CLUSTER STATUS` table that flags regressions as critical: Redis unreachable after upgrade, `cluster_state: ok → fail`, fewer slots assigned, smaller cluster size, lost masters, or newly disconnected nodes (a master→replica role change is shown as a non-critical failover note). Opt-in and must be set on both pre/post captures (same pattern as `--include-secrets`); needs `pods/exec` RBAC. Implemented via the kubernetes `stream` exec API with a 15s per-call timeout; pods not in `Running` phase are recorded as unreachable. Identification is by pod-name substring per the requested design.
- **Expanded `capture`/`diff` coverage with 9 more kinds + Custom Resources** — previously `capture`/`diff` only covered 22 categories (some kinds were export-only). Added to the before/after diff: **DaemonSet, Job, ServiceAccount, LimitRange, Role** (namespaced) and **ClusterRole, ClusterRoleBinding, IngressClass, PriorityClass** (cluster-scoped) — all with NEW / MISSING / field-drift detection and noise-stripped `spec_hash` gating. Each got an extractor + comparator (e.g. DaemonSet flags `NOT FULLY SCHEDULED`, PriorityClass flags `value`/`globalDefault` changes, ServiceAccount tracks `imagePullSecrets`/`automount` but ignores auto-generated token secrets). Jobs spawned by CronJobs and `system:*`/built-in cluster objects are filtered as noise. **Custom Resources** are now also diffable via `capture --include-custom-resources` (auto-discovers CRDs, hashes each CR's declared state, skips status churn) — shown in a dedicated `[CR] CUSTOM RESOURCES` table; both pre and post captures must use the flag (same pattern as `--include-secrets`). New `diff_custom_resources_table`; `diff_snapshots` reads new keys defensively with `.get()` so it still compares older snapshots.
- **Diff "Name" column now names the resource kind** — each diff table's Name column header reads the actual Kind (e.g. `Deployment Name`, `ConfigMap Name`, `Service Name`) instead of a generic `Name`, so it's clear what the listed names are. Driven by a `SECTION_KIND` title→kind map; unknown sections fall back to `Name`.
- **`diff` now hides unchanged resource categories by default** — previously the report printed a "No changes" table for every one of the 22 categories, burying the actual findings. The three table builders (`diff_ns_scoped_table`, `diff_cluster_scoped_table`, `diff_pods_table`) now also return a findings count, and `diff_snapshots` only prints tables (and their layer header) when there's at least one change. If nothing changed anywhere, it prints a single `✓ No changes detected` line. Use `--show-unchanged` to restore the full all-categories output. The PASS/FAIL verdict and exit code are unaffected.
- **Corrected stale filename/version references in README** — the Quick-start (`capture`/`diff`) examples and the CI/CD snippet still referenced the legacy `cluster_upgrade_snapshot.py`; updated all of them to the actual `cluster_upgrade_snapshot_v5.py`. Also bumped the title from `(v4)` to `(v5)` to match `__version__ = 5.0.0`.
- **Export now covers Custom Resources + cluster-scoped objects (near-full backup)** — the `export` command was extended beyond the 18 curated namespaced kinds. It now (a) auto-discovers every Custom Resource by listing the cluster's CRDs and dumping each CR's storage version across all namespaces (operator-managed objects: cert-manager, ArgoCD, Prometheus, vendor CRs, etc.), and (b) exports cluster-scoped objects — Namespace, ClusterRole, ClusterRoleBinding, StorageClass, PriorityClass, IngressClass, CustomResourceDefinition, and cluster-scoped CRs — into a top-level `_cluster-scoped/` folder. Both are ON by default; opt out with `--no-custom-resources` / `--no-cluster-scoped` (the latter is auto-skipped when `--namespace` targets a single namespace). Cluster-managed defaults (`system:*` ClusterRoles, built-in PriorityClasses) are filtered out; Nodes/PVs are intentionally excluded as environment-specific. CRD kinds that can't be listed (aggregated API down, RBAC, conversion webhook) are counted as "unavailable" and skipped rather than aborting. Needs broader read RBAC than the curated export.
- **Suppressed repeated `InsecureRequestWarning` spam** — when the kubeconfig sets `insecure-skip-tls-verify` (common on internal OCP clusters with self-signed certs), urllib3 printed a multi-line warning on *every* API call, flooding the output. `load_kube_config()` now disables that one warning — but only when TLS verification is actually off — and prints a single grey notice instead, so the security trade-off stays visible. Verification-enabled clusters are unaffected.
- **Fixed Python 3.6 compatibility (`TypeError: __init__() got an unexpected keyword argument 'required'`)** — `argparse.add_subparsers()` only accepts `required=` on Python 3.7+, but RHEL/OCP nodes commonly ship Python 3.6.8. Now sets `sub.required = True` via the attribute instead of the constructor kwarg, so the script runs on 3.6 as well. (The `required=True` args on individual `add_argument()` calls are fine on all versions.)
- **Strip server-applied defaults from exported manifests** — the `export` cleaner now drops API-server-defaulted pod-spec fields (`dnsPolicy: ClusterFirst`, `restartPolicy: Always`, `schedulerName: default-scheduler`, `terminationGracePeriodSeconds: 30`), per-container defaults (`terminationMessagePath: /dev/termination-log`, `terminationMessagePolicy: File`, empty `resources: {}`/`securityContext: {}`), and the deprecated `serviceAccount` alias. Fields are removed ONLY when the value still equals the documented default — a customized value (e.g. `terminationGracePeriodSeconds: 60`) is preserved. `serviceAccountName`, non-empty `securityContext`, and `imagePullSecrets` are kept; `imagePullPolicy` is deliberately NOT stripped (its default is tag-dependent).
- **Stripped runtime annotations from nested pod/job templates** — `restartedAt` markers (from `kubectl/oc rollout restart`) live in `spec.template.metadata.annotations`, which the export cleaner previously left untouched (it only scrubbed top-level `metadata`). The export cleaner is now recursive: it walks every nested `ObjectMeta` block (pod template, CronJob jobTemplate, etc.) and strips runtime fields + auto-managed annotations, while leaving labels intact so selectors stay valid. Also added a `/restartedAt` annotation-suffix rule to `hash_helper.clean_annotations` so it catches `openshift.openshift.io/restartedAt` (and any vendor's restart marker), not just the `kubectl.kubernetes.io/` one — this benefits the `capture`/`diff` hashing too. Note: chart-author annotations like `rollme` are kept (not Kubernetes-generated).
- **Added `.gitignore`** — ignores snapshot output (`snapshot_*` and `snapshot-*`) so capture artifacts don't get committed, plus Python build artifacts (`__pycache__/`, `*.pyc`).
- **Added `export` subcommand** — dumps clean, re-applyable YAML manifests, one file per object, foldered as `<output-dir>/<namespace>/<Kind>/<name>.yaml`. Covers all namespaces by default (including `kube-*`/`openshift-*`) across ~20 namespaced kinds plus OpenShift Routes. Strips `status` and all runtime-managed fields (`resourceVersion`, `uid`, `managedFields`, `ownerReferences`, auto-injected annotations, Service `clusterIP`/`nodePort`). Flags: `--namespace`, `--exclude-system`, `--no-secrets`. Secrets are exported with real values by default (files written `0600`); controller-generated objects (SA-token/dockercfg/Helm secrets, root-CA ConfigMaps, CronJob-spawned Jobs) are skipped. Added `pyyaml` to `requirements.txt`.
- **Fixed `UnicodeEncodeError` on Windows** — `write_secure()` now opens output files with `encoding="utf-8"`. On Windows, Python defaulted to the cp1252 codec, which crashed when cluster data contained characters like a zero-width space (`​`) — seen while writing the RoleBindings CSV. Also made the `diff` command read JSON snapshots as UTF-8 for cross-platform consistency.

### 2026-05-27
- **Added `requirements.txt`** — pins the two third-party Python dependencies (`kubernetes>=28.1.0`, `rich>=13.0.0`) so the project can be installed with `pip install -r requirements.txt`. `hash_helper.py` is a local module and is not listed.
- **Updated installation instructions** — README now points to `pip3 install -r requirements.txt` and references the actual script filename (`cluster_upgrade_snapshot_v5.py`) instead of the legacy name.
- **Added this "Tasks Performed" section** — going forward, every change made through Claude Code will be logged here so the history stays understandable.
