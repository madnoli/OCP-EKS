# 🚀 cluster-upgrade-snapshot  (v4)

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
python3 cluster_upgrade_snapshot.py capture \
    --label pre-upgrade \
    --output-dir /tmp/upgrade-2026-05-27
```

Add `--include-secrets` if your security policy allows hash-based secret tracking:

```bash
python3 cluster_upgrade_snapshot.py capture \
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
python3 cluster_upgrade_snapshot.py capture \
    --label post-upgrade \
    --output-dir /tmp/upgrade-2026-05-27
```

(Use the same `--include-secrets` flag as before if you used it for the pre snapshot.)

### Step 5 — Diff and verdict

```bash
python3 cluster_upgrade_snapshot.py diff \
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
if ! python3 cluster_upgrade_snapshot.py diff --before pre.json --after post.json; then
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
- **ClusterRoleBindings** — namespace-scoped RoleBindings only (cluster-wide RBAC out of scope)
- **MutatingWebhookConfigurations** — could add in future
- **Specific operator CRs** — we list CRDs but not individual objects (e.g., we see `ArgoCD` CRD exists but not specific `Application` objects)
- **System namespaces** (`kube-*`, `openshift-*`) — filtered for noise

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
  resources: ["namespaces", "nodes", "pods", "configmaps", "services",
              "persistentvolumes", "persistentvolumeclaims", "resourcequotas"]
  verbs: ["list", "get"]
- apiGroups: [""]
  resources: ["secrets"]                # only if --include-secrets
  verbs: ["list", "get"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets", "statefulsets"]
  verbs: ["list", "get"]
- apiGroups: ["batch"]
  resources: ["cronjobs"]
  verbs: ["list", "get"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["rolebindings"]
  verbs: ["list", "get"]
- apiGroups: ["storage.k8s.io"]
  resources: ["storageclasses"]
  verbs: ["list", "get"]
- apiGroups: ["networking.k8s.io"]
  resources: ["ingresses", "networkpolicies"]
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

### 2026-05-27
- **Added `requirements.txt`** — pins the two third-party Python dependencies (`kubernetes>=28.1.0`, `rich>=13.0.0`) so the project can be installed with `pip install -r requirements.txt`. `hash_helper.py` is a local module and is not listed.
- **Updated installation instructions** — README now points to `pip3 install -r requirements.txt` and references the actual script filename (`cluster_upgrade_snapshot_v5.py`) instead of the legacy name.
- **Added this "Tasks Performed" section** — going forward, every change made through Claude Code will be logged here so the history stays understandable.
