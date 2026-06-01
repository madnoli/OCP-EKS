#!/usr/bin/env python3
"""
cluster_upgrade_snapshot.py  (v5)
==================================
Capture and diff Kubernetes / OpenShift cluster state across upgrades.

WHAT'S NEW IN v5 (vs v4):
  • Correct drift detection via hash_helper.py
        — strips resourceVersion, managedFields, deprecated labels,
          auto-injected annotations BEFORE hashing
        — eliminates ~100% of false-positive drift alerts
  • Pre-flight connectivity + RBAC check (fail fast, not halfway through)
  • Request timeouts on every API call (won't hang forever)
  • Output files written with 0600 permissions (snapshot data is sensitive)
  • --version flag for CLI hygiene
  • ResourceQuota cleanly separates spec (hard) from status (used)

Tracked resources (22 categories across 3 layers):

  LAYER 1 — Platform (cluster-scoped):
    Nodes, PersistentVolumes, StorageClasses,
    CustomResourceDefinitions, APIServices,
    ClusterOperators (OpenShift only)

  LAYER 2 — Configuration (mostly namespace-scoped):
    ConfigMaps, Secrets (opt-in), Services, Routes (OCP),
    Ingresses, NetworkPolicies, RoleBindings, PVCs

  LAYER 3 — Workloads (namespace-scoped):
    Namespaces, Deployments, Pods, StatefulSets, CronJobs,
    HorizontalPodAutoscalers, PodDisruptionBudgets, ResourceQuotas

Outputs per snapshot:
  - <prefix>.json                  (full nested data, file mode 0600)
  - <prefix>_<resource>.csv        (one per resource, file mode 0600)

Requires:  pip install kubernetes rich
           AND hash_helper.py in same directory or on PYTHONPATH
"""

__version__ = "5.0.0"

import argparse
import csv
import json
import os
import socket
import stat
import sys
from collections import defaultdict
from datetime import datetime, timezone

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
except ImportError:
    sys.stderr.write("ERROR: 'kubernetes' library not installed.  pip install kubernetes\n")
    sys.exit(2)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import box
except ImportError:
    sys.stderr.write("ERROR: 'rich' library not installed.  pip install rich\n")
    sys.exit(2)

try:
    import yaml
except ImportError:
    sys.stderr.write("ERROR: 'PyYAML' not installed.  pip install pyyaml\n")
    sys.exit(2)

# NEW in v5: import the hash helper. Must be in same directory or PYTHONPATH.
try:
    from hash_helper import (
        stable_hash,
        declared_state_hash,
        spec_hash,
        clean_labels,
        clean_annotations,
    )
except ImportError:
    sys.stderr.write(
        "ERROR: hash_helper.py not found. Place it next to this script.\n"
    )
    sys.exit(2)


console = Console()

# Default timeout for every API call — protects against hung connections.
API_TIMEOUT_SECONDS = 60

HEALTHY_STATUSES = {"Running", "Completed", "Succeeded"}

SYSTEM_NAMESPACE_PREFIXES = ("kube-", "openshift-")
SYSTEM_NAMESPACES_EXACT   = {"kube-system", "kube-public", "kube-node-lease",
                             "default", "openshift", "openshift-infra"}
SYSTEM_RB_PREFIXES        = ("system:", "builder", "deployer")


def is_system_namespace(ns_name):
    return ns_name in SYSTEM_NAMESPACES_EXACT or \
           any(ns_name.startswith(p) for p in SYSTEM_NAMESPACE_PREFIXES)


def is_system_rolebinding(name):
    return any(name.startswith(p) for p in SYSTEM_RB_PREFIXES)


# ─────────────────────────────────────────────────────────────────────────────
# Cluster connection
# ─────────────────────────────────────────────────────────────────────────────
def load_kube_config():
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()


def preflight_check(core_v1):
    """
    NEW in v5: verify connectivity + minimum permissions BEFORE we start.
    Fails loud and early instead of crashing 30 seconds into capture.
    """
    console.print("[grey50]Running pre-flight check...[/]")
    try:
        # Test 1: API server is reachable
        v = client.VersionApi().get_code(_request_timeout=10)
        console.print(f"  [green]✓[/] API reachable (server v{v.git_version})")
    except (ApiException, socket.timeout, OSError) as e:
        console.print(f"  [red]✗ Cannot reach API server:[/] {e}")
        sys.exit(3)

    try:
        # Test 2: Can we list namespaces? (proves auth + minimal RBAC)
        core_v1.list_namespace(limit=1, _request_timeout=10)
        console.print("  [green]✓[/] Authenticated, can list namespaces")
    except ApiException as e:
        if e.status == 401:
            console.print("  [red]✗ Auth failed (401).[/] Refresh your token.")
        elif e.status == 403:
            console.print("  [red]✗ RBAC denied (403).[/] Need at least 'list namespaces'.")
        else:
            console.print(f"  [red]✗ API error:[/] {e.reason}")
        sys.exit(3)


def detect_cluster_type(core_v1):
    try:
        for ns in core_v1.list_namespace(_request_timeout=API_TIMEOUT_SECONDS).items:
            if ns.metadata.name.startswith("openshift-"):
                return "openshift"
        return "kubernetes"
    except ApiException:
        return "unknown"


def get_cluster_version():
    try:
        v = client.VersionApi().get_code(_request_timeout=10)
        return f"{v.major}.{v.minor.replace('+', '')}"
    except Exception:
        return "unknown"


def write_secure(path, content_writer):
    """
    NEW in v5: write a file with 0600 permissions (owner-only read/write).
    Snapshot data contains namespace names, image refs, sometimes secret hashes —
    not for /tmp world-readable.
    """
    with open(path, "w", newline="", encoding="utf-8") as f:
        content_writer(f)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)   # 0600


# ─────────────────────────────────────────────────────────────────────────────
# Pod status (kubectl-style)
# ─────────────────────────────────────────────────────────────────────────────
def compute_pod_status(pod):
    if pod.metadata.deletion_timestamp is not None:
        return "Terminating"
    init_statuses = pod.status.init_container_statuses or []
    for idx, ic in enumerate(init_statuses):
        if ic.state.terminated:
            if ic.state.terminated.exit_code == 0:
                continue
            reason = ic.state.terminated.reason or f"ExitCode:{ic.state.terminated.exit_code}"
            return f"Init:{reason}"
        if ic.state.waiting and ic.state.waiting.reason:
            return f"Init:{ic.state.waiting.reason}"
        if ic.state.running:
            return f"Init:{idx}/{len(init_statuses)}"
    for cs in (pod.status.container_statuses or []):
        if cs.state.waiting and cs.state.waiting.reason:
            return cs.state.waiting.reason
        if cs.state.terminated and cs.state.terminated.reason:
            return cs.state.terminated.reason
        if cs.state.terminated:
            if cs.state.terminated.signal:
                return f"Signal:{cs.state.terminated.signal}"
            return f"ExitCode:{cs.state.terminated.exit_code}"
    return pod.status.phase or "Unknown"


def compute_node_status(node):
    ready = "NotReady"
    for cond in (node.status.conditions or []):
        if cond.type == "Ready":
            ready = "Ready" if cond.status == "True" else "NotReady"
            break
    if node.spec.unschedulable:
        ready += ",SchedulingDisabled"
    return ready


# ─────────────────────────────────────────────────────────────────────────────
# Resource extractors — UPGRADED IN v5 to use declared_state_hash
# ─────────────────────────────────────────────────────────────────────────────

def extract_configmap(cm):
    """v5: hash is now noise-free via declared_state_hash."""
    return {
        # spec_hash captures cleaned metadata + cleaned data
        "spec_hash":   declared_state_hash(cm),
        "data_keys":   sorted((cm.data or {}).keys()),
        "binary_keys": sorted((cm.binary_data or {}).keys()),
    }


def extract_rolebinding(rb):
    """v5: hash captures cleaned subjects + roleRef (no resourceVersion noise)."""
    subjects = [{"kind": s.kind, "name": s.name,
                 "namespace": getattr(s, "namespace", None)}
                for s in (rb.subjects or [])]
    role_ref = {"kind": rb.role_ref.kind, "name": rb.role_ref.name} if rb.role_ref else {}
    return {
        "spec_hash": declared_state_hash(rb),
        "subjects":  sorted(subjects, key=lambda x: (x["kind"], x["name"])),
        "role_ref":  role_ref,
    }


def extract_cronjob(cj):
    """v5: schedule + suspend stay as-is (we compare them directly).
    status fields (lastScheduleTime, activeCount) are observation, not config."""
    return {
        "spec_hash":          spec_hash(cj.spec),
        "schedule":           cj.spec.schedule,
        "suspend":            bool(cj.spec.suspend),
        "concurrency_policy": cj.spec.concurrency_policy,
        # Status — informational only, NOT compared by hash
        "last_schedule_time": str(cj.status.last_schedule_time) if cj.status.last_schedule_time else None,
        "active_count":       len(cj.status.active or []),
    }


def extract_statefulset(sts):
    """v5: spec_hash for declared replicas/image/etc.; status compared via numbers."""
    spec_r = sts.spec.replicas if sts.spec.replicas is not None else 0
    ready  = sts.status.ready_replicas or 0
    image  = (sts.spec.template.spec.containers[0].image
              if sts.spec.template.spec.containers else "")
    return {
        "spec_hash":         spec_hash(sts.spec),
        "spec_replicas":     spec_r,
        "ready_replicas":    ready,
        "current_replicas":  sts.status.current_replicas or 0,
        "updated_replicas":  sts.status.updated_replicas or 0,
        "replica_mismatch":  spec_r != ready,
        "service_name":      sts.spec.service_name,
        "image":             image,
    }


def extract_service(svc):
    """v5: type/selector/ports compared structurally. clusterIP compared directly
    since it's both spec (when explicitly set) and observation (when auto-allocated)."""
    ports = [{"name": p.name, "port": p.port,
              "target_port": str(p.target_port) if p.target_port is not None else None,
              "protocol": p.protocol}
             for p in (svc.spec.ports or [])]
    return {
        # spec_hash captures the full declarative spec
        "spec_hash":  spec_hash(svc.spec),
        # Structural fields kept for human-readable diff output
        "type":       svc.spec.type,
        "cluster_ip": svc.spec.cluster_ip,
        "selector":   svc.spec.selector or {},
        "ports":      sorted(ports, key=lambda x: (x["port"] or 0)),
    }


def extract_route(route):
    """OpenShift Route — dict, not typed. spec_hash via helper."""
    spec = route.get("spec", {})
    tls  = spec.get("tls") or {}
    to   = spec.get("to")  or {}
    return {
        "spec_hash":       spec_hash(spec),
        "host":            spec.get("host"),
        "path":            spec.get("path"),
        "target_kind":     to.get("kind"),
        "target_name":     to.get("name"),
        "tls_termination": tls.get("termination"),
        "port":            (spec.get("port") or {}).get("targetPort"),
    }


def extract_pv(pv):
    """PersistentVolume — phase is status (compared with transition rules),
    everything else is spec."""
    sources = []
    spec = pv.spec
    for attr in ("aws_elastic_block_store", "nfs", "csi", "host_path", "gce_persistent_disk",
                 "azure_disk", "azure_file", "iscsi", "rbd"):
        if getattr(spec, attr, None):
            sources.append(attr)
    return {
        "spec_hash":      spec_hash(spec),
        "capacity":       spec.capacity.get("storage") if spec.capacity else None,
        "access_modes":   sorted(spec.access_modes or []),
        "reclaim_policy": spec.persistent_volume_reclaim_policy,
        "storage_class":  spec.storage_class_name,
        "phase":          pv.status.phase,   # STATUS — compared with transition rules
        "claim":          (f"{spec.claim_ref.namespace}/{spec.claim_ref.name}"
                           if spec.claim_ref else None),
        "volume_source":  sources[0] if sources else "unknown",
    }


def extract_pvc(pvc):
    """PVC — phase is status; the rest is spec."""
    return {
        "spec_hash":        spec_hash(pvc.spec),
        "phase":            pvc.status.phase,    # STATUS
        "volume_name":      pvc.spec.volume_name,
        "storage_class":    pvc.spec.storage_class_name,
        "access_modes":     sorted(pvc.spec.access_modes or []),
        "requested":        (pvc.spec.resources.requests.get("storage")
                             if pvc.spec.resources and pvc.spec.resources.requests else None),
        "actual_capacity":  (pvc.status.capacity.get("storage")
                             if pvc.status.capacity else None),
    }


def extract_storageclass(sc):
    """StorageClass — annotations contain the default-class flag, so we
    handle that manually instead of letting clean_annotations strip it."""
    is_default = (sc.metadata.annotations or {}).get(
        "storageclass.kubernetes.io/is-default-class", "false") == "true"
    return {
        # Hash the technical config (provisioner + parameters + binding mode)
        "params_hash":         stable_hash({
            "provisioner":         sc.provisioner,
            "parameters":          sc.parameters,
            "reclaim_policy":      sc.reclaim_policy,
            "volume_binding_mode": sc.volume_binding_mode,
            "allow_volume_expansion": bool(sc.allow_volume_expansion),
        }),
        "provisioner":           sc.provisioner,
        "reclaim_policy":        sc.reclaim_policy,
        "volume_binding_mode":   sc.volume_binding_mode,
        "allow_volume_expansion": bool(sc.allow_volume_expansion),
        "is_default":            is_default,   # tracked separately — high-impact field
    }


def extract_node(node):
    """v5 BIG FIX: only user labels are hashed.
    Auto-managed labels (beta.kubernetes.io/*, eks.amazonaws.com/*, etc.) stripped."""
    cap   = node.status.capacity    or {}
    alloc = node.status.allocatable or {}
    return {
        # Hash USER labels only — auto-managed ones change every K8s minor upgrade
        "user_labels_hash":   stable_hash(clean_labels(node.metadata.labels)),
        "user_annotations_hash": stable_hash(clean_annotations(node.metadata.annotations)),
        "status":             compute_node_status(node),
        "schedulable":        not bool(node.spec.unschedulable),
        "kubelet_version":    node.status.node_info.kubelet_version if node.status.node_info else None,
        "os_image":           node.status.node_info.os_image if node.status.node_info else None,
        "container_runtime":  node.status.node_info.container_runtime_version if node.status.node_info else None,
        "capacity_cpu":       cap.get("cpu"),
        "capacity_memory":    cap.get("memory"),
        "allocatable_cpu":    alloc.get("cpu"),
        "allocatable_memory": alloc.get("memory"),
        "taint_count":        len(node.spec.taints or []),
    }


def extract_ingress(ing):
    rules = []
    for r in (ing.spec.rules or []):
        paths = []
        if r.http:
            for p in (r.http.paths or []):
                paths.append({
                    "path":        p.path,
                    "path_type":   p.path_type,
                    "service":     p.backend.service.name if p.backend.service else None,
                    "port":        (p.backend.service.port.number
                                    if p.backend.service and p.backend.service.port else None),
                })
        rules.append({"host": r.host, "paths": paths})
    tls_hosts = sorted([h for t in (ing.spec.tls or []) for h in (t.hosts or [])])
    return {
        "spec_hash": spec_hash(ing.spec),
        "class":     ing.spec.ingress_class_name,
        "rules":     rules,
        "tls_hosts": tls_hosts,
    }


def extract_networkpolicy(np):
    return {
        "spec_hash":     spec_hash(np.spec),
        "pod_selector": stable_hash(np.spec.pod_selector.match_labels if np.spec.pod_selector else None),
        "policy_types":  sorted(np.spec.policy_types or []),
        "ingress_count": len(np.spec.ingress or []),
        "egress_count":  len(np.spec.egress or []),
    }


def extract_hpa(hpa):
    return {
        "spec_hash":        spec_hash(hpa.spec),
        "min_replicas":     hpa.spec.min_replicas,
        "max_replicas":     hpa.spec.max_replicas,
        "current_replicas": hpa.status.current_replicas,    # STATUS — informational
        "target_ref":       (f"{hpa.spec.scale_target_ref.kind}/{hpa.spec.scale_target_ref.name}"
                             if hpa.spec.scale_target_ref else None),
        "metrics_count":    len(hpa.spec.metrics or []),
    }


def extract_pdb(pdb):
    return {
        "spec_hash":         spec_hash(pdb.spec),
        "min_available":     str(pdb.spec.min_available) if pdb.spec.min_available is not None else None,
        "max_unavailable":   str(pdb.spec.max_unavailable) if pdb.spec.max_unavailable is not None else None,
        "current_healthy":   pdb.status.current_healthy if pdb.status else 0,   # STATUS
        "desired_healthy":   pdb.status.desired_healthy if pdb.status else 0,   # STATUS
    }


def extract_resource_quota(rq):
    """
    v5 IMPORTANT FIX: 'hard' is spec (limits you set), 'used' is status (current consumption).
    Old version hashed both together — caused false positives every time a pod started/stopped.
    Now 'hard' is hashed separately; 'used' is informational only.
    """
    hard = rq.spec.hard or {}
    used = (rq.status.used or {}) if rq.status else {}
    return {
        # Spec hash — only 'hard' (user-declared limits)
        "spec_hash":    stable_hash({str(k): str(v) for k, v in hard.items()}),
        "hard":         {str(k): str(v) for k, v in hard.items()},
        # Status — informational, never compared by hash
        "used":         {str(k): str(v) for k, v in used.items()},
        "scopes":       sorted(rq.spec.scopes or []),
    }


def extract_secret(secret):
    """v5: declared_state_hash also cleans metadata before hashing.
    'data' field is base64-encoded values; we hash key+value to detect rotations."""
    return {
        "spec_hash": declared_state_hash(secret),
        "type":      secret.type,
        "data_keys": sorted((secret.data or {}).keys()),
    }


def extract_crd(crd):
    versions = [{"name": v.name, "served": bool(v.served), "storage": bool(v.storage)}
                for v in (crd.spec.versions or [])]
    return {
        "spec_hash":       spec_hash(crd.spec),
        "group":           crd.spec.group,
        "scope":           crd.spec.scope,
        "kind":            crd.spec.names.kind,
        "plural":          crd.spec.names.plural,
        "versions":        sorted(versions, key=lambda x: x["name"]),
        "storage_version": next((v["name"] for v in versions if v["storage"]), None),
    }


def extract_apiservice(api):
    available = "Unknown"
    for cond in (api.status.conditions or []):
        if cond.type == "Available":
            available = cond.status
            break
    return {
        "spec_hash": spec_hash(api.spec),
        "group":     api.spec.group,
        "version":   api.spec.version,
        "service":   (f"{api.spec.service.namespace}/{api.spec.service.name}"
                      if api.spec.service else "local"),
        "available": available,
    }


def extract_clusteroperator(co):
    spec = co.get("status", {})
    conditions = {c["type"]: c["status"] for c in spec.get("conditions", [])}
    return {
        "available":   conditions.get("Available", "Unknown"),
        "progressing": conditions.get("Progressing", "Unknown"),
        "degraded":    conditions.get("Degraded", "Unknown"),
        "version":     (spec.get("versions", [{}])[0].get("version")
                        if spec.get("versions") else None),
    }


# ─────────────────────────────────────────────────────────────────────────────
# CSV writers
# ─────────────────────────────────────────────────────────────────────────────
def write_csv(path, headers, rows):
    def _writer(f):
        w = csv.writer(f)
        w.writerow(headers)
        w.writerows(rows)
    write_secure(path, _writer)


def export_all_csvs(snap, out_dir, prefix):
    """Flatten the snapshot into per-resource CSVs."""

    # Layer 3: Workloads
    write_csv(os.path.join(out_dir, f"{prefix}_namespaces.csv"),
              ["namespace"], [[n] for n in snap["namespaces"]["list"]])

    rows = []
    for ns, deps in snap["deployments"].items():
        for name, d in deps.items():
            rows.append([ns, name, d["spec_hash"], d["spec_replicas"], d["ready_replicas"],
                         d["available_replicas"], d["updated_replicas"],
                         "YES" if d["replica_mismatch"] else "no", d["image"]])
    write_csv(os.path.join(out_dir, f"{prefix}_deployments.csv"),
              ["namespace", "name", "spec_hash", "spec_replicas", "ready_replicas",
               "available", "updated", "mismatch", "image"], rows)

    rows = []
    for key, pods in snap["pods"].items():
        ns, owner = key.split("/", 1)
        for p in pods:
            rows.append([ns, owner, p["name"], p["status"], p["phase"], p["restarts"], p["node"]])
    write_csv(os.path.join(out_dir, f"{prefix}_pods.csv"),
              ["namespace", "owner", "pod_name", "status", "phase", "restarts", "node"], rows)

    rows = []
    for ns, cms in snap["configmaps"].items():
        for name, cm in cms.items():
            rows.append([ns, name, cm["spec_hash"], ",".join(cm["data_keys"])])
    write_csv(os.path.join(out_dir, f"{prefix}_configmaps.csv"),
              ["namespace", "name", "spec_hash", "keys"], rows)

    rows = []
    for ns, rbs in snap["rolebindings"].items():
        for name, rb in rbs.items():
            subj = "; ".join(f"{s['kind']}/{s['name']}" + (f"@{s['namespace']}" if s.get("namespace") else "")
                             for s in rb["subjects"])
            role = f"{rb['role_ref'].get('kind','')}/{rb['role_ref'].get('name','')}"
            rows.append([ns, name, rb["spec_hash"], subj, role])
    write_csv(os.path.join(out_dir, f"{prefix}_rolebindings.csv"),
              ["namespace", "name", "spec_hash", "subjects", "role_ref"], rows)

    rows = []
    for ns, cjs in snap["cronjobs"].items():
        for name, cj in cjs.items():
            rows.append([ns, name, cj["spec_hash"], cj["schedule"],
                         "YES" if cj["suspend"] else "no",
                         cj["concurrency_policy"],
                         cj["last_schedule_time"] or "never", cj["active_count"]])
    write_csv(os.path.join(out_dir, f"{prefix}_cronjobs.csv"),
              ["namespace", "name", "spec_hash", "schedule", "suspended",
               "concurrency_policy", "last_schedule", "active"], rows)

    rows = []
    for ns, ss in snap["statefulsets"].items():
        for name, s in ss.items():
            rows.append([ns, name, s["spec_hash"], s["spec_replicas"], s["ready_replicas"],
                         s["current_replicas"], s["updated_replicas"],
                         "YES" if s["replica_mismatch"] else "no",
                         s["service_name"], s["image"]])
    write_csv(os.path.join(out_dir, f"{prefix}_statefulsets.csv"),
              ["namespace", "name", "spec_hash", "spec_replicas", "ready_replicas",
               "current", "updated", "mismatch", "service_name", "image"], rows)

    rows = []
    for ns, svcs in snap["services"].items():
        for name, s in svcs.items():
            ports = ", ".join(f"{p['name'] or '-'}:{p['port']}→{p['target_port']}/{p['protocol']}"
                              for p in s["ports"])
            sel = ",".join(f"{k}={v}" for k, v in sorted(s["selector"].items()))
            rows.append([ns, name, s["spec_hash"], s["type"], s["cluster_ip"], sel, ports])
    write_csv(os.path.join(out_dir, f"{prefix}_services.csv"),
              ["namespace", "name", "spec_hash", "type", "cluster_ip", "selector", "ports"], rows)

    if snap.get("routes"):
        rows = []
        for ns, rts in snap["routes"].items():
            for name, r in rts.items():
                rows.append([ns, name, r["spec_hash"], r["host"], r["path"],
                             f"{r['target_kind']}/{r['target_name']}",
                             r["tls_termination"], r["port"]])
        write_csv(os.path.join(out_dir, f"{prefix}_routes.csv"),
                  ["namespace", "name", "spec_hash", "host", "path", "target",
                   "tls_termination", "port"], rows)

    rows = []
    for ns, pvcs in snap["pvcs"].items():
        for name, p in pvcs.items():
            rows.append([ns, name, p["spec_hash"], p["phase"], p["volume_name"],
                         p["storage_class"], ",".join(p["access_modes"]),
                         p["requested"], p["actual_capacity"]])
    write_csv(os.path.join(out_dir, f"{prefix}_pvcs.csv"),
              ["namespace", "name", "spec_hash", "phase", "volume",
               "storage_class", "access_modes", "requested", "actual"], rows)

    rows = []
    for name, pv in snap["pvs"].items():
        rows.append([name, pv["spec_hash"], pv["phase"], pv["capacity"],
                     ",".join(pv["access_modes"]), pv["reclaim_policy"],
                     pv["storage_class"], pv["claim"], pv["volume_source"]])
    write_csv(os.path.join(out_dir, f"{prefix}_pvs.csv"),
              ["name", "spec_hash", "phase", "capacity", "access_modes",
               "reclaim", "storage_class", "bound_to", "backend"], rows)

    rows = []
    for name, sc in snap["storageclasses"].items():
        rows.append([name, sc["params_hash"], sc["provisioner"], sc["reclaim_policy"],
                     sc["volume_binding_mode"],
                     "YES" if sc["allow_volume_expansion"] else "no",
                     "YES" if sc["is_default"] else "no"])
    write_csv(os.path.join(out_dir, f"{prefix}_storageclasses.csv"),
              ["name", "params_hash", "provisioner", "reclaim", "binding_mode",
               "expandable", "is_default"], rows)

    rows = []
    for name, n in snap["nodes"].items():
        rows.append([name, n["user_labels_hash"], n["status"],
                     "YES" if n["schedulable"] else "no",
                     n["kubelet_version"], n["os_image"], n["container_runtime"],
                     n["capacity_cpu"], n["capacity_memory"], n["taint_count"]])
    write_csv(os.path.join(out_dir, f"{prefix}_nodes.csv"),
              ["name", "user_labels_hash", "status", "schedulable", "kubelet",
               "os_image", "runtime", "cpu", "memory", "taints"], rows)

    rows = []
    for ns, ings in snap["ingresses"].items():
        for name, ing in ings.items():
            hosts = ", ".join(r["host"] or "*" for r in ing["rules"])
            rows.append([ns, name, ing["spec_hash"], ing["class"], hosts,
                         ", ".join(ing["tls_hosts"])])
    write_csv(os.path.join(out_dir, f"{prefix}_ingresses.csv"),
              ["namespace", "name", "spec_hash", "ingress_class", "hosts", "tls_hosts"], rows)

    rows = []
    for ns, nps in snap["networkpolicies"].items():
        for name, np in nps.items():
            rows.append([ns, name, np["spec_hash"], ",".join(np["policy_types"]),
                         np["ingress_count"], np["egress_count"]])
    write_csv(os.path.join(out_dir, f"{prefix}_networkpolicies.csv"),
              ["namespace", "name", "spec_hash", "policy_types",
               "ingress_rules", "egress_rules"], rows)

    rows = []
    for ns, hpas in snap["hpas"].items():
        for name, h in hpas.items():
            rows.append([ns, name, h["spec_hash"], h["target_ref"], h["min_replicas"],
                         h["max_replicas"], h["current_replicas"], h["metrics_count"]])
    write_csv(os.path.join(out_dir, f"{prefix}_hpas.csv"),
              ["namespace", "name", "spec_hash", "target", "min", "max", "current", "metrics"], rows)

    rows = []
    for ns, pdbs in snap["pdbs"].items():
        for name, p in pdbs.items():
            rows.append([ns, name, p["spec_hash"], p["min_available"],
                         p["max_unavailable"], p["current_healthy"], p["desired_healthy"]])
    write_csv(os.path.join(out_dir, f"{prefix}_pdbs.csv"),
              ["namespace", "name", "spec_hash", "min_available", "max_unavailable",
               "current_healthy", "desired_healthy"], rows)

    rows = []
    for ns, rqs in snap["resourcequotas"].items():
        for name, rq in rqs.items():
            hard_str = "; ".join(f"{k}={v}" for k, v in sorted(rq["hard"].items()))
            used_str = "; ".join(f"{k}={v}" for k, v in sorted(rq["used"].items()))
            rows.append([ns, name, rq["spec_hash"], hard_str, used_str])
    write_csv(os.path.join(out_dir, f"{prefix}_resourcequotas.csv"),
              ["namespace", "name", "spec_hash", "hard", "used"], rows)

    if snap.get("secrets"):
        rows = []
        for ns, secs in snap["secrets"].items():
            for name, s in secs.items():
                rows.append([ns, name, s["spec_hash"], s["type"], ",".join(s["data_keys"])])
        write_csv(os.path.join(out_dir, f"{prefix}_secrets.csv"),
                  ["namespace", "name", "spec_hash", "type", "keys"], rows)

    rows = []
    for name, crd in snap["crds"].items():
        versions = ", ".join(f"{v['name']}{'*' if v['storage'] else ''}{'' if v['served'] else '(unserved)'}"
                             for v in crd["versions"])
        rows.append([name, crd["spec_hash"], crd["group"], crd["scope"],
                     crd["kind"], versions, crd["storage_version"]])
    write_csv(os.path.join(out_dir, f"{prefix}_crds.csv"),
              ["name", "spec_hash", "group", "scope", "kind", "versions", "storage_version"], rows)

    rows = []
    for name, api in snap["apiservices"].items():
        rows.append([name, api["spec_hash"], api["group"], api["version"],
                     api["service"], api["available"]])
    write_csv(os.path.join(out_dir, f"{prefix}_apiservices.csv"),
              ["name", "spec_hash", "group", "version", "service", "available"], rows)

    if snap.get("clusteroperators"):
        rows = []
        for name, co in snap["clusteroperators"].items():
            rows.append([name, co["available"], co["progressing"], co["degraded"], co["version"]])
        write_csv(os.path.join(out_dir, f"{prefix}_clusteroperators.csv"),
                  ["name", "available", "progressing", "degraded", "version"], rows)


# ─────────────────────────────────────────────────────────────────────────────
# CAPTURE
# ─────────────────────────────────────────────────────────────────────────────
def snapshot_cluster(output_dir, label, include_secrets=False):
    os.makedirs(output_dir, exist_ok=True)
    console.print(Panel.fit(
        f"[bold cyan]Cluster Snapshot v{__version__}[/]  •  label: [yellow]{label}[/]"
        + ("  •  [red]including secrets (hashed)[/]" if include_secrets else ""),
        border_style="cyan",
    ))

    load_kube_config()
    core_v1        = client.CoreV1Api()

    # NEW in v5: pre-flight check
    preflight_check(core_v1)

    apps_v1        = client.AppsV1Api()
    batch_v1       = client.BatchV1Api()
    rbac_v1        = client.RbacAuthorizationV1Api()
    storage_v1     = client.StorageV1Api()
    networking_v1  = client.NetworkingV1Api()
    autoscaling_v2 = client.AutoscalingV2Api()
    policy_v1      = client.PolicyV1Api()
    apiext_v1      = client.ApiextensionsV1Api()
    apireg_v1      = client.ApiregistrationV1Api()
    custom         = client.CustomObjectsApi()

    cluster_type    = detect_cluster_type(core_v1)
    cluster_version = get_cluster_version()
    console.print(f"  Cluster: [bold]{cluster_type}[/]  •  API: [bold]{cluster_version}[/]\n")

    snap = {
        "metadata": {
            "label":           label,
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "cluster_type":    cluster_type,
            "cluster_version": cluster_version,
            "include_secrets": include_secrets,
            "snapshot_tool_version": __version__,
        },
        "namespaces":   {"count": 0, "list": []},
        "deployments":  {}, "pods": {}, "statefulsets": {}, "cronjobs": {},
        "hpas":         {}, "pdbs": {}, "resourcequotas": {},
        "configmaps":   {}, "secrets": {}, "services": {}, "routes": {},
        "ingresses":    {}, "networkpolicies": {}, "rolebindings": {}, "pvcs": {},
        "nodes":        {}, "pvs": {}, "storageclasses": {},
        "crds":         {}, "apiservices": {}, "clusteroperators": {},
    }

    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  console=console, transient=False) as progress:

        # ── Layer 3: Workloads ─────────────────────────────────────────────
        t = progress.add_task("[cyan]Namespaces...", total=None)
        ns_objs = core_v1.list_namespace(_request_timeout=API_TIMEOUT_SECONDS).items
        snap["namespaces"]["count"] = len(ns_objs)
        snap["namespaces"]["list"]  = sorted(n.metadata.name for n in ns_objs)
        progress.update(t, description=f"[green]✓ Namespaces ({len(ns_objs)})", completed=1)

        t = progress.add_task("[cyan]Deployments...", total=None)
        deps = apps_v1.list_deployment_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items
        for d in deps:
            ns = d.metadata.namespace
            snap["deployments"].setdefault(ns, {})
            spec_r = d.spec.replicas if d.spec.replicas is not None else 0
            ready  = d.status.ready_replicas or 0
            snap["deployments"][ns][d.metadata.name] = {
                "spec_hash":          spec_hash(d.spec),     # NEW in v5
                "spec_replicas":      spec_r,
                "ready_replicas":     ready,
                "available_replicas": d.status.available_replicas or 0,
                "updated_replicas":   d.status.updated_replicas or 0,
                "replica_mismatch":   spec_r != ready,
                "image": (d.spec.template.spec.containers[0].image
                          if d.spec.template.spec.containers else ""),
            }
        progress.update(t, description=f"[green]✓ Deployments ({len(deps)})", completed=1)

        t = progress.add_task("[cyan]Pods...", total=None)
        rs_to_deploy = {}
        for rs in apps_v1.list_replica_set_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items:
            for owner in (rs.metadata.owner_references or []):
                if owner.kind == "Deployment":
                    rs_to_deploy[(rs.metadata.namespace, rs.metadata.name)] = owner.name
                    break
        pods = core_v1.list_pod_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items
        for pod in pods:
            ns = pod.metadata.namespace
            owner_kind = owner_name = None
            for o in (pod.metadata.owner_references or []):
                owner_kind, owner_name = o.kind, o.name
                break
            if owner_kind == "ReplicaSet":
                deploy_name = rs_to_deploy.get((ns, owner_name), f"orphan-rs/{owner_name}")
            elif owner_kind:
                deploy_name = f"{owner_kind}/{owner_name}"
            else:
                deploy_name = "_standalone_"
            key = f"{ns}/{deploy_name}"
            snap["pods"].setdefault(key, []).append({
                "name":     pod.metadata.name,
                "phase":    pod.status.phase,
                "status":   compute_pod_status(pod),
                "restarts": sum(cs.restart_count for cs in (pod.status.container_statuses or [])),
                "node":     pod.spec.node_name,
            })
        progress.update(t, description=f"[green]✓ Pods ({len(pods)})", completed=1)

        t = progress.add_task("[cyan]StatefulSets...", total=None)
        sts_count = 0
        for sts in apps_v1.list_stateful_set_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items:
            ns = sts.metadata.namespace
            if is_system_namespace(ns): continue
            snap["statefulsets"].setdefault(ns, {})[sts.metadata.name] = extract_statefulset(sts)
            sts_count += 1
        progress.update(t, description=f"[green]✓ StatefulSets ({sts_count})", completed=1)

        t = progress.add_task("[cyan]CronJobs...", total=None)
        cj_count = 0
        for cj in batch_v1.list_cron_job_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items:
            ns = cj.metadata.namespace
            if is_system_namespace(ns): continue
            snap["cronjobs"].setdefault(ns, {})[cj.metadata.name] = extract_cronjob(cj)
            cj_count += 1
        progress.update(t, description=f"[green]✓ CronJobs ({cj_count})", completed=1)

        t = progress.add_task("[cyan]HPAs...", total=None)
        hpa_count = 0
        try:
            for hpa in autoscaling_v2.list_horizontal_pod_autoscaler_for_all_namespaces(
                    _request_timeout=API_TIMEOUT_SECONDS).items:
                ns = hpa.metadata.namespace
                if is_system_namespace(ns): continue
                snap["hpas"].setdefault(ns, {})[hpa.metadata.name] = extract_hpa(hpa)
                hpa_count += 1
            progress.update(t, description=f"[green]✓ HPAs ({hpa_count})", completed=1)
        except ApiException as e:
            progress.update(t, description=f"[yellow]⚠ HPAs skipped: {e.reason}", completed=1)

        t = progress.add_task("[cyan]PDBs...", total=None)
        pdb_count = 0
        try:
            for pdb in policy_v1.list_pod_disruption_budget_for_all_namespaces(
                    _request_timeout=API_TIMEOUT_SECONDS).items:
                ns = pdb.metadata.namespace
                if is_system_namespace(ns): continue
                snap["pdbs"].setdefault(ns, {})[pdb.metadata.name] = extract_pdb(pdb)
                pdb_count += 1
            progress.update(t, description=f"[green]✓ PDBs ({pdb_count})", completed=1)
        except ApiException as e:
            progress.update(t, description=f"[yellow]⚠ PDBs skipped: {e.reason}", completed=1)

        t = progress.add_task("[cyan]ResourceQuotas...", total=None)
        rq_count = 0
        for rq in core_v1.list_resource_quota_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items:
            ns = rq.metadata.namespace
            if is_system_namespace(ns): continue
            snap["resourcequotas"].setdefault(ns, {})[rq.metadata.name] = extract_resource_quota(rq)
            rq_count += 1
        progress.update(t, description=f"[green]✓ ResourceQuotas ({rq_count})", completed=1)

        # ── Layer 2: Configuration ─────────────────────────────────────────
        t = progress.add_task("[cyan]ConfigMaps...", total=None)
        cm_count = 0
        for cm in core_v1.list_config_map_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items:
            ns, name = cm.metadata.namespace, cm.metadata.name
            if is_system_namespace(ns): continue
            if name in ("kube-root-ca.crt", "openshift-service-ca.crt"): continue
            snap["configmaps"].setdefault(ns, {})[name] = extract_configmap(cm)
            cm_count += 1
        progress.update(t, description=f"[green]✓ ConfigMaps ({cm_count})", completed=1)

        if include_secrets:
            t = progress.add_task("[red]Secrets (hashed)...", total=None)
            sec_count = 0
            for sec in core_v1.list_secret_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items:
                ns, name = sec.metadata.namespace, sec.metadata.name
                if is_system_namespace(ns): continue
                if sec.type in ("kubernetes.io/service-account-token",
                                "helm.sh/release.v1"):
                    continue
                snap["secrets"].setdefault(ns, {})[name] = extract_secret(sec)
                sec_count += 1
            progress.update(t, description=f"[green]✓ Secrets ({sec_count}, hashed)", completed=1)

        t = progress.add_task("[cyan]Services...", total=None)
        svc_count = 0
        for svc in core_v1.list_service_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items:
            ns, name = svc.metadata.namespace, svc.metadata.name
            if is_system_namespace(ns): continue
            snap["services"].setdefault(ns, {})[name] = extract_service(svc)
            svc_count += 1
        progress.update(t, description=f"[green]✓ Services ({svc_count})", completed=1)

        t = progress.add_task("[cyan]Routes...", total=None)
        route_count = 0
        if cluster_type == "openshift":
            try:
                routes_resp = custom.list_cluster_custom_object(
                    group="route.openshift.io", version="v1", plural="routes",
                    _request_timeout=API_TIMEOUT_SECONDS)
                for route in routes_resp.get("items", []):
                    ns   = route["metadata"]["namespace"]
                    name = route["metadata"]["name"]
                    if is_system_namespace(ns): continue
                    snap["routes"].setdefault(ns, {})[name] = extract_route(route)
                    route_count += 1
                progress.update(t, description=f"[green]✓ Routes ({route_count})", completed=1)
            except ApiException as e:
                progress.update(t, description=f"[yellow]⚠ Routes skipped: {e.reason}", completed=1)
        else:
            progress.update(t, description="[grey50]– Routes skipped (not OpenShift)", completed=1)

        t = progress.add_task("[cyan]Ingresses...", total=None)
        ing_count = 0
        try:
            for ing in networking_v1.list_ingress_for_all_namespaces(
                    _request_timeout=API_TIMEOUT_SECONDS).items:
                ns = ing.metadata.namespace
                if is_system_namespace(ns): continue
                snap["ingresses"].setdefault(ns, {})[ing.metadata.name] = extract_ingress(ing)
                ing_count += 1
            progress.update(t, description=f"[green]✓ Ingresses ({ing_count})", completed=1)
        except ApiException as e:
            progress.update(t, description=f"[yellow]⚠ Ingresses skipped: {e.reason}", completed=1)

        t = progress.add_task("[cyan]NetworkPolicies...", total=None)
        np_count = 0
        try:
            for np in networking_v1.list_network_policy_for_all_namespaces(
                    _request_timeout=API_TIMEOUT_SECONDS).items:
                ns = np.metadata.namespace
                if is_system_namespace(ns): continue
                snap["networkpolicies"].setdefault(ns, {})[np.metadata.name] = extract_networkpolicy(np)
                np_count += 1
            progress.update(t, description=f"[green]✓ NetworkPolicies ({np_count})", completed=1)
        except ApiException as e:
            progress.update(t, description=f"[yellow]⚠ NetPols skipped: {e.reason}", completed=1)

        t = progress.add_task("[cyan]RoleBindings...", total=None)
        rb_count = 0
        for rb in rbac_v1.list_role_binding_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items:
            ns, name = rb.metadata.namespace, rb.metadata.name
            if is_system_namespace(ns) or is_system_rolebinding(name): continue
            snap["rolebindings"].setdefault(ns, {})[name] = extract_rolebinding(rb)
            rb_count += 1
        progress.update(t, description=f"[green]✓ RoleBindings ({rb_count})", completed=1)

        t = progress.add_task("[cyan]PVCs...", total=None)
        pvc_count = 0
        for pvc in core_v1.list_persistent_volume_claim_for_all_namespaces(
                _request_timeout=API_TIMEOUT_SECONDS).items:
            ns = pvc.metadata.namespace
            if is_system_namespace(ns): continue
            snap["pvcs"].setdefault(ns, {})[pvc.metadata.name] = extract_pvc(pvc)
            pvc_count += 1
        progress.update(t, description=f"[green]✓ PVCs ({pvc_count})", completed=1)

        # ── Layer 1: Platform (cluster-scoped) ─────────────────────────────
        t = progress.add_task("[cyan]Nodes...", total=None)
        node_count = 0
        for node in core_v1.list_node(_request_timeout=API_TIMEOUT_SECONDS).items:
            snap["nodes"][node.metadata.name] = extract_node(node)
            node_count += 1
        progress.update(t, description=f"[green]✓ Nodes ({node_count})", completed=1)

        t = progress.add_task("[cyan]PVs...", total=None)
        pv_count = 0
        for pv in core_v1.list_persistent_volume(_request_timeout=API_TIMEOUT_SECONDS).items:
            snap["pvs"][pv.metadata.name] = extract_pv(pv)
            pv_count += 1
        progress.update(t, description=f"[green]✓ PVs ({pv_count})", completed=1)

        t = progress.add_task("[cyan]StorageClasses...", total=None)
        sc_count = 0
        for sc in storage_v1.list_storage_class(_request_timeout=API_TIMEOUT_SECONDS).items:
            snap["storageclasses"][sc.metadata.name] = extract_storageclass(sc)
            sc_count += 1
        progress.update(t, description=f"[green]✓ StorageClasses ({sc_count})", completed=1)

        t = progress.add_task("[cyan]CRDs...", total=None)
        crd_count = 0
        try:
            for crd in apiext_v1.list_custom_resource_definition(
                    _request_timeout=API_TIMEOUT_SECONDS).items:
                snap["crds"][crd.metadata.name] = extract_crd(crd)
                crd_count += 1
            progress.update(t, description=f"[green]✓ CRDs ({crd_count})", completed=1)
        except ApiException as e:
            progress.update(t, description=f"[yellow]⚠ CRDs skipped: {e.reason}", completed=1)

        t = progress.add_task("[cyan]APIServices...", total=None)
        api_count = 0
        try:
            for api in apireg_v1.list_api_service(_request_timeout=API_TIMEOUT_SECONDS).items:
                snap["apiservices"][api.metadata.name] = extract_apiservice(api)
                api_count += 1
            progress.update(t, description=f"[green]✓ APIServices ({api_count})", completed=1)
        except ApiException as e:
            progress.update(t, description=f"[yellow]⚠ APIServices skipped: {e.reason}", completed=1)

        t = progress.add_task("[cyan]ClusterOperators...", total=None)
        co_count = 0
        if cluster_type == "openshift":
            try:
                cos_resp = custom.list_cluster_custom_object(
                    group="config.openshift.io", version="v1", plural="clusteroperators",
                    _request_timeout=API_TIMEOUT_SECONDS)
                for co in cos_resp.get("items", []):
                    snap["clusteroperators"][co["metadata"]["name"]] = extract_clusteroperator(co)
                    co_count += 1
                progress.update(t, description=f"[green]✓ ClusterOperators ({co_count})", completed=1)
            except ApiException as e:
                progress.update(t, description=f"[yellow]⚠ ClusterOps skipped: {e.reason}", completed=1)
        else:
            progress.update(t, description="[grey50]– ClusterOperators skipped (not OpenShift)", completed=1)

    # ── Persist (with secure file permissions)
    prefix = f"snapshot_{label}"
    json_path = os.path.join(output_dir, f"{prefix}.json")

    def _write_json(f):
        json.dump(snap, f, indent=2, default=str, sort_keys=True)
    write_secure(json_path, _write_json)

    export_all_csvs(snap, output_dir, prefix)

    # ── Summary table
    table = Table(title=f"Snapshot Summary  •  {label}",
                  box=box.ROUNDED, header_style="bold magenta")
    table.add_column("Layer", style="dim")
    table.add_column("Resource", style="cyan")
    table.add_column("Count", justify="right", style="bold yellow")
    table.add_row("3 Workload", "Namespaces",   str(snap["namespaces"]["count"]))
    table.add_row("3 Workload", "Deployments",  str(len(deps)))
    table.add_row("3 Workload", "Pods",         str(len(pods)))
    table.add_row("3 Workload", "StatefulSets", str(sts_count))
    table.add_row("3 Workload", "CronJobs",     str(cj_count))
    table.add_row("3 Workload", "HPAs",         str(hpa_count))
    table.add_row("3 Workload", "PDBs",         str(pdb_count))
    table.add_row("3 Workload", "ResourceQuotas", str(rq_count))
    table.add_row("2 Config",   "ConfigMaps",   str(cm_count))
    if include_secrets:
        table.add_row("2 Config", "Secrets",     str(sum(len(v) for v in snap["secrets"].values())))
    table.add_row("2 Config",   "Services",     str(svc_count))
    if cluster_type == "openshift":
        table.add_row("2 Config", "Routes",      str(route_count))
    table.add_row("2 Config",   "Ingresses",    str(ing_count))
    table.add_row("2 Config",   "NetPolicies",  str(np_count))
    table.add_row("2 Config",   "RoleBindings", str(rb_count))
    table.add_row("2 Config",   "PVCs",         str(pvc_count))
    table.add_row("1 Platform", "Nodes",        str(node_count))
    table.add_row("1 Platform", "PVs",          str(pv_count))
    table.add_row("1 Platform", "StorageClasses", str(sc_count))
    table.add_row("1 Platform", "CRDs",         str(crd_count))
    table.add_row("1 Platform", "APIServices",  str(api_count))
    if cluster_type == "openshift":
        table.add_row("1 Platform", "ClusterOps", str(co_count))
    console.print(); console.print(table)

    console.print(f"\n[green]✓ Files written to:[/] [bold]{output_dir}/[/]  [grey50](mode 0600)[/]")


# ─────────────────────────────────────────────────────────────────────────────
# YAML EXPORT — dump clean, re-applyable manifests, one file per object,
# foldered by namespace then Kind:  <output_dir>/<namespace>/<Kind>/<name>.yaml
#
# Strips status + everything the API server / controllers add at runtime:
#   - status (the whole block)
#   - metadata: resourceVersion, uid, generation, creationTimestamp,
#     managedFields, ownerReferences, selfLink, finalizers, generateName, ...
#   - auto-injected annotations (last-applied-config, rollout revision, bind hints)
#   - auto-assigned Service clusterIP / nodePort
# ─────────────────────────────────────────────────────────────────────────────

# Runtime annotation prefixes to strip on top of hash_helper's NOISY_ANNOTATION_PREFIXES.
EXPORT_EXTRA_NOISY_ANNOTATION_PREFIXES = (
    "pv.kubernetes.io/",
    "volume.kubernetes.io/",
    "volume.beta.kubernetes.io/",
)

EXPORT_STRIP_METADATA_FIELDS = (
    "resourceVersion", "uid", "generation", "creationTimestamp",
    "deletionTimestamp", "deletionGracePeriodSeconds", "finalizers",
    "managedFields", "ownerReferences", "selfLink", "generateName",
)

# API-server-defaulted pod-spec fields. Dropped ONLY when the value still equals
# the documented default — a user-customized value (e.g. grace period 60) is kept.
POD_SPEC_DEFAULTS = {
    "dnsPolicy":                     "ClusterFirst",
    "restartPolicy":                 "Always",            # Jobs use OnFailure/Never → untouched
    "schedulerName":                 "default-scheduler",
    "terminationGracePeriodSeconds": 30,
}
# Per-container defaulted fields (same equals-default rule). imagePullPolicy is
# intentionally NOT here: its default is tag-dependent (:latest → Always), so
# dropping it could silently change pull behavior.
CONTAINER_DEFAULTS = {
    "terminationMessagePath":   "/dev/termination-log",
    "terminationMessagePolicy": "File",
}


def _fs_safe(name):
    """K8s names are DNS-1123 safe already; guard against stray chars just in case."""
    return "".join(c if (c.isalnum() or c in "-._") else "_" for c in name)


def _clean_export_annotations(anns):
    """hash_helper.clean_annotations (exact/prefix/suffix) + export-only prefixes."""
    if not isinstance(anns, dict):
        return {}
    anns = clean_annotations(anns)
    return {k: v for k, v in anns.items()
            if not any(k.startswith(p) for p in EXPORT_EXTRA_NOISY_ANNOTATION_PREFIXES)}


def _scrub_metadata(node):
    """
    Recursively strip runtime fields + noisy annotations from EVERY ObjectMeta block
    in a manifest — the top-level metadata AND nested pod/job templates
    (spec.template.metadata, spec.jobTemplate.spec.template.metadata, ...).
    Labels are left intact so selectors stay valid. Mutates in place.
    """
    if isinstance(node, dict):
        meta = node.get("metadata")
        if isinstance(meta, dict):
            for f in EXPORT_STRIP_METADATA_FIELDS:
                meta.pop(f, None)
            if isinstance(meta.get("annotations"), dict):
                cleaned = _clean_export_annotations(meta["annotations"])
                if cleaned:
                    meta["annotations"] = cleaned
                else:
                    meta.pop("annotations", None)
        for v in node.values():
            _scrub_metadata(v)
    elif isinstance(node, list):
        for item in node:
            _scrub_metadata(item)


def _strip_container_defaults(c):
    if not isinstance(c, dict):
        return
    for field, default in CONTAINER_DEFAULTS.items():
        if c.get(field) == default:
            c.pop(field, None)
    for field in ("resources", "securityContext"):     # API renders these as empty {}
        if c.get(field) == {}:
            c.pop(field, None)


def _strip_server_defaults(node):
    """
    Recursively drop API-server-defaulted fields from pod specs and containers so
    manifests are minimal. A field is removed ONLY when it still equals its
    documented default; any user-customized value is preserved. A dict is treated
    as a PodSpec when it has a `containers` list (true only for pod specs).
    """
    if isinstance(node, dict):
        if isinstance(node.get("containers"), list):
            for field, default in POD_SPEC_DEFAULTS.items():
                if node.get(field) == default:
                    node.pop(field, None)
            node.pop("serviceAccount", None)            # deprecated alias of serviceAccountName
            if node.get("securityContext") == {}:
                node.pop("securityContext", None)
            for group in ("containers", "initContainers", "ephemeralContainers"):
                for c in (node.get(group) or []):
                    _strip_container_defaults(c)
        for v in node.values():
            _strip_server_defaults(v)
    elif isinstance(node, list):
        for item in node:
            _strip_server_defaults(item)


def clean_object_for_export(obj):
    """
    obj: a camelCase dict (from ApiClient.sanitize_for_serialization, or a raw
    custom-object dict). Strips status + runtime fields (at every nesting level)
    and server-applied defaults, returning an ordered dict (apiVersion, kind,
    metadata, ...) ready to write as a manifest.
    """
    obj.pop("status", None)
    _scrub_metadata(obj)        # top-level + nested pod/job templates
    _strip_server_defaults(obj) # API-defaulted pod-spec / container fields

    # Service: clusterIP / nodePort are assigned at runtime when not user-specified.
    if obj.get("kind") == "Service" and isinstance(obj.get("spec"), dict):
        spec = obj["spec"]
        spec.pop("clusterIP", None)
        spec.pop("clusterIPs", None)
        for port in (spec.get("ports") or []):
            if isinstance(port, dict):
                port.pop("nodePort", None)

    ordered = {}
    for k in ("apiVersion", "kind", "metadata"):
        if k in obj:
            ordered[k] = obj[k]
    for k, v in obj.items():
        if k not in ordered:
            ordered[k] = v
    return ordered


def write_yaml_secure(path, obj_dict):
    """Write one manifest as YAML with 0600 perms (secrets may be present)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    def _writer(f):
        yaml.safe_dump(obj_dict, f, default_flow_style=False,
                       sort_keys=False, width=4096, allow_unicode=True)
    write_secure(path, _writer)


def export_cluster_yaml(output_dir, only_namespace=None,
                        exclude_system=False, include_secrets=True):
    os.makedirs(output_dir, exist_ok=True)
    console.print(Panel.fit(
        f"[bold cyan]Cluster YAML Export v{__version__}[/]"
        + (f"  •  namespace: [yellow]{only_namespace}[/]" if only_namespace
           else "  •  [yellow]all namespaces[/]")
        + ("  •  [grey50]excluding system ns[/]" if exclude_system else "")
        + ("  •  [red]including secret values[/]" if include_secrets else ""),
        border_style="cyan",
    ))

    load_kube_config()
    core_v1 = client.CoreV1Api()
    preflight_check(core_v1)

    apps_v1        = client.AppsV1Api()
    batch_v1       = client.BatchV1Api()
    rbac_v1        = client.RbacAuthorizationV1Api()
    networking_v1  = client.NetworkingV1Api()
    autoscaling_v2 = client.AutoscalingV2Api()
    policy_v1      = client.PolicyV1Api()
    custom         = client.CustomObjectsApi()
    api_client     = client.ApiClient()

    cluster_type = detect_cluster_type(core_v1)
    console.print(f"  Cluster: [bold]{cluster_type}[/]\n")

    if include_secrets:
        console.print("[red]⚠ Secret manifests contain real (base64) values. "
                      "Files are written 0600 — keep the output dir secure.[/]\n")

    # (kind, apiVersion, lister() -> [typed objs], skip(obj) -> bool | None)
    registry = [
        ("ConfigMap", "v1",
         lambda: core_v1.list_config_map_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items,
         lambda o: o.metadata.name in ("kube-root-ca.crt", "openshift-service-ca.crt")),
        ("Service", "v1",
         lambda: core_v1.list_service_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items, None),
        ("Endpoints", "v1",
         lambda: core_v1.list_endpoints_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items, None),
        ("PersistentVolumeClaim", "v1",
         lambda: core_v1.list_persistent_volume_claim_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items, None),
        ("ServiceAccount", "v1",
         lambda: core_v1.list_service_account_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items, None),
        ("ResourceQuota", "v1",
         lambda: core_v1.list_resource_quota_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items, None),
        ("LimitRange", "v1",
         lambda: core_v1.list_limit_range_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items, None),
        ("Deployment", "apps/v1",
         lambda: apps_v1.list_deployment_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items, None),
        ("StatefulSet", "apps/v1",
         lambda: apps_v1.list_stateful_set_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items, None),
        ("DaemonSet", "apps/v1",
         lambda: apps_v1.list_daemon_set_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items, None),
        ("CronJob", "batch/v1",
         lambda: batch_v1.list_cron_job_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items, None),
        ("Job", "batch/v1",
         lambda: batch_v1.list_job_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items,
         lambda o: any(r.kind == "CronJob" for r in (o.metadata.owner_references or []))),
        ("Ingress", "networking.k8s.io/v1",
         lambda: networking_v1.list_ingress_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items, None),
        ("NetworkPolicy", "networking.k8s.io/v1",
         lambda: networking_v1.list_network_policy_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items, None),
        ("Role", "rbac.authorization.k8s.io/v1",
         lambda: rbac_v1.list_role_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items, None),
        ("RoleBinding", "rbac.authorization.k8s.io/v1",
         lambda: rbac_v1.list_role_binding_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items, None),
        ("HorizontalPodAutoscaler", "autoscaling/v2",
         lambda: autoscaling_v2.list_horizontal_pod_autoscaler_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items, None),
        ("PodDisruptionBudget", "policy/v1",
         lambda: policy_v1.list_pod_disruption_budget_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items, None),
    ]

    if include_secrets:
        # Skip controller-generated secrets (SA tokens, dockercfg, Helm release blobs).
        registry.insert(1, (
            "Secret", "v1",
            lambda: core_v1.list_secret_for_all_namespaces(_request_timeout=API_TIMEOUT_SECONDS).items,
            lambda o: o.type in ("kubernetes.io/service-account-token",
                                 "kubernetes.io/dockercfg",
                                 "helm.sh/release.v1"),
        ))

    def want_ns(ns):
        if only_namespace:
            return ns == only_namespace
        if exclude_system and is_system_namespace(ns):
            return False
        return True

    counts          = defaultdict(int)
    namespaces_seen = set()
    total_files     = 0

    with Progress(SpinnerColumn(),
                  TextColumn("[progress.description]{task.description}"),
                  console=console, transient=False) as progress:

        for kind, api_version, lister, skip in registry:
            t = progress.add_task(f"[cyan]{kind}...", total=None)
            try:
                items = lister()
            except ApiException as e:
                progress.update(t, description=f"[yellow]⚠ {kind} skipped: {e.reason}", completed=1)
                continue

            n = 0
            for obj in items:
                ns = obj.metadata.namespace
                if ns is None or not want_ns(ns):
                    continue
                if skip and skip(obj):
                    continue
                d = api_client.sanitize_for_serialization(obj)
                d["apiVersion"] = api_version
                d["kind"]       = kind
                cleaned = clean_object_for_export(d)
                path = os.path.join(output_dir, _fs_safe(ns), kind,
                                    f"{_fs_safe(obj.metadata.name)}.yaml")
                write_yaml_secure(path, cleaned)
                namespaces_seen.add(ns)
                counts[kind] += 1
                n += 1
                total_files += 1
            progress.update(t, description=f"[green]✓ {kind} ({n})", completed=1)

        # OpenShift Routes (custom resource — raw camelCase dicts already)
        t = progress.add_task("[cyan]Route...", total=None)
        if cluster_type == "openshift":
            try:
                resp = custom.list_cluster_custom_object(
                    group="route.openshift.io", version="v1", plural="routes",
                    _request_timeout=API_TIMEOUT_SECONDS)
                n = 0
                for route in resp.get("items", []):
                    ns = route["metadata"]["namespace"]
                    if not want_ns(ns):
                        continue
                    name = route["metadata"]["name"]
                    route["apiVersion"] = "route.openshift.io/v1"
                    route["kind"]       = "Route"
                    cleaned = clean_object_for_export(route)
                    path = os.path.join(output_dir, _fs_safe(ns), "Route", f"{_fs_safe(name)}.yaml")
                    write_yaml_secure(path, cleaned)
                    namespaces_seen.add(ns)
                    counts["Route"] += 1
                    n += 1
                    total_files += 1
                progress.update(t, description=f"[green]✓ Route ({n})", completed=1)
            except ApiException as e:
                progress.update(t, description=f"[yellow]⚠ Route skipped: {e.reason}", completed=1)
        else:
            progress.update(t, description="[grey50]– Route skipped (not OpenShift)", completed=1)

    table = Table(title="YAML Export Summary", box=box.ROUNDED, header_style="bold magenta")
    table.add_column("Kind", style="cyan")
    table.add_column("Files", justify="right", style="bold yellow")
    for kind in sorted(counts):
        table.add_row(kind, str(counts[kind]))
    table.add_row("[bold]TOTAL", f"[bold]{total_files}")
    console.print(); console.print(table)
    console.print(f"\n[green]✓ {total_files} manifests across {len(namespaces_seen)} "
                  f"namespace(s) written to:[/] [bold]{output_dir}/[/]  [grey50](mode 0600)[/]")


# ─────────────────────────────────────────────────────────────────────────────
# DIFF comparators (return list of (msg, is_critical))
# UPGRADED in v5: now use spec_hash as primary signal
# ─────────────────────────────────────────────────────────────────────────────
def cmp_deployment(b, a):
    out = []
    if b["spec_hash"] != a["spec_hash"]:
        # Provide structural context too
        if b["spec_replicas"] != a["spec_replicas"]:
            out.append((f"spec.replicas: {b['spec_replicas']} → {a['spec_replicas']}", True))
        if b["image"] != a["image"]:
            out.append((f"image changed", False))
        if not out:  # spec changed but we don't know what
            out.append(("spec drifted (full diff in JSON)", True))
    if a["replica_mismatch"]:
        out.append((f"REPLICA MISMATCH: spec={a['spec_replicas']} ready={a['ready_replicas']}", True))
    return out


def cmp_configmap(b, a):
    out = []
    if b["spec_hash"] != a["spec_hash"]:
        removed = set(b["data_keys"]) - set(a["data_keys"])
        added   = set(a["data_keys"]) - set(b["data_keys"])
        if removed: out.append((f"keys removed: {sorted(removed)}", True))
        if added:   out.append((f"keys added: {sorted(added)}", False))
        if not removed and not added:
            out.append((f"data values changed (hash: {b['spec_hash']} → {a['spec_hash']})", True))
    return out


def cmp_rolebinding(b, a):
    out = []
    if b["spec_hash"] != a["spec_hash"]:
        if b["subjects"] != a["subjects"]:
            out.append((f"subjects changed (was {len(b['subjects'])}, now {len(a['subjects'])})", True))
        if b["role_ref"] != a["role_ref"]:
            out.append((f"roleRef changed: {b['role_ref']} → {a['role_ref']}", True))
        if not out:
            out.append(("rolebinding drifted", True))
    return out


def cmp_cronjob(b, a):
    out = []
    if b["spec_hash"] != a["spec_hash"]:
        if b["schedule"] != a["schedule"]:
            out.append((f"schedule: '{b['schedule']}' → '{a['schedule']}'", True))
        if b["suspend"] != a["suspend"]:
            out.append((f"suspend flipped: {b['suspend']} → {a['suspend']}", True))
        if not out:
            out.append(("cronjob spec drifted", True))
    return out


def cmp_statefulset(b, a):
    out = []
    if b["spec_hash"] != a["spec_hash"]:
        if b["spec_replicas"] != a["spec_replicas"]:
            out.append((f"spec.replicas: {b['spec_replicas']} → {a['spec_replicas']}", True))
        if b["image"] != a["image"]:
            out.append((f"image changed", False))
        if not out:
            out.append(("statefulset spec drifted", True))
    if a["replica_mismatch"]:
        out.append((f"REPLICA MISMATCH: spec={a['spec_replicas']} ready={a['ready_replicas']}", True))
    return out


def cmp_service(b, a):
    out = []
    if b["spec_hash"] != a["spec_hash"]:
        if b["type"] != a["type"]:
            out.append((f"type: {b['type']} → {a['type']}", True))
        if b["cluster_ip"] != a["cluster_ip"]:
            out.append((f"clusterIP: {b['cluster_ip']} → {a['cluster_ip']}", True))
        if b["selector"] != a["selector"]:
            out.append(("selector changed", True))
        if b["ports"] != a["ports"]:
            out.append(("ports changed", True))
        if not out:
            out.append(("service spec drifted", True))
    return out


def cmp_route(b, a):
    out = []
    if b["spec_hash"] != a["spec_hash"]:
        if b["host"] != a["host"]:
            out.append((f"host: {b['host']} → {a['host']}", True))
        if b["tls_termination"] != a["tls_termination"]:
            out.append((f"TLS: {b['tls_termination']} → {a['tls_termination']}", True))
        if b["target_name"] != a["target_name"]:
            out.append((f"target: {b['target_name']} → {a['target_name']}", True))
        if not out:
            out.append(("route spec drifted", True))
    return out


def cmp_pvc(b, a):
    """v5: spec hash for declared, phase transition for status."""
    out = []
    if b["spec_hash"] != a["spec_hash"]:
        if b["storage_class"] != a["storage_class"]:
            out.append((f"storage class: {b['storage_class']} → {a['storage_class']}", True))
        if b["requested"] != a["requested"]:
            out.append((f"requested: {b['requested']} → {a['requested']}", False))
        if not out:
            out.append(("PVC spec drifted", True))
    # Phase is status — transition rules
    if b["phase"] != a["phase"]:
        critical = (a["phase"] != "Bound")
        out.append((f"phase: {b['phase']} → {a['phase']}", critical))
    if b["volume_name"] != a["volume_name"]:
        out.append((f"bound PV: {b['volume_name']} → {a['volume_name']}", True))
    return out


def cmp_pv(b, a):
    out = []
    if b["spec_hash"] != a["spec_hash"]:
        if b["capacity"] != a["capacity"]:
            out.append((f"capacity: {b['capacity']} → {a['capacity']}", True))
        if b["reclaim_policy"] != a["reclaim_policy"]:
            out.append((f"reclaim: {b['reclaim_policy']} → {a['reclaim_policy']}", True))
        if not out:
            out.append(("PV spec drifted", True))
    if b["phase"] != a["phase"]:
        critical = (a["phase"] not in ("Bound", "Available"))
        out.append((f"phase: {b['phase']} → {a['phase']}", critical))
    if b["claim"] != a["claim"]:
        out.append((f"bound claim: {b['claim']} → {a['claim']}", True))
    return out


def cmp_storageclass(b, a):
    out = []
    if b["is_default"] != a["is_default"]:
        out.append((f"DEFAULT FLAG FLIPPED: {b['is_default']} → {a['is_default']}", True))
    if b["params_hash"] != a["params_hash"]:
        if b["provisioner"] != a["provisioner"]:
            out.append((f"provisioner: {b['provisioner']} → {a['provisioner']}", True))
        if b["volume_binding_mode"] != a["volume_binding_mode"]:
            out.append((f"binding mode: {b['volume_binding_mode']} → {a['volume_binding_mode']}", True))
        if not out:
            out.append(("parameters changed", True))
    return out


def cmp_node(b, a):
    """v5: user_labels_hash only flags real user-label changes, not deprecated K8s labels."""
    out = []
    if b["status"] != a["status"]:
        critical = ("NotReady" in a["status"] or "SchedulingDisabled" in a["status"])
        out.append((f"status: {b['status']} → {a['status']}", critical))
    if b["kubelet_version"] != a["kubelet_version"]:
        out.append((f"kubelet: {b['kubelet_version']} → {a['kubelet_version']}", False))
    if b["allocatable_cpu"] != a["allocatable_cpu"]:
        out.append((f"allocatable CPU: {b['allocatable_cpu']} → {a['allocatable_cpu']}", True))
    if b["allocatable_memory"] != a["allocatable_memory"]:
        out.append((f"allocatable mem: {b['allocatable_memory']} → {a['allocatable_memory']}", True))
    if b["taint_count"] != a["taint_count"]:
        out.append((f"taint count: {b['taint_count']} → {a['taint_count']}", True))
    if b["user_labels_hash"] != a["user_labels_hash"]:
        out.append(("user labels changed", False))
    return out


def cmp_ingress(b, a):
    out = []
    if b["spec_hash"] != a["spec_hash"]:
        b_hosts = sorted({r["host"] for r in b["rules"] if r["host"]})
        a_hosts = sorted({r["host"] for r in a["rules"] if r["host"]})
        if b_hosts != a_hosts:
            out.append((f"hosts changed: {b_hosts} → {a_hosts}", True))
        if b["tls_hosts"] != a["tls_hosts"]:
            out.append((f"TLS hosts changed", True))
        if b["class"] != a["class"]:
            out.append((f"ingress class: {b['class']} → {a['class']}", True))
        if not out:
            out.append(("ingress spec drifted", True))
    return out


def cmp_networkpolicy(b, a):
    out = []
    if b["spec_hash"] != a["spec_hash"]:
        if b["policy_types"] != a["policy_types"]:
            out.append((f"policy types: {b['policy_types']} → {a['policy_types']}", True))
        if b["pod_selector"] != a["pod_selector"]:
            out.append(("pod selector changed", True))
        if b["ingress_count"] != a["ingress_count"] or b["egress_count"] != a["egress_count"]:
            out.append((f"rules: ingress {b['ingress_count']}→{a['ingress_count']}, "
                        f"egress {b['egress_count']}→{a['egress_count']}", True))
        if not out:
            out.append(("NetworkPolicy spec drifted", True))
    return out


def cmp_hpa(b, a):
    out = []
    if b["spec_hash"] != a["spec_hash"]:
        if b["min_replicas"] != a["min_replicas"] or b["max_replicas"] != a["max_replicas"]:
            out.append((f"replica range: {b['min_replicas']}-{b['max_replicas']} "
                        f"→ {a['min_replicas']}-{a['max_replicas']}", True))
        if b["target_ref"] != a["target_ref"]:
            out.append((f"target: {b['target_ref']} → {a['target_ref']}", True))
        if not out:
            out.append(("HPA spec drifted", True))
    return out


def cmp_pdb(b, a):
    out = []
    if b["spec_hash"] != a["spec_hash"]:
        if b["min_available"] != a["min_available"]:
            out.append((f"min_available: {b['min_available']} → {a['min_available']}", True))
        if b["max_unavailable"] != a["max_unavailable"]:
            out.append((f"max_unavailable: {b['max_unavailable']} → {a['max_unavailable']}", True))
        if not out:
            out.append(("PDB spec drifted", True))
    if a["current_healthy"] < a["desired_healthy"]:
        out.append((f"UNHEALTHY: {a['current_healthy']}/{a['desired_healthy']} healthy", True))
    return out


def cmp_resourcequota(b, a):
    """v5 FIX: 'used' is no longer in the hash — only 'hard' is.
    No more false positives from pods coming and going."""
    out = []
    if b["spec_hash"] != a["spec_hash"]:
        out.append(("hard limits changed", True))
    return out


def cmp_secret(b, a):
    out = []
    if b["type"] != a["type"]:
        out.append((f"type: {b['type']} → {a['type']}", True))
    if b["spec_hash"] != a["spec_hash"]:
        removed = set(b["data_keys"]) - set(a["data_keys"])
        added   = set(a["data_keys"]) - set(b["data_keys"])
        if removed: out.append((f"keys removed: {sorted(removed)}", True))
        if added:   out.append((f"keys added: {sorted(added)}", False))
        if not removed and not added:
            out.append(("data values changed (rotation?)", True))
    return out


def cmp_crd(b, a):
    out = []
    b_versions = {v["name"] for v in b["versions"]}
    a_versions = {v["name"] for v in a["versions"]}
    removed = b_versions - a_versions
    added   = a_versions - b_versions
    if removed:
        out.append((f"VERSIONS REMOVED: {sorted(removed)} — existing objects may break!", True))
    if added:
        out.append((f"versions added: {sorted(added)}", False))
    if b["storage_version"] != a["storage_version"]:
        out.append((f"storage version: {b['storage_version']} → {a['storage_version']}", True))
    return out


def cmp_apiservice(b, a):
    out = []
    if b["available"] != a["available"]:
        critical = (a["available"] != "True")
        out.append((f"available: {b['available']} → {a['available']}", critical))
    return out


def cmp_clusteroperator(b, a):
    out = []
    if b["available"] != a["available"]:
        critical = (a["available"] != "True")
        out.append((f"Available: {b['available']} → {a['available']}", critical))
    if b["degraded"] != a["degraded"]:
        critical = (a["degraded"] == "True")
        out.append((f"Degraded: {b['degraded']} → {a['degraded']}", critical))
    if b["progressing"] != a["progressing"]:
        out.append((f"Progressing: {b['progressing']} → {a['progressing']}", False))
    if b["version"] != a["version"]:
        out.append((f"version: {b['version']} → {a['version']}", False))
    return out


# ─────────────────────────────────────────────────────────────────────────────
# DIFF table builders
# ─────────────────────────────────────────────────────────────────────────────
def diff_ns_scoped_table(title, before_section, after_section, common_ns, compare_fn):
    findings = []
    for ns in sorted(common_ns):
        b = before_section.get(ns, {}); a = after_section.get(ns, {})
        for name in sorted(set(b) - set(a)):
            findings.append((ns, name, "MISSING after upgrade", True, "red"))
        for name in sorted(set(a) - set(b)):
            findings.append((ns, name, "NEW after upgrade", False, "green"))
        for name in sorted(set(b) & set(a)):
            for msg, critical in compare_fn(b[name], a[name]):
                findings.append((ns, name, msg, critical, "red" if critical else "yellow"))

    table = Table(title=title, box=box.ROUNDED, header_style="bold magenta",
                  title_style="bold cyan", expand=True)
    table.add_column("", width=2)
    table.add_column("Namespace", style="cyan", no_wrap=True)
    table.add_column("Name", style="bold")
    table.add_column("Change")
    critical_count = 0
    if not findings:
        table.add_row("[green]✓[/]", "—", "—", "[green]No changes[/]")
    else:
        for ns, name, msg, crit, color in findings:
            icon = "[red]✗[/]" if crit else "[yellow]•[/]"
            table.add_row(icon, ns, name, f"[{color}]{msg}[/]")
            if crit: critical_count += 1
    return table, critical_count


def diff_cluster_scoped_table(title, before_section, after_section, compare_fn):
    findings = []
    b_names = set(before_section); a_names = set(after_section)
    for name in sorted(b_names - a_names):
        findings.append((name, "MISSING after upgrade", True, "red"))
    for name in sorted(a_names - b_names):
        findings.append((name, "NEW after upgrade", False, "green"))
    for name in sorted(b_names & a_names):
        for msg, critical in compare_fn(before_section[name], after_section[name]):
            findings.append((name, msg, critical, "red" if critical else "yellow"))

    table = Table(title=title, box=box.ROUNDED, header_style="bold magenta",
                  title_style="bold cyan", expand=True)
    table.add_column("", width=2)
    table.add_column("Name", style="bold cyan")
    table.add_column("Change")
    critical_count = 0
    if not findings:
        table.add_row("[green]✓[/]", "—", "[green]No changes[/]")
    else:
        for name, msg, crit, color in findings:
            icon = "[red]✗[/]" if crit else "[yellow]•[/]"
            table.add_row(icon, name, f"[{color}]{msg}[/]")
            if crit: critical_count += 1
    return table, critical_count


def diff_pods_table(before, after):
    def aggregate(snap):
        result = {}
        for key, pods in snap["pods"].items():
            counts = defaultdict(int)
            for p in pods:
                counts[p["status"]] += 1
            result[key] = dict(counts)
        return result

    b_pods, a_pods = aggregate(before), aggregate(after)
    findings = []
    for key in sorted(set(b_pods) | set(a_pods)):
        b_c, a_c = b_pods.get(key, {}), a_pods.get(key, {})
        if b_c == a_c: continue
        if key in b_pods and key not in a_pods:
            findings.append((key, f"NO PODS (was: {dict(b_c)})", True)); continue
        if a_c.get("Running", 0) < b_c.get("Running", 0):
            findings.append((key,
                f"Running: {b_c.get('Running',0)} → {a_c.get('Running',0)} (DECREASED)", True))
        for status in sorted(set(a_c) - HEALTHY_STATUSES):
            before_c, after_c = b_c.get(status, 0), a_c.get(status, 0)
            if after_c > before_c:
                findings.append((key, f"{status}: {before_c} → {after_c}", True))

    table = Table(title="[L3] POD STATUS", box=box.ROUNDED,
                  header_style="bold magenta", title_style="bold cyan", expand=True)
    table.add_column("", width=2)
    table.add_column("Namespace / Owner", style="cyan")
    table.add_column("Change", style="red")
    critical_count = 0
    if not findings:
        table.add_row("[green]✓[/]", "—", "[green]All pods healthy[/]")
    else:
        for key, msg, crit in findings:
            table.add_row("[red]✗[/]" if crit else "[yellow]•[/]", key, msg)
            if crit: critical_count += 1
    return table, critical_count


# ─────────────────────────────────────────────────────────────────────────────
# DIFF orchestrator
# ─────────────────────────────────────────────────────────────────────────────
def diff_snapshots(before_file, after_file):
    with open(before_file, encoding="utf-8") as f: before = json.load(f)
    with open(after_file,  encoding="utf-8") as f: after  = json.load(f)

    # NEW in v5: warn if comparing snapshots from incompatible tool versions
    b_ver = before["metadata"].get("snapshot_tool_version", "pre-5.0")
    a_ver = after["metadata"].get("snapshot_tool_version",  "pre-5.0")
    if b_ver != a_ver:
        console.print(f"[yellow]⚠ Comparing snapshots from different tool versions: "
                      f"{b_ver} vs {a_ver}. Results may be unreliable.[/]")

    console.print(Panel.fit(
        f"[bold magenta]CLUSTER UPGRADE DIFF REPORT  (v{__version__})[/]\n"
        f"Before: [yellow]{before['metadata']['label']}[/]  @ {before['metadata']['timestamp']}\n"
        f"After : [yellow]{after['metadata']['label']}[/]  @ {after['metadata']['timestamp']}\n"
        f"Cluster: [cyan]{before['metadata']['cluster_type']}[/]  "
        f"(v{before['metadata']['cluster_version']} → v{after['metadata']['cluster_version']})",
        border_style="magenta", title="📋 Diff",
    ))

    before_ns = set(before["namespaces"]["list"])
    after_ns  = set(after["namespaces"]["list"])
    common_ns = before_ns & after_ns
    issues = 0

    # LAYER 1: Platform
    console.print(Panel.fit("[bold yellow]LAYER 1 — PLATFORM[/]", border_style="yellow"))
    for title, key, fn in [
        ("[L1] NODES",               "nodes",           cmp_node),
        ("[L1] PERSISTENT VOLUMES",  "pvs",             cmp_pv),
        ("[L1] STORAGE CLASSES",     "storageclasses",  cmp_storageclass),
        ("[L1] CRDs",                "crds",            cmp_crd),
        ("[L1] API SERVICES",        "apiservices",     cmp_apiservice),
    ]:
        t, c = diff_cluster_scoped_table(title, before[key], after[key], fn)
        console.print(t); issues += c

    if before["metadata"]["cluster_type"] == "openshift":
        t, c = diff_cluster_scoped_table("[L1] CLUSTER OPERATORS",
                                         before["clusteroperators"], after["clusteroperators"],
                                         cmp_clusteroperator)
        console.print(t); issues += c

    # LAYER 2: Configuration
    console.print(Panel.fit("[bold yellow]LAYER 2 — CONFIGURATION[/]", border_style="yellow"))

    ns_table = Table(title="[L2] NAMESPACES", box=box.ROUNDED,
                     header_style="bold magenta", title_style="bold cyan", expand=True)
    ns_table.add_column("", width=2); ns_table.add_column("Namespace", style="cyan")
    ns_table.add_column("Change")
    if before_ns == after_ns:
        ns_table.add_row("[green]✓[/]", "—", f"[green]No change ({len(before_ns)} namespaces)[/]")
    else:
        for ns in sorted(before_ns - after_ns):
            ns_table.add_row("[red]✗[/]", ns, "[red]REMOVED[/]"); issues += 1
        for ns in sorted(after_ns - before_ns):
            ns_table.add_row("[green]+[/]", ns, "[green]ADDED[/]")
    console.print(ns_table)

    layer2_sections = [
        ("[L2] CONFIGMAPS",       "configmaps",      cmp_configmap),
        ("[L2] SERVICES",         "services",        cmp_service),
        ("[L2] INGRESSES",        "ingresses",       cmp_ingress),
        ("[L2] NETWORK POLICIES", "networkpolicies", cmp_networkpolicy),
        ("[L2] ROLEBINDINGS",     "rolebindings",    cmp_rolebinding),
        ("[L2] PVCs",             "pvcs",            cmp_pvc),
    ]
    if before["metadata"]["cluster_type"] == "openshift":
        layer2_sections.append(("[L2] ROUTES", "routes", cmp_route))
    if before["metadata"].get("include_secrets") and after["metadata"].get("include_secrets"):
        layer2_sections.append(("[L2] SECRETS (hashed)", "secrets", cmp_secret))

    for title, key, fn in layer2_sections:
        t, c = diff_ns_scoped_table(title, before[key], after[key], common_ns, fn)
        console.print(t); issues += c

    # LAYER 3: Workloads
    console.print(Panel.fit("[bold yellow]LAYER 3 — WORKLOADS[/]", border_style="yellow"))

    t, c = diff_ns_scoped_table("[L3] DEPLOYMENTS",
                                before["deployments"], after["deployments"], common_ns, cmp_deployment)
    console.print(t); issues += c

    t, c = diff_pods_table(before, after)
    console.print(t); issues += c

    for title, key, fn in [
        ("[L3] STATEFULSETS",    "statefulsets",   cmp_statefulset),
        ("[L3] CRONJOBS",        "cronjobs",       cmp_cronjob),
        ("[L3] HPAs",            "hpas",           cmp_hpa),
        ("[L3] PDBs",            "pdbs",           cmp_pdb),
        ("[L3] RESOURCE QUOTAS", "resourcequotas", cmp_resourcequota),
    ]:
        t, c = diff_ns_scoped_table(title, before[key], after[key], common_ns, fn)
        console.print(t); issues += c

    # Verdict
    if issues == 0:
        console.print(Panel.fit(
            "[bold green]✓ UPGRADE CLEAN — no critical regressions across 22 resource categories[/]",
            border_style="green",
        ))
    else:
        console.print(Panel.fit(
            f"[bold red]✗ {issues} CRITICAL ISSUE(S) FOUND — review tables above[/]",
            border_style="red",
        ))
    return issues


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(
        description=f"Backup & diff cluster state across upgrades (v{__version__})  •  EKS + OpenShift",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--version", action="version",
                   version=f"cluster_upgrade_snapshot {__version__}")

    # NOTE: required=True on add_subparsers() needs Python 3.7+. We set it via the
    # attribute instead so the script also runs on Python 3.6 (common on RHEL/OCP nodes).
    sub = p.add_subparsers(dest="command")
    sub.required = True

    cap = sub.add_parser("capture", help="Capture a cluster snapshot (JSON + CSVs)")
    cap.add_argument("--label",           required=True, help="e.g. 'pre-upgrade'")
    cap.add_argument("--output-dir",      required=True, help="Directory for JSON + CSVs")
    cap.add_argument("--include-secrets", action="store_true",
                     help="Also capture Secrets (hashed only — no raw values stored)")

    df = sub.add_parser("diff", help="Diff two snapshot JSON files (rich tables)")
    df.add_argument("--before", required=True)
    df.add_argument("--after",  required=True)

    ex = sub.add_parser("export",
                        help="Export clean, re-applyable YAML manifests (one file per object)")
    ex.add_argument("--output-dir", required=True,
                    help="Base dir for the tree: <output-dir>/<namespace>/<Kind>/<name>.yaml")
    ex.add_argument("--namespace",
                    help="Limit export to a single namespace (default: all namespaces)")
    ex.add_argument("--exclude-system", action="store_true",
                    help="Skip kube-* / openshift-* system namespaces (default: included)")
    ex.add_argument("--no-secrets", action="store_true",
                    help="Do NOT export Secrets (default: secrets ARE exported, with real values)")

    args = p.parse_args()
    try:
        if args.command == "capture":
            snapshot_cluster(args.output_dir, args.label, include_secrets=args.include_secrets)
        elif args.command == "diff":
            sys.exit(1 if diff_snapshots(args.before, args.after) > 0 else 0)
        elif args.command == "export":
            export_cluster_yaml(args.output_dir,
                                only_namespace=args.namespace,
                                exclude_system=args.exclude_system,
                                include_secrets=not args.no_secrets)
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Interrupted by user. Partial output may exist.[/]")
        sys.exit(130)


if __name__ == "__main__":
    main()
