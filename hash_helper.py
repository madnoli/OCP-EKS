"""
hash_helper.py — Stable hashing for Kubernetes objects.

THE PROBLEM THIS SOLVES:
========================
Naive hashing of K8s objects produces FALSE POSITIVE drift alerts because every
object contains volatile fields that change with each cluster operation:

  • metadata.resourceVersion       — bumps on every write
  • metadata.generation            — bumps on every spec change
  • metadata.managedFields[]       — rewritten constantly by controllers
  • metadata.creationTimestamp     — fine, but...
  • metadata.uid                   — changes if object is recreated
  • status.*                       — observed state, NOT desired
  • Auto-injected annotations      — operators add these
  • System labels (beta.*, etc.)   — change between K8s versions
  • Last-applied-config annotation — kubectl/oc rewrites it

THE SOLUTION:
=============
Hash ONLY user-declared fields. Strip system noise. Separate spec from status.
"""

import hashlib
import json
from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# The Deny-Lists
#
# These are the noisy fields that change for reasons UNRELATED to user intent.
# Keep this list narrow — when in doubt, INCLUDE the field in the hash.
# Better to flag a false positive than miss a real change.
# ─────────────────────────────────────────────────────────────────────────────

# Annotations injected by the platform or kubectl/oc, not by users
NOISY_ANNOTATIONS_EXACT = frozenset({
    # kubectl / oc machinery
    "kubectl.kubernetes.io/last-applied-configuration",
    "kubectl.kubernetes.io/restartedAt",

    # Deployment / ReplicaSet rollout tracking
    "deployment.kubernetes.io/revision",
    "deployment.kubernetes.io/desired-replicas",
    "deployment.kubernetes.io/max-replicas",

    # Endpoint / Service controller noise
    "endpoints.kubernetes.io/last-change-trigger-time",
    "endpoints.kubernetes.io/over-capacity",

    # Leader election (anywhere it's used)
    "control-plane.alpha.kubernetes.io/leader",

    # Pod readiness / scheduling internals
    "kubernetes.io/psp",
    "scheduler.alpha.kubernetes.io/preferAvoidPods",

    # OpenShift internals
    "openshift.io/generated-by",
    "openshift.io/host.generated",      # Route — auto-generated host marker
    "openshift.io/scc",                 # injected by SCC admission

    # Service Account token controller
    "kubernetes.io/service-account.uid",
})

# Annotations whose KEY PREFIX is auto-managed
NOISY_ANNOTATION_PREFIXES = (
    "kubectl.kubernetes.io/",            # all kubectl machinery
    "autoscaling.alpha.kubernetes.io/",
    "batch.kubernetes.io/",              # job controller status hints
    "cni.projectcalico.org/",
    "k8s.v1.cni.cncf.io/",
    "kubernetes.io/change-cause",        # `--record` flag noise
)

# Labels auto-managed by the platform — change between K8s versions or operators
NOISY_LABEL_EXACT = frozenset({
    "controller-uid",                    # ReplicaSet → Pod
    "pod-template-hash",                 # ReplicaSet → Pod
    "controller-revision-hash",          # StatefulSet → Pod
    "statefulset.kubernetes.io/pod-name",
    "batch.kubernetes.io/controller-uid",
    "batch.kubernetes.io/job-name",
})

# Labels whose PREFIX is auto-managed (often differ between K8s versions)
NOISY_LABEL_PREFIXES = (
    "beta.kubernetes.io/",                  # deprecated, replaced over time
    "failure-domain.beta.kubernetes.io/",   # deprecated, replaced
    "topology.ebs.csi.aws.com/",            # CSI driver internals
    "topology.gke.io/",                     # GKE internals (harmless if present)
    "csi.k8s.io/",
    "node.kubernetes.io/instance-type",     # provider-managed
    "eks.amazonaws.com/",                   # EKS internals (nodegroup, etc.)
    "alpha.eksctl.io/",
    "machine.openshift.io/",                # OCP MachineSet internals
    "machineconfiguration.openshift.io/",   # OCP MCO internals
)

# Status-like fields that sneak into spec on some resources — exclude these too
NOISY_SPEC_PATHS = frozenset({
    "spec.nodeName",                # Pod — assigned by scheduler, not user
    "spec.serviceAccount",          # Pod — deprecated alias of serviceAccountName
    "spec.priority",                # Pod — set by priority class controller
})

# Top-level fields that should NEVER be in a hash
ALWAYS_STRIP_METADATA_FIELDS = frozenset({
    "resourceVersion",
    "generation",
    "uid",
    "creationTimestamp",
    "deletionTimestamp",
    "deletionGracePeriodSeconds",
    "finalizers",                    # added/removed by controllers
    "managedFields",                 # massive, rewritten constantly
    "ownerReferences",               # set by controllers
    "selfLink",                      # deprecated, removed in K8s 1.20+
    "generateName",
})


# ─────────────────────────────────────────────────────────────────────────────
# Cleaning functions — strip noise before hashing
# ─────────────────────────────────────────────────────────────────────────────

def clean_annotations(anns: Optional[Dict[str, str]]) -> Dict[str, str]:
    """Remove auto-managed annotations. Returns a new dict; doesn't mutate."""
    if not anns:
        return {}
    return {
        k: v for k, v in anns.items()
        if k not in NOISY_ANNOTATIONS_EXACT
        and not any(k.startswith(p) for p in NOISY_ANNOTATION_PREFIXES)
    }


def clean_labels(labels: Optional[Dict[str, str]]) -> Dict[str, str]:
    """Remove auto-managed labels. Returns a new dict."""
    if not labels:
        return {}
    return {
        k: v for k, v in labels.items()
        if k not in NOISY_LABEL_EXACT
        and not any(k.startswith(p) for p in NOISY_LABEL_PREFIXES)
    }


def clean_metadata(meta: Any) -> Dict[str, Any]:
    """
    Extract a fingerprint of user-relevant metadata.
    Strips resourceVersion, managedFields, timestamps, controller-set fields.
    Keeps name, namespace, USER labels, USER annotations.
    """
    if meta is None:
        return {}
    # Support both dict (raw API responses) and typed objects (kubernetes SDK)
    if hasattr(meta, "to_dict"):
        meta = meta.to_dict()

    return {
        "name":        meta.get("name"),
        "namespace":   meta.get("namespace"),
        "labels":      clean_labels(meta.get("labels")),
        "annotations": clean_annotations(meta.get("annotations")),
    }


def strip_paths(obj: Any, paths_to_strip: frozenset) -> Any:
    """
    Recursively remove dotted-path fields from a dict.
    Example: strip_paths(pod_spec, {"spec.nodeName"}) removes spec.nodeName.
    Doesn't mutate input.
    """
    if not isinstance(obj, dict):
        return obj
    result = {}
    for k, v in obj.items():
        # Check if any path-to-strip starts with this key
        sub_paths = {p[len(k)+1:] for p in paths_to_strip if p.startswith(f"{k}.")}
        if k in paths_to_strip:
            continue  # full match — drop it
        if sub_paths and isinstance(v, dict):
            result[k] = strip_paths(v, frozenset(sub_paths))
        else:
            result[k] = v
    return result


# ─────────────────────────────────────────────────────────────────────────────
# The hash functions
# ─────────────────────────────────────────────────────────────────────────────

def stable_hash(obj: Any) -> str:
    """
    Deterministic SHA-1 of any JSON-serializable object.
    Uses sort_keys=True so {a:1,b:2} and {b:2,a:1} produce the SAME hash.
    Returns 12-char prefix (collisions vanishingly rare for our use case).
    """
    if obj is None or obj == {} or obj == []:
        return "empty"
    return hashlib.sha1(
        json.dumps(obj, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:12]


def spec_hash(spec: Any,
              extra_strip_paths: Optional[frozenset] = None) -> str:
    """
    Hash of an object's SPEC, with known-noisy spec paths removed.

    Use this instead of `stable_hash(obj.spec)` for any K8s object's spec.
    """
    if spec is None:
        return "empty"
    if hasattr(spec, "to_dict"):
        spec = spec.to_dict()

    paths = NOISY_SPEC_PATHS
    if extra_strip_paths:
        paths = frozenset(paths | extra_strip_paths)

    cleaned = strip_paths({"spec": spec}, paths)
    return stable_hash(cleaned)


def declared_state_hash(obj: Any,
                        extra_strip_paths: Optional[frozenset] = None) -> str:
    """
    The MAIN function to use. Hashes the USER-DECLARED state of an object:
      - cleaned metadata (no resourceVersion, managedFields, etc.)
      - cleaned spec    (no scheduler-assigned fields)
      - cleaned data    (for ConfigMaps, Secrets)
      - cleaned subjects/roleRef (for RoleBindings)

    SKIPS status entirely (compare status separately with transition rules).
    """
    if obj is None:
        return "empty"
    if hasattr(obj, "to_dict"):
        obj = obj.to_dict()

    fingerprint = {
        "metadata": clean_metadata(obj.get("metadata")),
    }
    # Include any of these top-level fields that exist
    for field in ("spec", "data", "binaryData", "stringData",
                  "subjects", "roleRef", "rules",
                  "provisioner", "parameters", "reclaimPolicy"):
        if field in obj and obj[field] is not None:
            value = obj[field]
            if field == "spec":
                paths = NOISY_SPEC_PATHS
                if extra_strip_paths:
                    paths = frozenset(paths | extra_strip_paths)
                value = strip_paths({"_": value}, paths)["_"]
            fingerprint[field] = value

    return stable_hash(fingerprint)


# ─────────────────────────────────────────────────────────────────────────────
# Convenience: compare two objects and explain WHAT changed
# ─────────────────────────────────────────────────────────────────────────────

def explain_diff(before: Any, after: Any,
                 prefix: str = "") -> List[str]:
    """
    Walk two cleaned dicts and produce human-readable diff lines.
    Use this when the hash differs and you want to know WHY.

    NOT used for primary detection (the hash is the gate). Used to expand
    a single 'spec changed' finding into 'spec.replicas changed: 3 → 5'.
    """
    if before == after:
        return []

    out = []
    if isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(set(before) | set(after)):
            path = f"{prefix}.{key}" if prefix else key
            if key not in before:
                out.append(f"+ {path} = {after[key]!r}")
            elif key not in after:
                out.append(f"- {path}")
            else:
                out.extend(explain_diff(before[key], after[key], path))
    elif isinstance(before, list) and isinstance(after, list):
        if before != after:
            out.append(f"~ {prefix}: list changed ({len(before)} → {len(after)} items)")
    else:
        if before != after:
            out.append(f"~ {prefix}: {before!r} → {after!r}")
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Self-test / examples (run: python3 hash_helper.py)
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Running self-tests for hash_helper.py")
    print("=" * 60)

    # Test 1: Same logical object, different volatile fields → SAME hash
    obj_before = {
        "metadata": {
            "name": "my-app",
            "namespace": "prod",
            "resourceVersion": "847291",          # volatile
            "generation": 5,                       # volatile
            "uid": "8f7a-old-uid-xxx",            # volatile
            "managedFields": [{"manager": "kubectl"}],  # volatile, huge
            "creationTimestamp": "2026-01-01T00:00:00Z",  # volatile-ish
            "labels": {
                "app": "my-app",                  # user label, KEEP
                "pod-template-hash": "abc123",    # noisy, STRIP
            },
            "annotations": {
                "owner": "platform-team",         # user annotation, KEEP
                "deployment.kubernetes.io/revision": "5",  # noisy, STRIP
                "kubectl.kubernetes.io/last-applied-configuration": "{huge json}",  # noisy
            },
        },
        "spec": {"replicas": 3, "selector": {"matchLabels": {"app": "my-app"}}},
        "status": {"readyReplicas": 3, "observedGeneration": 5},  # IGNORED
    }
    obj_after = {
        "metadata": {
            "name": "my-app",
            "namespace": "prod",
            "resourceVersion": "999988",          # changed (noise)
            "generation": 6,                       # changed (noise)
            "uid": "8f7a-old-uid-xxx",
            "managedFields": [{"manager": "oc"}, {"manager": "operator"}],  # changed (noise)
            "creationTimestamp": "2026-01-01T00:00:00Z",
            "labels": {
                "app": "my-app",
                "pod-template-hash": "xyz789",    # changed (noise — different RS)
            },
            "annotations": {
                "owner": "platform-team",
                "deployment.kubernetes.io/revision": "6",  # changed (noise)
                "kubectl.kubernetes.io/last-applied-configuration": "{different huge json}",
            },
        },
        "spec": {"replicas": 3, "selector": {"matchLabels": {"app": "my-app"}}},  # SAME spec
        "status": {"readyReplicas": 2, "observedGeneration": 6},  # changed (ignored)
    }
    h1 = declared_state_hash(obj_before)
    h2 = declared_state_hash(obj_after)
    print(f"Test 1 (volatile noise only): hashes match? {h1 == h2}  {h1} vs {h2}")
    assert h1 == h2, "FAIL: hashes should be equal when only noise changed"
    print("  ✓ PASS: noise stripped correctly\n")

    # Test 2: Real spec change → DIFFERENT hash
    obj_after_real_change = {**obj_after, "spec": {"replicas": 5,
                              "selector": {"matchLabels": {"app": "my-app"}}}}
    h3 = declared_state_hash(obj_after_real_change)
    print(f"Test 2 (real spec change): hashes differ? {h1 != h3}  {h1} vs {h3}")
    assert h1 != h3, "FAIL: hashes should differ when spec.replicas changed"
    print("  ✓ PASS: real change detected\n")

    # Test 3: clean_labels filters noisy prefixes
    labels = {
        "app": "payments",
        "team": "platform",
        "beta.kubernetes.io/arch": "amd64",       # deprecated → strip
        "kubernetes.io/hostname": "node-1",       # user-relevant → keep
        "pod-template-hash": "abc",                # auto-generated → strip
        "node.kubernetes.io/instance-type": "m5", # provider → strip
    }
    cleaned = clean_labels(labels)
    expected = {"app": "payments", "team": "platform",
                "kubernetes.io/hostname": "node-1"}
    print(f"Test 3 (label cleaning): {cleaned == expected}")
    assert cleaned == expected, f"FAIL: got {cleaned}"
    print("  ✓ PASS: noisy labels stripped\n")

    # Test 4: explain_diff produces readable output
    diffs = explain_diff(
        {"spec": {"replicas": 3, "image": "v1"}},
        {"spec": {"replicas": 5, "image": "v2"}},
    )
    print(f"Test 4 (explain_diff): {diffs}")
    assert any("replicas" in d for d in diffs)
    assert any("image" in d for d in diffs)
    print("  ✓ PASS: diff explained\n")

    print("=" * 60)
    print("All self-tests passed! ✓")
