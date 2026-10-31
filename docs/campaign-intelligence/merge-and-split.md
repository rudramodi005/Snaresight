# Cluster Merge & Split Operations

## Non-Destructive Invariant
In security investigations, analyst hypotheses evolve as more telemetry is collected. However, historical integrity must never be destroyed. SnareSight enforces a strict **Non-Destructive Invariant**:

- **No Data Deletion:** Merging or splitting never deletes original records from `investigation_clusters`, `cluster_memberships`, or `cluster_evidence`.
- **Bidirectional Provenance:** Explicit foreign keys (`merged_into_id`, `split_from_id`) preserve the exact lineage of every cluster transformation.
- **Audit Persistence:** Detailed audit logs record which analyst performed the operation, the reason provided, and the entities affected.

---

## 1. Merge Operation (`merge_clusters`)

When an analyst determines that two clusters represent the same underlying campaign or coordinated activity, they can merge the source cluster into a target cluster.

```
+------------------------------------+       +------------------------------------+
| Source Cluster: CLUST-SRC          |       | Target Cluster: CLUST-TGT          |
| Status: CANDIDATE / UNDER_REVIEW   |       | Status: ACTIVE                     |
| Members: [SESS-1, SESS-2]          |       | Members: [SESS-3]                  |
+-----------------+------------------+       +-----------------+------------------+
                  |                                            |
                  |                   MERGE                    |
                  +--------------------------------------------+
                                       |
                                       v
+------------------------------------+       +------------------------------------+
| Preserved Source: CLUST-SRC        |       | Updated Target: CLUST-TGT          |
| Status: MERGED                     |       | Status: ACTIVE                     |
| merged_into_id: CLUST-TGT          |       | Members: [SESS-3, SESS-1, SESS-2]  |
| Members: Retained (historical)     |       | Evidence: Consolidated from SRC    |
+------------------------------------+       +------------------------------------+
```

### Execution Steps:
1. Validate that `source_cluster_id` and `target_cluster_id` exist and are distinct.
2. Validate that target cluster is not already `MERGED` or `SPLIT`.
3. Copy all unique `ClusterMembershipModel` entries from the source cluster to the target cluster (preventing duplicate membership keys).
4. Copy unique `ClusterEvidenceModel` entries from the source cluster to the target cluster.
5. Recompute the target cluster's aggregate metrics (`entity_counts`, `shared_indicators`, `first_seen_at`, `last_seen_at`).
6. Set source cluster `lifecycle_status = 'MERGED'` and `merged_into_id = target_cluster_id`.
7. Write audit entries to both source and target cluster logs.
8. Publish SSE notification for real-time frontend synchronization.

---

## 2. Split Operation (`split_cluster`)

When an analyst determines that an existing cluster contains unrelated activities (e.g., disparate scanning coincidentally hitting the same sensor), they can split specific entities into a new cluster.

```
+--------------------------------------------------------------+
| Source Cluster: CLUST-ORIG (Status: ACTIVE)                  |
| Members: [SESS-A, SESS-B, SESS-C, SESS-D]                    |
+------------------------------+-------------------------------+
                               |
                               | SPLIT [SESS-C, SESS-D]
                               v
+------------------------------+   +---------------------------+
| Source Cluster: CLUST-ORIG   |   | New Cluster: CLUST-NEW    |
| Status: ACTIVE               |   | Status: ACTIVE            |
| Members: [SESS-A, SESS-B]    |   | split_from_id: CLUST-ORIG |
|                              |   | Members: [SESS-C, SESS-D] |
+------------------------------+   +---------------------------+
```

### Execution Steps:
1. Validate that the specified `entity_ids` exist in the source cluster.
2. Require that at least one entity remains in the source cluster (a cluster cannot be emptied entirely via split).
3. Create a new `InvestigationClusterModel` with a fresh unique code, descriptive title, and `split_from_id = source_cluster_id`.
4. Reassign the selected memberships to the new cluster.
5. Reassign associated evidence to the new cluster where applicable.
6. Recompute aggregates (`entity_counts`, `shared_indicators`, `first_seen_at`, `last_seen_at`) for both clusters.
7. Write audit log entries on both source and new cluster records.
8. Publish SSE notification for real-time UI refresh.

