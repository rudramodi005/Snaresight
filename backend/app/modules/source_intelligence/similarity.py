"""Explainable behavioral similarity analysis across Observed Source Profiles."""

import math
from typing import Any
from app.modules.source_intelligence.schemas import SimilarFactor, SimilarProfileResponse


def _cosine_similarity(vec1: dict[str, int | float], vec2: dict[str, int | float]) -> float:
    """Calculates cosine similarity between two frequency vectors."""
    all_keys = set(vec1.keys()) | set(vec2.keys())
    if not all_keys:
        return 1.0
    dot_product = sum(vec1.get(k, 0) * vec2.get(k, 0) for k in all_keys)
    norm1 = math.sqrt(sum(v * v for v in vec1.values()))
    norm2 = math.sqrt(sum(v * v for v in vec2.values()))
    if norm1 == 0 or norm2 == 0:
        return 0.0
    return max(0.0, min(1.0, dot_product / (norm1 * norm2)))


def _jaccard_similarity(set1: set, set2: set) -> float:
    """Calculates Jaccard similarity between two sets."""
    if not set1 and not set2:
        return 1.0
    if not set1 or not set2:
        return 0.0
    intersection = len(set1 & set2)
    union = len(set1 | set2)
    return intersection / union if union > 0 else 0.0


def compare_source_profiles(
    source_p: Any,
    source_feat: dict[str, Any],
    target_p: Any,
    target_feat: dict[str, Any],
) -> SimilarProfileResponse:
    """Computes transparent behavioral similarity between a base profile and a candidate profile."""
    factors: list[SimilarFactor] = []

    # 1. Honeypot Affinity Dimension (Weight: 0.25)
    # Extract distinct honeypots from features / summaries
    source_hones = set(source_p.behavioral_summary.get("honeypots", []))
    target_hones = set(target_p.behavioral_summary.get("honeypots", []))
    hone_sim = _jaccard_similarity(source_hones, target_hones)
    common_honeypots = sorted(list(source_hones & target_hones))
    factors.append(
        SimilarFactor(
            dimension="TARGET_AFFINITY",
            weight=0.25,
            similarity=round(hone_sim, 3),
            rationale=(
                f"Shared {len(common_honeypots)} decoy target(s): {', '.join(common_honeypots) if common_honeypots else 'None'}"
            ),
        )
    )

    # 2. Protocol Distribution Dimension (Weight: 0.25)
    proto_sim = _cosine_similarity(source_p.protocol_distribution, target_p.protocol_distribution)
    factors.append(
        SimilarFactor(
            dimension="PROTOCOL_DISTRIBUTION",
            weight=0.25,
            similarity=round(proto_sim, 3),
            rationale=f"Protocol vector cosine alignment of {round(proto_sim * 100, 1)}%",
        )
    )

    # 3. MITRE Technique Footprint Dimension (Weight: 0.25)
    source_techs = set(source_feat.get("technique_distribution", {}).keys())
    target_techs = set(target_feat.get("technique_distribution", {}).keys())
    tech_sim = _jaccard_similarity(source_techs, target_techs)
    common_techs = sorted(list(source_techs & target_techs))
    factors.append(
        SimilarFactor(
            dimension="ATTACK_TECHNIQUES",
            weight=0.25,
            similarity=round(tech_sim, 3),
            rationale=(
                f"Shared {len(common_techs)} ATT&CK technique(s): {', '.join(common_techs) if common_techs else 'None'}"
            ),
        )
    )

    # 4. Behavioral Modulation & Interaction Tempo (Weight: 0.25)
    # Compare tempo, auth failure ratio, and traversal probes
    s_tempo = source_feat.get("interaction_tempo", 0.0)
    t_tempo = target_feat.get("interaction_tempo", 0.0)
    tempo_sim = 1.0 - min(abs(s_tempo - t_tempo) / max(s_tempo + t_tempo, 1.0), 1.0)

    s_auth_fail = source_feat.get("auth_failure_count", 0)
    t_auth_fail = target_feat.get("auth_failure_count", 0)
    auth_sim = 1.0 - min(abs(s_auth_fail - t_auth_fail) / max(s_auth_fail + t_auth_fail, 1.0), 1.0)

    behavior_sim = 0.5 * tempo_sim + 0.5 * auth_sim
    factors.append(
        SimilarFactor(
            dimension="INTERACTION_MODULATION",
            weight=0.25,
            similarity=round(behavior_sim, 3),
            rationale=f"Tempo alignment {round(tempo_sim * 100, 1)}% and auth spray similarity {round(auth_sim * 100, 1)}%",
        )
    )

    # Weighted Composite Score (0 - 100%)
    overall_sim = sum(f.weight * f.similarity for f in factors) * 100.0
    overall_score = round(max(0.0, min(100.0, overall_sim)), 1)

    return SimilarProfileResponse(
        target_profile_id=target_p.profile_id,
        target_display_label=target_p.display_label,
        target_source_ip=target_p.source_ip,
        similarity_score=overall_score,
        priority=target_p.profile_priority,
        status=target_p.profile_status,
        contributing_factors=factors,
        common_techniques=common_techs,
        common_honeypots=common_honeypots,
    )

