# Behavioral Similarity Method

## 1. Objective & Explainability
The **Behavioral Similarity Engine** (`similarity.py`) determines whether two Observed Source Profiles share operational methods, targeting patterns, or interaction tempos.

Rather than relying on opaque deep-learning models or black-box embeddings, the engine uses **transparent vector alignment and set overlap metrics**. Every similarity assessment generates:
1. An overall match percentage (0% to 100%).
2. Individual contributing factors with associated weights and rationales.
3. Overlapping techniques and honeypots.

---

## 2. Multi-Dimensional Similarity Model

Similarity is computed across four distinct dimensions, each weighted equally ($w_i = 0.25$):

$$S_{\text{composite}} = \sum_{i=1}^{4} w_i \cdot s_i \times 100\%$$

### Dimension 1: Target Decoy Affinity ($s_1$, Weight = 0.25)
- Computes Jaccard set similarity over the set of honeypots targeted:
  $$s_1 = J(H_1, H_2) = \frac{|H_1 \cap H_2|}{|H_1 \cup H_2|}$$
- If both sources target identical decoys (e.g. `WEB-001` and `SSH-001`), $s_1 = 1.0$.

### Dimension 2: Protocol Vector Distribution ($s_2$, Weight = 0.25)
- Computes the Cosine Similarity between the normalized protocol frequency vectors $\mathbf{u}$ and $\mathbf{v}$:
  $$s_2 = \frac{\mathbf{u} \cdot \mathbf{v}}{\|\mathbf{u}\| \|\mathbf{v}\|}$$
- Captures whether sources focus on the same protocol mix (e.g. 80% SSH, 20% HTTP).

### Dimension 3: MITRE Technique Footprint ($s_3$, Weight = 0.25)
- Computes Jaccard set similarity over observed MITRE ATT&CK technique IDs:
  $$s_3 = J(T_1, T_2) = \frac{|T_1 \cap T_2|}{|T_1 \cup T_2|}$$
- Highlights shared exploitation or probing techniques (e.g. Credential Spraying `T1110.003`, Command Shell `T1059.004`).

### Dimension 4: Interaction Modulation ($s_4$, Weight = 0.25)
- Compares interaction tempo and authentication failure counts:
  $$s_{\text{tempo}} = 1.0 - \min\left(\frac{|\text{tempo}_1 - \text{tempo}_2|}{\max(\text{tempo}_1 + \text{tempo}_2, 1.0)}, 1.0\right)$$
  $$s_{\text{auth}} = 1.0 - \min\left(\frac{|\text{auth}_1 - \text{auth}_2|}{\max(\text{auth}_1 + \text{auth}_2, 1.0)}, 1.0\right)$$
  $$s_4 = 0.5 \cdot s_{\text{tempo}} + 0.5 \cdot s_{\text{auth}}$$

---

## 3. Explainable Output Structure
The result returns:
```json
{
  "target_profile_id": "PROF-9E8B2A1C0F451D8E",
  "target_source_ip": "198.51.100.42",
  "similarity_score": 88.5,
  "priority": "HIGH",
  "status": "ACTIVE",
  "contributing_factors": [
    {
      "dimension": "TARGET_AFFINITY",
      "weight": 0.25,
      "similarity": 1.0,
      "rationale": "Shared 2 decoy target(s): SSH-001, WEB-001"
    },
    {
      "dimension": "PROTOCOL_DISTRIBUTION",
      "weight": 0.25,
      "similarity": 0.95,
      "rationale": "Protocol vector cosine alignment of 95.0%"
    },
    {
      "dimension": "ATTACK_TECHNIQUES",
      "weight": 0.25,
      "similarity": 0.8,
      "rationale": "Shared 2 ATT&CK technique(s): T1110, T1059"
    },
    {
      "dimension": "INTERACTION_MODULATION",
      "weight": 0.25,
      "similarity": 0.79,
      "rationale": "Tempo alignment 82.0% and auth spray similarity 76.0%"
    }
  ],
  "common_techniques": ["T1110", "T1059"],
  "common_honeypots": ["SSH-001", "WEB-001"]
}
```

