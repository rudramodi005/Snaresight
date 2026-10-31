# Interactive ATT&CK Matrix Layout and Visual States

## Canonical Enterprise Tactic Order
The matrix displays all 14 tactics in exact canonical progression:
1. `TA0043` — Reconnaissance
2. `TA0042` — Resource Development
3. `TA0001` — Initial Access
4. `TA0002` — Execution
5. `TA0003` — Persistence
6. `TA0004` — Privilege Escalation
7. `TA0005` — Defense Evasion
8. `TA0006` — Credential Access
9. `TA0007` — Discovery
10. `TA0008` — Lateral Movement
11. `TA0009` — Collection
12. `TA0011` — Command and Control
13. `TA0010` — Exfiltration
14. `TA0040` — Impact

## Visual States & Hierarchy
Each technique card in the matrix reflects its operational status computed in real-time:
1. `ALERT_EVIDENCE` (Emerald / Pulse):
   - Active honeypot alert evidence has been recorded for this technique.
   - Shows badge with total supporting alert count.
2. `RULE_MAPPED` (Blue):
   - Configured detection rule exists in `MitreMappingRegistry`, but no live alerts have yet fired.
3. `REVIEW_REQUIRED` (Amber):
   - Mapping exists with status `PENDING` or `NEEDS_MORE_EVIDENCE` awaiting analyst review.
4. `UNMAPPED` (Muted Slate):
   - Technique is part of Enterprise ATT&CK but no detection rule has been mapped.

## Navigation and Interaction
- Clicking any technique card opens the slide-over Technique Detail Drawer.
- Multi-attribute filtering allows slicing matrix columns by Visual State, Keyword search, or Tactic.
- Horizontal scrolling container preserves fixed column widths for all 14 tactics simultaneously.

