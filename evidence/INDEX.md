# Evidence index

| File | SHA-256 (first 16) | Description |
|---|---|---|
| evidence/after-recovery.jsonl | 6fa45595acde7f83 | Verification of 32 bench/r1-c1 objects after recovery |
| evidence/before-recovery.jsonl | 415356dc870a04e6 | Verification of 32 bench/r1-c1 objects before recovery |
| evidence/canary.jsonl | 42766edbc1265ad0 | Raw canary reads during Pod replacement (start_s/end_s) |
| evidence/delete-time.txt | c05a5f8ec581cd15 | UTC timestamp of storage Pod deletion |
| evidence/E-hash-check-raw.json | 6d03c45eed019e45 | Owner read of research-raw fixture, SHA-256 check (role E) |
| evidence/E-hash-check-release.json | 041c27146a523982 | Owner read of research-release fixture, SHA-256 check (role E) |
| evidence/events.txt | 5b0f093e8eb6e7bd | Kubernetes events exported during recovery |
| evidence/pod-after.yaml | 03289a9e66c6b395 | Storage Pod after replacement (new UID, node, imageID) |
| evidence/pod-before.yaml | 6eed2fcb0c1202fe | Storage Pod before replacement (UID, node, imageID) |
| evidence/pod-logs.txt | 2cc36f66b9d38ebd | Storage Pod logs, credentials excluded |
| evidence/pvc-after.yaml | 3570bc9fee464114 | PVC object-data after replacement (same UID, Bound) |
| evidence/pvc-before.yaml | 3570bc9fee464114 | PVC object-data before replacement (UID, Bound) |
| evidence/pvc-binding-check.yaml | 3570bc9fee464114 | Independent check of PVC binding, volumeName, StorageClass (role E) |
| evidence/role-e-self-audit.txt | ab846a0c0e666762 | Role E self-audit script output |
| evidence/S06-retest.json | 1fed4a21021fa9b0 | S06 retest after recovery: analyst GET release fixture (allow) |
| evidence/S08-retest.json | 511e0084651727e1 | S08 retest after recovery: analyst PUT release (deny) |
| evidence/S10-retest.json | f7d437ba3eea3964 | S10 retest after recovery: analyst GET raw fixture (deny) |
| evidence/topology.txt | e2c83e0a0492f127 | Pod/PVC/Service/EndpointSlice topology |
| evidence/versions.yaml | 0d1002b538b9a692 | kubectl client/server versions |
