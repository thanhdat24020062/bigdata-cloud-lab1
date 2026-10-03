# Cloud-Native Big Data Infrastructure & Governance

**Group namespace:** `bd-g05`

This repository contains the deployment manifests, scripts, governance configuration, experiment evidence, and final results for the Cloud-Native Big Data Infrastructure & Governance lab.

## Project Structure

```text
lab1-bigdata/
├── manifests/
│   ├── task-a/        # Platform guardrails, quotas, resource policies
│   ├── task-b/        # Storage deployment, PVC, Service, client workloads
│   ├── task-c/        # S3 access control, RBAC, NetworkPolicy
│   ├── task-d/        # Performance and benchmark configuration
│   └── task-e/        # Reliability and governance configuration
│
├── evidence/
│   ├── task-a/        # Task A logs, outputs, screenshots, results
│   ├── task-b/        # Task B logs, outputs, screenshots, results
│   ├── task-c/        # S3, RBAC, and network security test evidence
│   ├── task-d/        # Benchmark outputs and performance evidence
│   └── task-e/        # Recovery and governance evidence
│
├── scripts/
│   ├── make_identities.py   # Generate S3 identities and credentials
│   └── observer.py          # Generate observer kubeconfig
│
├── governance/
│   ├── policies-redacted.json
│   └── task-c-governance.json
│
├── private/           # Local credentials and kubeconfig files
│                      # DO NOT commit this directory
│
├── security-results.csv
├── README.md
└── .gitignore