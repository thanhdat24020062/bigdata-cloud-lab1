# Role C - Access Engineer

## Responsibilities
- Configure bucket-scoped S3 permissions.
- Configure Kubernetes observer RBAC.
- Configure and verify ingress NetworkPolicy.

## S3 authorization
12 authorization tests were executed.

Result:
- S01-S12: 12/12 passed.

An initial policy configuration allowed permissions too broadly.
The S3 policy was corrected to:
- ingestor: Read/Write/List only on research-raw
- analyst: Read/List only on research-release

The failed attempts were retained before retesting.

## Kubernetes RBAC
Observer permissions were tested using a token-only kubeconfig.

Result:
- K01-K03 allowed.
- K04-K06 denied with Forbidden.
- Total: 6/6 passed.

## NetworkPolicy
Network reachability was tested for authorized, blocked and outsider clients.

Result:
- N01 authorized owner connection: allowed.
- N02 blocked client: blocked.
- N03 management port 8888: blocked.
- N04 outsider namespace: blocked.
- Total: 4/4 passed.

## Final Task 3 result
- S3: 12/12
- RBAC: 6/6
- Network: 4/4
- Total security tests: 22/22
