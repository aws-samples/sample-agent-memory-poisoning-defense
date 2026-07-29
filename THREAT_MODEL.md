# Threat Model: AgentCore Memory Poisoning Defense

## 1. Project Overview

| Field | Value |
|-------|-------|
| Project Name | AgentCore Memory Poisoning Defense |
| Author | Tarun Kumar (tarrych@) |
| Date | 2026-07-29 |
| Type | Sample code / Blog companion |
| Publication Channel | aws-samples (GitHub) |
| Associated Blog | AWS Security Blog: "Defend against memory poisoning in Amazon Bedrock AgentCore with multi-layer write validation" |

## 2. Architecture Summary

The solution is a Lambda-based validation pipeline that attaches as a pre-write interceptor on Amazon Bedrock AgentCore Gateway. It evaluates memory write content against four signals (semantic drift, instruction patterns, namespace boundaries, write-rate anomaly) and returns ALLOW, QUARANTINE, or DENY decisions.

**AWS Services Used:**
- AWS Lambda (validation function)
- Amazon DynamoDB (write-rate tracking, audit log)
- Amazon Bedrock Titan Embeddings v2 (semantic similarity)
- Amazon SNS (alerting)
- Amazon Bedrock AgentCore (Gateway, Memory, Policy)
- AWS KMS (quarantine namespace encryption)

## 3. Data Flow

```
Agent → AgentCore Memory Write API → AgentCore Gateway (interceptor) → Validation Lambda
                                                                            │
                                                            ┌───────────────┼───────────────┐
                                                            ▼               ▼               ▼
                                                         ALLOW          QUARANTINE         DENY
                                                            │               │               │
                                                            ▼               ▼               ▼
                                                      Target namespace  Quarantine NS    Blocked + SNS
```

## 4. Data Classification

| Data | Classification | Notes |
|------|---------------|-------|
| Memory write content | Customer content | Passed through for validation, not stored outside DynamoDB audit log |
| Session context (embeddings) | Customer content | Used for cosine similarity, not persisted |
| Write-rate counters | Operational metadata | Session ID + count only |
| Audit log entries | Operational metadata | Content hash + decision + scores |

## 5. Threat Analysis

### Threat 1: Secrets in sample code
| Field | Value |
|-------|-------|
| Risk | Hardcoded credentials, API keys, or account IDs in published code |
| Likelihood | Low |
| Impact | High |
| Mitigation | No real credentials in code. All values use placeholders (`<your-gateway-id>`, `<account-id>`). git-secrets installed. |

### Threat 2: Overly permissive IAM roles
| Field | Value |
|-------|-------|
| Risk | CDK stack creates Lambda role with excessive permissions |
| Likelihood | Medium |
| Impact | Medium |
| Mitigation | Lambda role follows least privilege: only DynamoDB (specific table), SNS (specific topic), Bedrock InvokeModel (Titan Embeddings only), KMS (specific key). |

### Threat 3: Customer data exposure in logs
| Field | Value |
|-------|-------|
| Risk | Memory write content logged in full, exposing sensitive customer data |
| Likelihood | Medium |
| Impact | Medium |
| Mitigation | Audit log stores content hash only, not full content. CloudWatch logs contain only decision + score, not payload. Demo test cases use synthetic data only. |

### Threat 4: DynamoDB table publicly accessible
| Field | Value |
|-------|-------|
| Risk | Write-rate or audit tables accessible without auth |
| Likelihood | Low |
| Impact | High |
| Mitigation | DynamoDB tables use default VPC-only access. No public endpoints. IAM policy restricts access to Lambda execution role only. Encryption at rest enabled. |

### Threat 5: SNS topic sends alerts to unintended recipients
| Field | Value |
|-------|-------|
| Risk | Security alerts with content previews sent to wrong endpoint |
| Likelihood | Low |
| Impact | Medium |
| Mitigation | SNS topic policy restricts publish to Lambda role only. Subscription requires confirmation. Content preview is truncated (first 100 chars). |

### Threat 6: Malicious input in test payloads
| Field | Value |
|-------|-------|
| Risk | Test payloads contain real malicious URLs or instructions that could be misused |
| Likelihood | Low |
| Impact | Low |
| Mitigation | Test payloads use clearly fake domains (exfil.evil.com, legit-looking-domain.com). These are educational examples demonstrating attack patterns, consistent with published security research. |

## 6. Assumptions and Limitations

- This is **sample code** — not production-ready without additional hardening
- Customers are responsible for their own security testing before deployment
- The demo uses a local keyword-overlap approximation instead of real Titan Embeddings API calls
- No real customer data is included in any test cases or examples
- The README includes a clear disclaimer stating this is for educational purposes

## 7. Conclusion

The sample code follows AWS security best practices for public content:
- No hardcoded secrets or credentials
- Least-privilege IAM policies
- Encryption at rest for all data stores
- No real customer data
- Clear educational disclaimer

The primary purpose is to demonstrate a security defense pattern. The code itself does not introduce security risks beyond standard Lambda/DynamoDB/SNS usage patterns well-documented in AWS.
