# Defend Against Memory Poisoning in Amazon Bedrock AgentCore with Multi-Layer Write Validation

## Summary

Implement a real-time memory write validation pipeline for AI agents on Amazon Bedrock AgentCore that detects and neutralizes memory poisoning attacks. The pipeline uses a Gateway interceptor Lambda to score every memory write against 4 detection signals — semantic drift, instruction-pattern detection, namespace boundary enforcement, and write-rate anomaly — and applies a graduated response (allow, quarantine, or deny) before content reaches persistent memory.

## Problem

AI agents on Amazon Bedrock AgentCore use persistent memory (AgentCore Memory) for cross-session context, user preferences, and shared domain knowledge. This memory is retrieved and injected into the agent's context automatically — meaning anything stored in memory directly influences the agent's future behavior.

Memory poisoning exploits this trust: an attacker embeds malicious instructions in content that gets written to long-term memory. Unlike ephemeral prompt injection (which resets each session), poisoned memories persist indefinitely and can:

- Corrupt agent behavior across ALL future sessions
- Spread to other agents sharing the same memory namespace
- Execute days or weeks later, triggered by unrelated interactions
- Survive undetected because the agent appears to function normally

**Current gaps:**
- **AgentCore Policy (Cedar)** controls WHO can access memory, but not WHAT gets written
- **AgentCore Guardrails** filter model outputs but don't inspect memory write operations
- **AgentCore Gateway** provides the interception point but no built-in memory validation

The attack surface is amplified by AgentCore Memory's shared namespace feature — where a single poisoned write in a shared namespace can influence every agent that reads from it.

## When to use this pattern

- You have agents on AgentCore Runtime that use persistent memory (short-term or long-term)
- Your agents share memory namespaces across sessions or across agents
- You handle sensitive data where corrupted agent behavior could cause real harm (financial, healthcare, PII)
- You need defense-in-depth beyond Cedar policies and Guardrails

## When NOT to use this pattern

- Agents with no persistent memory (stateless, single-turn only)
- Development/testing environments where memory writes are not production-sensitive
- Extremely latency-sensitive paths where even 26ms additional latency is unacceptable

## Prerequisites

- Amazon Bedrock AgentCore Runtime with Memory enabled
- AgentCore Gateway configured (for interceptor attachment)
- AgentCore Policy (Cedar) configured
- AWS Lambda, Amazon DynamoDB, Amazon SNS
- Amazon Bedrock model access (Titan Embeddings v2)
- AWS CDK v2 for deployment

## Architecture

### Component Overview

```
Agent → Memory Write Request → AgentCore Gateway
                                      │
                              ┌───────▼────────┐
                              │  Pre-Write     │
                              │  Interceptor   │
                              │  (Lambda)      │
                              └───────┬────────┘
                                      │
                              ┌───────▼────────┐
                              │  4-Signal      │
                              │  Validation    │
                              │  Engine        │
                              └───────┬────────┘
                                      │
                     ┌────────────────┼────────────────┐
                     ▼                ▼                ▼
               ┌──────────┐   ┌────────────┐   ┌──────────┐
               │  ALLOW   │   │ QUARANTINE │   │   DENY   │
               │  Score<40│   │ Score 40-70│   │ Score>70 │
               └────┬─────┘   └─────┬──────┘   └────┬─────┘
                    │               │                │
                    ▼               ▼                ▼
              AgentCore        Quarantine         Block +
              Memory           Namespace         SNS Alert
              (target ns)     (isolated)
```

### Detection Signals

| Signal | Weight | What It Detects | Technique |
|--------|--------|-----------------|-----------|
| Semantic Drift | 30% | Write content unrelated to session context | Titan Embeddings cosine similarity |
| Instruction Pattern | 35% | Embedded system-prompt-like commands | Regex pattern matching (14 patterns) |
| Namespace Boundary | 20% | Writes targeting protected namespaces | Namespace prefix matching + session context |
| Write-Rate Anomaly | 15% | Burst writes indicating automation | DynamoDB counter vs. historical baseline |

### Namespace Trust Hierarchy

```
system/          → No runtime writes (deployment-only)
user/{userId}/   → Standard validation (4-signal, threshold 40/70)
shared/          → Enhanced validation (stricter threshold: 30/60)
quarantine/      → Validator-only write access; agents cannot read
```

## Implementation

### Step 1: Deploy Infrastructure

The CDK stack (see `infrastructure/cdk-stack.ts`) provisions:
- Validation Lambda with provisioned concurrency
- DynamoDB tables (write-rate tracking + audit log)
- SNS topic for alerts

```bash
cd infrastructure && cdk deploy
```

### Step 2: Configure Gateway Interceptor

Attach the deployed Lambda as a pre-write interceptor on AgentCore Gateway:

```typescript
// AgentCore Gateway configuration
{
  "interceptors": {
    "memory": {
      "preWrite": {
        "lambdaArn": "<ValidatorFunctionArn from CDK output>",
        "timeoutMs": 5000,
        "failurePolicy": "ALLOW"  // Fail-open for availability
      }
    }
  }
}
```

### Step 3: Apply Cedar Policies

Deploy the Cedar policies (see `policies/namespace-isolation.cedar`) to AgentCore Policy. These enforce namespace-level access control as a secondary defense layer.

### Step 4: Configure Alerts

Subscribe your security team's email/Slack/PagerDuty to the SNS topic for QUARANTINE and DENY notifications.

## Performance

| Metric | Value |
|--------|-------|
| Warm-path latency | ~26ms |
| Cold-start latency | ~230ms (mitigated with provisioned concurrency) |
| DynamoDB read | ~5ms (sub-3ms with DAX) |
| Embedding generation | ~12ms (Titan Embed v2, 256 dimensions) |
| Memory overhead | 512MB Lambda |

## Cost Considerations

- Lambda: ~$0.0000067 per invocation (512MB, 100ms)
- DynamoDB: On-demand pricing, minimal reads/writes per memory operation
- Titan Embeddings: $0.00002 per 1K tokens (2 invocations per validation)
- SNS: Standard messaging rates (only on QUARANTINE/DENY)

For an agent fleet generating 10,000 memory writes/day: **~$2.50/day** total validation cost.

## Limitations

- **Embedding-based detection is not foolproof**: Sophisticated attacks that maintain topical relevance while embedding subtle instructions may evade semantic drift detection
- **Regex patterns require updates**: New injection techniques may not match existing patterns; periodic pattern updates recommended
- **Cold starts**: First invocation after idle period adds ~230ms; mitigated with provisioned concurrency but adds cost
- **Fail-open design**: If the Lambda errors out, writes proceed unvalidated (availability over security trade-off — configurable)

## Related Resources

- [AWS Docs: AgentCore Memory Best Practices](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/best-practices.html)
- [AWS Blog: Organizing Agents' Memory at Scale — Namespace Design Patterns](https://aws.amazon.com/blogs/machine-learning/organizing-agents-memory-at-scale-namespace-design-patterns-in-agentcore-memory/)
- [AWS Blog: Secure AI Agents with Policy and Lambda Interceptors in AgentCore Gateway](https://aws.amazon.com/blogs/machine-learning/secure-ai-agents-with-policy-and-lambda-interceptors-in-amazon-bedrock-agentcore-gateway/)
- [Palo Alto Unit 42: When AI Remembers Too Much](https://unit42.paloaltonetworks.com/indirect-prompt-injection-poisons-ai-longterm-memory/)
- [OWASP Top 10 for Agentic Applications 2026](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
