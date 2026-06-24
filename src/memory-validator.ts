/**
 * Memory Write Validation Lambda for Amazon Bedrock AgentCore
 *
 * This Lambda function is configured as a pre-write interceptor on AgentCore Gateway.
 * It evaluates every memory write request against 4 detection signals and returns
 * an ALLOW, QUARANTINE, or DENY decision.
 */

import {
  BedrockRuntimeClient,
  InvokeModelCommand,
} from "@aws-sdk/client-bedrock-runtime";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";
import { SNSClient, PublishCommand } from "@aws-sdk/client-sns";

// --- Types ---

interface MemoryWriteEvent {
  requestContext: {
    agentId: string;
    sessionId: string;
    userId: string;
    sourceNamespace: string;
  };
  memoryWrite: {
    targetNamespace: string;
    content: string;
    metadata?: Record<string, string>;
  };
  sessionContext: {
    recentMessages: string[];
  };
}

interface ValidationResult {
  decision: "ALLOW" | "QUARANTINE" | "DENY";
  scores: SignalScores;
  compositeScore: number;
  redirectNamespace?: string;
  reason?: string;
}

interface SignalScores {
  semanticDrift: number;
  instructionPattern: number;
  namespaceBoundary: number;
  writeRateAnomaly: number;
}

// --- Configuration ---

const THRESHOLDS = {
  ALLOW_MAX: 35,
  QUARANTINE_MAX: 60,
} as const;

const WEIGHTS = {
  semanticDrift: 0.4,
  instructionPattern: 0.25,
  namespaceBoundary: 0.25,
  writeRateAnomaly: 0.1,
} as const;

const PROTECTED_NAMESPACES = ["system/", "system"];
const ELEVATED_NAMESPACES = ["shared/", "shared"];
const WRITE_RATE_WINDOW_SECONDS = 60;
const WRITE_RATE_THRESHOLD_MULTIPLIER = 5;

// --- Clients (initialized outside handler for warm starts) ---

const bedrockClient = new BedrockRuntimeClient({});
const dynamoClient = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const snsClient = new SNSClient({});

const RATE_TABLE = process.env.RATE_TABLE_NAME!;
const AUDIT_TABLE = process.env.AUDIT_TABLE_NAME!;
const ALERT_TOPIC_ARN = process.env.ALERT_TOPIC_ARN!;
const EMBEDDING_MODEL_ID = process.env.EMBEDDING_MODEL_ID || "amazon.titan-embed-text-v2:0";

// --- Handler ---

export const handler = async (event: MemoryWriteEvent): Promise<ValidationResult> => {
  const { requestContext, memoryWrite, sessionContext } = event;

  // Run all 4 signals in parallel
  const [semanticDrift, instructionPattern, namespaceBoundary, writeRateAnomaly] =
    await Promise.all([
      scoreSemanticDrift(memoryWrite.content, sessionContext.recentMessages),
      scoreInstructionPattern(memoryWrite.content),
      scoreNamespaceBoundary(memoryWrite.targetNamespace, requestContext),
      scoreWriteRateAnomaly(requestContext.agentId, requestContext.sessionId),
    ]);

  const scores: SignalScores = {
    semanticDrift,
    instructionPattern,
    namespaceBoundary,
    writeRateAnomaly,
  };

  // Compute weighted composite score
  const compositeScore = Math.round(
    scores.semanticDrift * WEIGHTS.semanticDrift +
    scores.instructionPattern * WEIGHTS.instructionPattern +
    scores.namespaceBoundary * WEIGHTS.namespaceBoundary +
    scores.writeRateAnomaly * WEIGHTS.writeRateAnomaly
  );

  // Decision
  let decision: ValidationResult["decision"];
  let redirectNamespace: string | undefined;
  let reason: string | undefined;

  if (compositeScore <= THRESHOLDS.ALLOW_MAX) {
    decision = "ALLOW";
  } else if (compositeScore <= THRESHOLDS.QUARANTINE_MAX) {
    decision = "QUARANTINE";
    redirectNamespace = `quarantine/${requestContext.agentId}/${Date.now()}`;
    reason = buildReason(scores);
  } else {
    decision = "DENY";
    reason = buildReason(scores);
  }

  // Record write rate
  await recordWrite(requestContext.agentId, requestContext.sessionId);

  // Async post-decision actions (non-blocking)
  if (decision !== "ALLOW") {
    await Promise.all([
      publishAlert(decision, compositeScore, reason!, requestContext, memoryWrite),
      auditLog(decision, compositeScore, scores, requestContext, memoryWrite),
    ]);
  }

  return { decision, scores, compositeScore, redirectNamespace, reason };
};

// --- Signal 1: Semantic Drift ---

async function scoreSemanticDrift(
  writeContent: string,
  recentMessages: string[]
): Promise<number> {
  if (!recentMessages.length) return 50; // No context = moderate suspicion

  const sessionContext = recentMessages.slice(-5).join(" ");

  const [writeEmbedding, contextEmbedding] = await Promise.all([
    getEmbedding(writeContent),
    getEmbedding(sessionContext),
  ]);

  const similarity = cosineSimilarity(writeEmbedding, contextEmbedding);

  // similarity ranges: 1.0 = identical, 0.0 = unrelated, -1.0 = opposite
  // Score: high similarity = low risk, low similarity = high risk
  if (similarity >= 0.6) return 0;
  if (similarity >= 0.4) return 25;
  if (similarity >= 0.3) return 50;
  if (similarity >= 0.2) return 75;
  return 100;
}

async function getEmbedding(text: string): Promise<number[]> {
  const response = await bedrockClient.send(
    new InvokeModelCommand({
      modelId: EMBEDDING_MODEL_ID,
      contentType: "application/json",
      accept: "application/json",
      body: JSON.stringify({
        inputText: text.slice(0, 8000), // Titan limit
        dimensions: 256,
        normalize: true,
      }),
    })
  );

  const result = JSON.parse(new TextDecoder().decode(response.body));
  return result.embedding;
}

function cosineSimilarity(a: number[], b: number[]): number {
  let dotProduct = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < a.length; i++) {
    dotProduct += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
}

// --- Signal 2: Instruction Pattern Detection ---

const INJECTION_PATTERNS: RegExp[] = [
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /you\s+are\s+now\s+a/i,
  /from\s+now\s+on,?\s+(always|never)/i,
  /your\s+new\s+(role|instruction|directive|purpose)\s+is/i,
  /system\s*prompt\s*:/i,
  /\[INST\]|\[\/INST\]|<<SYS>>|<\|im_start\|>/i,
  /do\s+not\s+(reveal|share|tell|disclose)\s+(your|the)\s+(instructions|prompt|system)/i,
  /override\s+(previous|prior|existing)\s+(instructions|rules|constraints)/i,
  /act\s+as\s+(if|though)\s+you\s+(are|were)\s+/i,
  /disregard\s+(all|any|previous)\s+(safety|content|ethical)/i,
  /repeat\s+(the\s+)?(text|words|content)\s+(above|before|earlier)/i,
  /send\s+(all|any|the)\s+(data|information|content)\s+to/i,
  /execute\s+(the\s+following|this)\s+(command|code|script)/i,
  /when(ever)?\s+(anyone|a\s+user|someone)\s+asks/i,
];

async function scoreInstructionPattern(content: string): Promise<number> {
  let matchCount = 0;

  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(content)) {
      matchCount++;
    }
  }

  if (matchCount === 0) return 0;
  if (matchCount === 1) return 60;
  if (matchCount === 2) return 85;
  return 100; // 3+ matches = almost certainly malicious
}

// --- Signal 3: Namespace Boundary Enforcement ---

async function scoreNamespaceBoundary(
  targetNamespace: string,
  context: MemoryWriteEvent["requestContext"]
): Promise<number> {
  // Attempting to write to system namespace = instant high score
  if (PROTECTED_NAMESPACES.some((ns) => targetNamespace.startsWith(ns))) {
    return 100;
  }

  // Writing to shared namespace from a user session = elevated concern
  if (ELEVATED_NAMESPACES.some((ns) => targetNamespace.startsWith(ns))) {
    return 50;
  }

  // Writing to own user namespace = expected behavior
  if (targetNamespace.startsWith(`user/${context.userId}/`)) {
    return 0;
  }

  // Writing to another user's namespace = suspicious
  if (targetNamespace.startsWith("user/") && !targetNamespace.startsWith(`user/${context.userId}/`)) {
    return 90;
  }

  return 20; // Unknown namespace structure
}

// --- Signal 4: Write-Rate Anomaly ---

async function scoreWriteRateAnomaly(
  agentId: string,
  sessionId: string
): Promise<number> {
  const key = `${agentId}#${sessionId}`;
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - WRITE_RATE_WINDOW_SECONDS;

  try {
    const result = await dynamoClient.send(
      new GetCommand({
        TableName: RATE_TABLE,
        Key: { pk: key },
      })
    );

    if (!result.Item) return 0; // First write in session

    const recentCount = result.Item.writeCount || 0;
    const baselineRate = result.Item.baselineRate || 3; // Default: 3 writes/minute
    const lastWriteTime = result.Item.lastWriteTime || 0;

    // Reset if outside window
    if (lastWriteTime < windowStart) return 0;

    const ratio = recentCount / baselineRate;

    if (ratio <= 1) return 0;
    if (ratio <= 2) return 15;
    if (ratio <= WRITE_RATE_THRESHOLD_MULTIPLIER) return 40;
    if (ratio <= 10) return 75;
    return 100; // >10x baseline = very likely automated
  } catch {
    return 0; // Fail open on DDB errors for availability
  }
}

// --- Helpers ---

async function recordWrite(agentId: string, sessionId: string): Promise<void> {
  const key = `${agentId}#${sessionId}`;
  const now = Math.floor(Date.now() / 1000);

  await dynamoClient.send(
    new UpdateCommand({
      TableName: RATE_TABLE,
      Key: { pk: key },
      UpdateExpression: "SET writeCount = if_not_exists(writeCount, :zero) + :one, lastWriteTime = :now",
      ExpressionAttributeValues: {
        ":zero": 0,
        ":one": 1,
        ":now": now,
      },
    })
  );
}

function buildReason(scores: SignalScores): string {
  const reasons: string[] = [];
  if (scores.semanticDrift >= 50) reasons.push("high semantic drift from session context");
  if (scores.instructionPattern >= 60) reasons.push("instruction injection patterns detected");
  if (scores.namespaceBoundary >= 50) reasons.push("namespace boundary violation");
  if (scores.writeRateAnomaly >= 40) reasons.push("abnormal write rate");
  return reasons.join("; ") || "composite score exceeded threshold";
}

async function publishAlert(
  decision: string,
  score: number,
  reason: string,
  context: MemoryWriteEvent["requestContext"],
  write: MemoryWriteEvent["memoryWrite"]
): Promise<void> {
  await snsClient.send(
    new PublishCommand({
      TopicArn: ALERT_TOPIC_ARN,
      Subject: `[AgentCore Memory] ${decision}: Agent ${context.agentId}`,
      Message: JSON.stringify({
        decision,
        compositeScore: score,
        reason,
        agentId: context.agentId,
        sessionId: context.sessionId,
        targetNamespace: write.targetNamespace,
        contentPreview: write.content.slice(0, 200),
        timestamp: new Date().toISOString(),
      }, null, 2),
    })
  );
}

async function auditLog(
  decision: string,
  score: number,
  scores: SignalScores,
  context: MemoryWriteEvent["requestContext"],
  write: MemoryWriteEvent["memoryWrite"]
): Promise<void> {
  await dynamoClient.send(
    new PutCommand({
      TableName: AUDIT_TABLE,
      Item: {
        pk: `${context.agentId}#${Date.now()}`,
        sk: context.sessionId,
        decision,
        compositeScore: score,
        signalScores: scores,
        agentId: context.agentId,
        sessionId: context.sessionId,
        userId: context.userId,
        targetNamespace: write.targetNamespace,
        contentHash: Buffer.from(write.content).toString("base64").slice(0, 44),
        timestamp: new Date().toISOString(),
        ttl: Math.floor(Date.now() / 1000) + 90 * 24 * 60 * 60, // 90-day retention
      },
    })
  );
}
