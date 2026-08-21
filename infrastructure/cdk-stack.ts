/**
 * CDK Stack: Memory Poisoning Defense for AgentCore
 *
 * Deploys the Validation Lambda, DynamoDB tables, SNS topic,
 * and necessary IAM permissions.
 */

import * as cdk from "aws-cdk-lib";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as nodejs from "aws-cdk-lib/aws-lambda-nodejs";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as sns from "aws-cdk-lib/aws-sns";
import * as iam from "aws-cdk-lib/aws-iam";
import { Construct } from "constructs";

export class MemoryPoisoningDefenseStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // --- DynamoDB: Write-Rate Tracking ---
    const rateTable = new dynamodb.Table(this, "WriteRateTable", {
      tableName: "agentcore-memory-write-rate",
      partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.ON_DEMAND,
      timeToLiveAttribute: "ttl",
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // --- DynamoDB: Audit Log ---
    const auditTable = new dynamodb.Table(this, "AuditTable", {
      tableName: "agentcore-memory-audit",
      partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "sk", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.ON_DEMAND,
      timeToLiveAttribute: "ttl",
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // --- SNS: Alert Topic ---
    const alertTopic = new sns.Topic(this, "MemoryAlertTopic", {
      topicName: "agentcore-memory-poisoning-alerts",
      displayName: "AgentCore Memory Poisoning Alerts",
    });

    // --- Lambda: Validation Function ---
    const validationLambda = new nodejs.NodejsFunction(this, "MemoryValidator", {
      functionName: "agentcore-memory-validator",
      entry: "../src/memory-validator.ts",
      handler: "handler",
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: cdk.Duration.seconds(10),
      memorySize: 512,
      environment: {
        RATE_TABLE_NAME: rateTable.tableName,
        AUDIT_TABLE_NAME: auditTable.tableName,
        ALERT_TOPIC_ARN: alertTopic.topicArn,
        EMBEDDING_MODEL_ID: "amazon.titan-embed-text-v2:0",
      },
    });

    // Provisioned concurrency for warm starts
    const version = validationLambda.currentVersion;
    new lambda.Alias(this, "MemoryValidatorAlias", {
      aliasName: "live",
      version,
      provisionedConcurrentExecutions: 5,
    });

    // --- Permissions ---
    rateTable.grantReadWriteData(validationLambda);
    auditTable.grantWriteData(validationLambda);
    alertTopic.grantPublish(validationLambda);

    // Bedrock Titan Embeddings access
    validationLambda.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["bedrock:InvokeModel"],
        resources: [
          `arn:aws:bedrock:${this.region}::foundation-model/amazon.titan-embed-text-v2:0`,
        ],
      })
    );

    // --- Outputs ---
    new cdk.CfnOutput(this, "ValidatorFunctionArn", {
      value: validationLambda.functionArn,
      description: "ARN of the Memory Validation Lambda — configure as AgentCore Gateway interceptor",
    });

    new cdk.CfnOutput(this, "AlertTopicArn", {
      value: alertTopic.topicArn,
      description: "Subscribe to this topic for memory poisoning alerts",
    });

    new cdk.CfnOutput(this, "AuditTableName", {
      value: auditTable.tableName,
      description: "DynamoDB table storing QUARANTINE/DENY audit logs",
    });
  }
}
