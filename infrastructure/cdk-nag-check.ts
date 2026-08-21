/**
 * cdk-nag validation script
 * Run: npx tsx infrastructure/cdk-nag-check.ts
 */

import * as cdk from "aws-cdk-lib";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as sns from "aws-cdk-lib/aws-sns";
import * as iam from "aws-cdk-lib/aws-iam";
import { Construct } from "constructs";
import { AwsSolutionsChecks } from "cdk-nag";

class MemoryPoisoningDefenseStackForNag extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const rateTable = new dynamodb.Table(this, "WriteRateTable", {
      tableName: "agentcore-memory-write-rate",
      partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.ON_DEMAND,
      timeToLiveAttribute: "ttl",
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const auditTable = new dynamodb.Table(this, "AuditTable", {
      tableName: "agentcore-memory-audit",
      partitionKey: { name: "pk", type: dynamodb.AttributeType.STRING },
      sortKey: { name: "sk", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.ON_DEMAND,
      timeToLiveAttribute: "ttl",
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const alertTopic = new sns.Topic(this, "MemoryAlertTopic", {
      topicName: "agentcore-memory-poisoning-alerts",
      displayName: "AgentCore Memory Poisoning Alerts",
    });

    const validationLambda = new lambda.Function(this, "MemoryValidator", {
      functionName: "agentcore-memory-validator",
      code: lambda.Code.fromInline("exports.handler = async () => {};"),
      handler: "index.handler",
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

    const version = validationLambda.currentVersion;
    new lambda.Alias(this, "MemoryValidatorAlias", {
      aliasName: "live",
      version,
      provisionedConcurrentExecutions: 5,
    });

    rateTable.grantReadWriteData(validationLambda);
    auditTable.grantWriteData(validationLambda);
    alertTopic.grantPublish(validationLambda);

    validationLambda.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["bedrock:InvokeModel"],
        resources: [
          `arn:aws:bedrock:${this.region}::foundation-model/amazon.titan-embed-text-v2:0`,
        ],
      })
    );
  }
}

const app = new cdk.App();
const stack = new MemoryPoisoningDefenseStackForNag(app, "MemoryPoisoningDefenseStack", {
  env: { account: "123456789012", region: "us-east-1" },
});

cdk.Aspects.of(app).add(new AwsSolutionsChecks());
app.synth();
