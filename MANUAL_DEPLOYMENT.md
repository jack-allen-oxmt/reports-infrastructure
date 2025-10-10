# Manual Deployment Guide

Quick reference for setting up the usage analytics infrastructure from scratch.

---

## Prerequisites

- AWS Console access with permissions for OpenSearch, Lambda, IAM, CloudWatch
- Application CloudWatch Log Group name
- Python 3.11+ for local testing (optional)

---

## Step 1: Create OpenSearch Domain

**AWS Console → OpenSearch Service → Create domain**

**Configuration:**
- **Domain name:** `usage-analytics-<environment>`
- **Deployment type:** Dev/test
- **Engine version:** OpenSearch 3.1
- **Instance type:** t3.small.search (dev)
- **Number of nodes:** 1
- **EBS storage:** 20 GB per node (adjust based on log volume)
- **Network:** Public access
- **Fine-grained access control:** Enabled
    - **Create master user:** Set username/password
- **Access policy:** Start with open access, will restrict later

**Create domain** (takes 15-20 minutes)

**Note the endpoint:** `search-usage-analytics-xyz.region.es.amazonaws.com`

---

## Step 2: Configure OpenSearch

### 2.1 Create Index Templates

**OpenSearch Dashboards → Dev Tools**

**Session summaries template:**
```json
PUT _index_template/session-summaries-template
```
Copy contents from `opensearch/index_templates/session_summaries.json` and paste

**Request events template:**
```json
PUT _index_template/request-events-template
```
Copy contents from `opensearch/index_templates/request_events.json` and paste

**Verify:**
```json
GET _index_template/*-template
```

---

## Step 3: Create IAM Role

**IAM Console → Roles → Create role**

**Trust policy:**
- **Trusted entity:** AWS service → Lambda

**Permissions:**
- Attach: `AWSLambdaBasicExecutionRole`
- Create custom policy: `OpenSearchAccessPolicy`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "es:ESHttpPost",
        "es:ESHttpPut"
      ],
      "Resource": "arn:aws:es:<REGION>:<ACCOUNT-ID>:domain/<DOMAIN-NAME>/*"
    }
  ]
}
```

**Role name:** `usage-analytics-lambda-role`

**Copy the Role ARN** for next step

---

## Step 4: Update OpenSearch Access Policy

**OpenSearch Console → Domain → Security configuration → Edit**

Add Lambda role to access policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<ACCOUNT-ID>:role/usage-analytics-lambda-role"
      },
      "Action": "es:*",
      "Resource": "arn:aws:es:<REGION>:<ACCOUNT-ID>:domain/<DOMAIN-NAME>/*"
    }
  ]
}
```

---

## Step 5: Deploy Lambda Function

**Lambda Console → Create function**

**Configuration:**
- **Function name:** `usage-analytics-log-processor`
- **Runtime:** Python 3.11
- **Execution role:** Use existing → `usage-analytics-lambda-role`

**Upload code:**
- Copy `lambda/lambda_function.py` into the inline editor

**Configuration:**
- **Memory:** 256 MB
- **Timeout:** 1 min

**Environment variables:**
- `OPENSEARCH_ENDPOINT`: `search-usage-analytics-xyz.region.es.amazonaws.com` (no https://)
- `AWS_REGION`: `ap-southeast-2` (or your region)

**Test:**
- Create test event using `lambda/tests/test_events/test_basic.json`
- Click **Test**
- Expected: `"statusCode": 200`

---

## Step 6: Add Lambda Permission

**Lambda → Configuration → Permissions → Resource-based policy statements → Add permissions**

- **Statement ID:** `CloudWatchLogsInvoke`
- **Principal:** `logs.amazonaws.com`
- **Source ARN:** `arn:aws:logs:<REGION>:<ACCOUNT-ID>:log-group:<LOG-GROUP-NAME>:*`
- **Action:** `lambda:InvokeFunction`

---

## Step 7: Create CloudWatch Subscription

**CloudWatch Console → Log groups → Select your application log group**

**Actions → Create subscription filter**

- **Destination:** Lambda function
- **Lambda function:** `usage-analytics-log-processor`
- **Filter name:** `usage-analytics-subscription`
- **Filter pattern:** (empty - process all logs)

**Create**

---

## Step 8: Verify

**Generate activity** in your application (log in, navigate modules)

**Check Lambda logs:**
```bash
aws logs tail /aws/lambda/usage-analytics-log-processor --follow
```

Expected:
```
Successfully sent X/X event documents to OpenSearch
Updated X/X session summaries
```

**Check OpenSearch:**
```json
GET session-summaries/_count
GET request-events-*/_count
```

Both should return `count > 0`

---

## Step 9: Create Index Pattern (Optional)

**For dashboards:**

OpenSearch Dashboards → Stack Management → Index Patterns → Create

- **Index pattern:** `session-summaries`
- **Time field:** `last_updated`

---

## Quick Reference

| Component | Name | Purpose |
|-----------|------|---------|
| OpenSearch Domain | `usage-analytics-<env>` | Data storage |
| Lambda Function | `usage-analytics-log-processor` | Log processing |
| IAM Role | `usage-analytics-lambda-role` | Lambda permissions |
| Subscription Filter | `usage-analytics-subscription` | Log streaming |
| Index Template | `session-summaries-template` | Schema definition |
| Index Template | `request-events-template` | Schema definition |

---

## What's Next?

1. **Create dashboards** - Set up Dashboards as per client needs
2. **Set up monitoring** - CloudWatch alarms for Lambda errors
3. **Plan backfill** - Import historical data from S3
4. **Terraform migration** - Codify infrastructure

