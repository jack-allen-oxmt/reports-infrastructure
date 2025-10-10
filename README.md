# Usage Analytics Reporting Infrastructure

> Real-time usage analytics pipeline for tracking user sessions, module usage, and system interactions across the IronMan platform.

---

## Overview

This infrastructure replaces manual PDF report generation (IM-8136) with an automated, real-time analytics pipeline. It captures application logs from CloudWatch, processes them through Lambda, aggregates session data, and stores everything in OpenSearch for analysis and visualization. The system provides immediate insights into user behavior, module popularity, and system usage patterns.

---

## Quick Start

### Prerequisites
- AWS account with Lambda, CloudWatch, and OpenSearch permissions
- OpenSearch Domain (v3.1+) provisioned
- CloudWatch Log Group with application logs
- Python 3.11+ (for local testing)

---

## Architecture

```
┌─────────────────┐
│  Application    │
│  (IronMan)      │
└────────┬────────┘
         │ Logs
         ▼
┌─────────────────┐
│  CloudWatch     │
│  Logs           │
└────────┬────────┘
         │ Stream (Subscription Filter)
         ▼
┌─────────────────┐      ┌──────────────────────────┐
│  Lambda         │────▶ │  OpenSearch              │
│  Processor      │      │  ┌────────────────────┐  │
│                 │      │  │ session-summaries  │  │
│  • Parse logs   │      │  │ (aggregated)       │  │
│  • Filter noise │      │  └────────────────────┘  │
│  • Aggregate    │      │  ┌────────────────────┐  │
│  • Enrich       │      │  │ request-events-*   │  │
│                 │      │  │ (daily indices)    │  │
└─────────────────┘      │  └────────────────────┘  │
                         └──────────┬───────────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │  OpenSearch          │
                         │  Dashboards          │
                         │  • Visualizations    │
                         │  • Reports           │
                         │  • CSV Exports       │
                         └──────────────────────┘
```

---

## Key Features

### ✅ Automated Data Collection
- Real-time log processing from CloudWatch
- Automatic session aggregation with deduplication
- No manual intervention required

### 📊 Comprehensive Metrics
Tracks all requirements from IM-8136:
- ✅ Unique users per day
- ✅ Sessions per user per day
- ✅ Session duration (average, distribution)
- ✅ Module usage (sessions per module)
- ✅ Site usage (sessions per site token)
- ✅ Asset type usage (sessions per asset type)

---

## Data Model

### Session Summaries
Aggregated session-level metrics:

| Field | Type | Description |
|-------|------|-------------|
| `session_id` | keyword | Unique session identifier |
| `user` | keyword | User email address |
| `modules` | keyword[] | Modules visited (deduplicated) |
| `paths` | keyword[] | URLs accessed (deduplicated) |
| `assetTypes` | keyword[] | Asset types filtered (deduplicated) |
| `siteTokens` | keyword[] | Sites accessed (deduplicated) |
| `start_time` | date | Session start timestamp |
| `end_time` | date | Session end timestamp |
| `duration_seconds` | float | Total session duration |
| `event_count` | integer | Number of requests in session |
| `last_updated` | date | Last time session was updated |

### Request Events
Individual request-level data (stored in daily indices):

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | date | Request timestamp |
| `session_id` | keyword | Session identifier |
| `user` | keyword | User email |
| `path` | keyword | Request URL path |
| `method` | keyword | HTTP method (GET, POST, etc.) |
| `status_code` | integer | HTTP response code |
| `response_time` | integer | Response time in milliseconds |
| `module` | keyword | Module name (if page-beacon) |
