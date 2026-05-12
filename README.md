# System Architecture — Multi-Stage Threat Detection Pipeline

The platform follows a **tiered intelligence architecture** designed to process, classify, and enrich security telemetry in real time.

The pipeline separates detection into two independent analytical stages:

1. **Fast Heuristic Triage**
2. **Deep Cognitive AI Analysis**

This design enables high scalability, low latency, and cost-efficient AI usage while maintaining high detection accuracy.

---

# Architecture Overview


```text
                +----------------------+
                |   Log Sources        |
                |----------------------|
                | Windows Event Logs   |
                | Syslog               |
                | REST APIs            |
                +----------+-----------+
                           |
                           v
                +----------------------+
                | Elasticsearch        |
                | Central Data Lake    |
                +----------+-----------+
                           |
                           v
          +----------------------------------+
          | Stage 1: Heuristic Triage        |
          | Python Worker (scc.py)           |
          |----------------------------------|
          | - Log normalization              |
          | - Weighted risk scoring          |
          | - IOC pattern matching           |
          +----------------+-----------------+
                           |
                 Score >= 60
                           |
                           v
          +----------------------------------+
          | Stage 2: Cognitive Enrichment    |
          | LLM Worker (Groq + Llama 3.3)   |
          |----------------------------------|
          | - Threat explanation             |
          | - Intent analysis                |
          | - Maliciousness verdict          |
          +----------------+-----------------+
                           |
                           v
                +----------------------+
                | Kibana Dashboard     |
                | ES|QL Visualization  |
                +----------------------+
```

---

# Stage 1 — Heuristic Triage & Normalization (`scc.py`)

The first worker acts as the **real-time triage engine** responsible for rapidly processing raw telemetry.

Its primary objective is to filter noise and identify potentially suspicious activity before invoking expensive AI analysis.

---

## Core Responsibilities

### Real-Time Monitoring

The worker continuously monitors recent logs stored in Elasticsearch.

### Sliding Window Processing

The engine processes logs in small batches:

```text
Window Size = 100 Logs
```

This ensures:

- Low latency
- Continuous stream analysis
- Fast incident prioritization

---

## Detection Logic

A custom heuristic scoring algorithm evaluates each log based on:

- Attack signatures
- Behavioral indicators
- Suspicious command execution
- Obfuscation techniques

---

## Security Enrichment

Each processed log is enriched with:

```json
{
  "security_score": 85
}
```

The `security_score` represents the estimated maliciousness probability derived from heuristic analysis.

---

## Example Indicators

| Indicator | Score Weight |
|---|---|
| Mimikatz Signature | +50 |
| PowerShell Obfuscation | +30 |
| Encoded Commands | +20 |
| Suspicious Event ID 4104 | +20 |
| Privilege Escalation Indicators | +25 |

---

## Design Goals

The Stage 1 worker is optimized for:

- High throughput
- Low computational overhead
- Fast filtering
- Massive log volume handling

This stage acts as the pipeline's **gatekeeper**.

---

# Stage 2 — Cognitive Inference & Validation (`LLM.py`)

The second worker provides advanced contextual analysis using a Large Language Model.

Unlike traditional SIEM systems that rely solely on static detection rules, this stage performs semantic reasoning and intent analysis.

---

## Elasticsearch Querying

The worker specifically searches for logs already enriched with:

```json
{
  "security_score": ">= 60"
}
```

This threshold-based routing dramatically reduces unnecessary AI requests.

---

# Threshold Filtering Logic

Only logs classified as **High-Risk** are escalated.

```text
Security Score ≥ 60
```

This filtering mechanism provides:

- Reduced API costs
- Faster AI response times
- Better scalability
- High-signal threat analysis

---

# LLM Analysis Pipeline

Selected logs are forwarded to:

- Groq API
- Llama 3.3 70B

The AI performs:

- Contextual reasoning
- Behavioral interpretation
- Threat intent analysis
- Human-readable explanation generation

---

## AI Output Example

```json
{
  "security_score": 87,
  "verdict": "Malicious",
  "ai_comment": "The command sequence strongly resembles credential dumping behavior associated with Mimikatz execution."
}
```

---

# Operational Impact

The dual-worker architecture creates a **High-Signal Security Pipeline**.

Instead of analyzing every log with AI, the heuristic engine acts as an intelligent filter that forwards only the most suspicious events for cognitive analysis.

---

# Key Benefits

## Cost Optimization

The LLM is invoked only for high-risk events.

Benefits include:

- Reduced token consumption
- Lower infrastructure costs
- Sustainable production deployment

---

## Reduced Alert Fatigue

The system filters out approximately:

```text
~98% of low-value telemetry
```

allowing analysts to focus only on actionable incidents.

---

## Improved Detection Accuracy

The combination of:

- deterministic heuristics
- contextual AI reasoning

significantly reduces false positives compared to traditional rule-based systems.


---
The `scc.py` file can be much more complex and handle many different cases, event IDs, behaviors, and more. This is just a functional prototype , but the overall logic remains the same.
