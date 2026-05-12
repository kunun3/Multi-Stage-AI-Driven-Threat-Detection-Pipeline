# Multi-Stage AI-Driven Threat Detection Pipeline

## Overview

The **Multi-Stage AI-Driven Threat Detection Pipeline** is an automated SOC (Security Operations Center) framework designed to combine traditional heuristic threat detection with advanced Large Language Models (LLMs).

The project addresses two critical challenges in modern cybersecurity:

- **Alert Fatigue** caused by massive volumes of low-value security alerts
- **High AI Operational Costs** due to excessive token consumption

To solve these problems, the pipeline implements a **multi-stage triage architecture** that filters approximately **98% of benign or low-priority events** before forwarding only high-risk incidents to an AI analysis engine.

The result is a scalable, cost-efficient, and context-aware threat detection system capable of identifying sophisticated attack techniques while minimizing false positives.

---

# Features

- Real-time log ingestion and normalization
- Weighted heuristic threat scoring
- AI-powered contextual threat analysis
- Elasticsearch-based centralized storage
- Kibana dashboards for live monitoring
- ES|QL-powered incident filtering
- Cross-platform schema normalization
- Cost-efficient AI routing logic

---

# Architecture

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
