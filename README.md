# 🛡️ NetSecure Assess

> **Educational Network Security & Governance Workspace**
>
> A full-stack defensive cyber laboratory combining safe target discovery, configuration findings management, privacy-preserving traffic metadata, explainable risk scoring, NIST/CIS control governance, and automated 15-page PDF technical report generation.

---

[![Python](https://img.shields.io/badge/Python-3.12%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.116.1-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19.0-61DAFB.svg?logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-3178C6.svg?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg?logo=docker&logoColor=white)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Safety](https://img.shields.io/badge/Policy-Defensive--Only-brightgreen.svg)]()

---

## 📋 Overview

**NetSecure Assess** is designed for university students, cybersecurity researchers, and defensive analysts to learn network security posture assessment, risk scoring, and governance compliance in a safe, controlled environment.

The platform is **strictly defensive**: it contains **no exploitation, credential attacks, malware, denial-of-service, persistence, or data-exfiltration features**. All findings represent automated baseline hypotheses that require human validation.

---

## ✨ Key Features

- **🔒 Bounded TCP-Connect Scanner**: Target normalization using Python's `ipaddress` module. Accepts only private IPv4 (RFC1918) and localhost with hard host, port, concurrency, and time ceilings.
- **📊 Transparent 0–100 Risk Scoring Engine**: Explainable weighted risk calculation based on technical severity (30%), detection confidence (10%), asset criticality (15%), exposure (10%), likelihood (10%), and business impact (15%).
- **🏛️ 14-Category Governance Control Framework**: Informed by NIST CSF and CIS Controls (AM-01 through TP-01) with automated maturity index calculation (scale 0.0 to 5.0).
- **📑 Automated 15-Page PDF Technical Report Generator**: Custom `fpdf2` report engine generating comprehensive, executive-ready PDF snapshots complete with cover page, TOC, asset inventories, finding deep-dives, control posture evaluations, and threat models.
- **🌐 Privacy-Preserving Traffic Metadata Import**: Accepts PCAP/PCAPNG uploads while strictly discarding packet payloads and retaining only connection metadata.
- **🚨 Explainable Intrusion Alerts**: Constrained JSON rule detection engine for cleartext protocols and connection bursts.
- **⚡ Modern Full-Stack Architecture**: React 19 SPA + TypeScript + Vite frontend coupled with a FastAPI + SQLAlchemy backend API.

---

## 🏗️ System Architecture

```text
               ┌───────────────────────────────────────────┐
               │    React 19 + TypeScript + Vite SPA       │
               └─────────────────────┬─────────────────────┘
                                     │ REST / JWT Auth
               ┌─────────────────────▼─────────────────────┐
               │      FastAPI Modular Monolith API         │
               ├───────────────────────────────────────────┤
               │ • Auth & Role-Based Access Control (RBAC) │
               │ • Project Authorization Boundaries        │
               │ • Bounded Async TCP-Connect Scanner       │
               │ • Privacy-Preserving Traffic Importer     │
               │ • 14-Category Control Assessment Engine   │
               │ • 15-Page Technical PDF Report Service    │
               └─────────────────────┬─────────────────────┘
                                     │ SQLAlchemy ORM
               ┌─────────────────────▼─────────────────────┐
               │   SQLite (Dev) / PostgreSQL (Production)  │
               └───────────────────────────────────────────┘
```

---

## 🚀 Quick Start (Docker Compose)

The fastest way to deploy NetSecure Assess is with Docker Compose:

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Arsh0x/netsecure-assess.git
   cd netsecure-assess
   ```

2. **Copy Environment Variables**:
   ```bash
   cp .env.example .env
   ```

3. **Build & Start Containers**:
   ```bash
   docker compose up --build
   ```

4. **Access the Web Workspace**:
   - **Frontend UI**: `http://localhost:8081`
   - **FastAPI OpenAPI UI**: `http://localhost:8000/docs`

---

## 💻 Local Development Setup

### Backend (Python 3.12+)

```bash
cd backend

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start FastAPI server
uvicorn app.main:app --reload
```

### Frontend (Node 22+)

In a separate terminal:

```bash
cd frontend

# Install node dependencies
npm install

# Start Vite dev server
npm run dev
```

---

## 🔑 Demo Access Credentials

When starting in development mode (`DEMO_MODE=true`), the system auto-seeds an in-memory laboratory project (`Campus Lab Baseline` on `10.20.0.0/24`) with four simulated assets and initial security observations:

| Role | Email | Password | Scope & Permissions |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin@netsecure.local` | `AdminDemo!2026` | Full platform control, user management, audit log access |
| **Researcher** | `researcher@netsecure.local` | `ResearchDemo!2026` | Project creation, target scans, findings & report exports |
| **Student** | `student@netsecure.local` | `StudentDemo!2026` | Read-only project view, finding review, self-assessments |

---

## 📄 Generating the 15-Page Technical PDF Report

NetSecure Assess includes an automated, self-contained Python script to generate an exhaustive **15-page security & system report**:

```bash
# Run report generator using backend environment
backend/.venv/bin/python scripts/generate_pdf_report.py
```

Output: `NetSecure_Assess_Security_Report.pdf` (in project root)

### Report Structure Overview:
- **Page 1**: Title Cover Banner & Document Metadata
- **Page 2**: Table of Contents & Revision Sign-offs
- **Page 3**: Executive Summary & High-Level Metric Cards
- **Page 4**: Product Requirements & User Role Matrix
- **Page 5**: System Architecture & Technology Stack
- **Page 6**: Scanner Safety Ceilings & Target Normalization
- **Page 7**: Database Schema & Entity Relationships
- **Page 8**: REST API Endpoint Directory & JWT Security
- **Page 9**: Discovered Asset Inventory & Exposed Services
- **Page 10**: Vulnerability Findings & 0–100 Risk Scoring Model
- **Page 11**: 14-Category Governance Control Assessment
- **Page 12**: Traffic Metadata & Intrusion Detection Alerts
- **Page 13**: Threat Model & Trust Boundaries
- **Page 14**: Containerization & Production Hardening Checklist
- **Page 15**: Verification Test Suite & Operational Guide

---

## 🛡️ Safety Ceilings & Defensive Policy

To prevent unintended scanning or network disruption, NetSecure Assess enforces strict server-side ceilings:

| Safety Parameter | Default Ceiling | Enforcement Mechanism |
| :--- | :--- | :--- |
| **Target Normalization** | Private IPv4 & Localhost | Python `ipaddress` RFC1918 validation |
| **CIDR Host Ceiling** | 64 Hosts Max (`/26`) | Strict network size check before execution |
| **Port Ceiling** | 256 Ports Max | Caps requested port range |
| **Socket Concurrency** | 16 Sockets Max | Bounded `asyncio` TCP connect worker |
| **Scan Timeout** | 5 Minutes Hard Budget | Hard task cancellation & deadline monitoring |
| **Audit Trail** | Immutable Append-Only | Database security log for all lifecycle events |

---

## 🧪 Testing & Verification

Run backend unit, API, permission, and target safety tests:

```bash
cd backend
pytest -q
```

Run frontend production build & type checks:

```bash
cd frontend
npm run build
```

Run Playwright browser E2E smoke tests:

```bash
cd frontend
npx playwright install chromium
npm run test:e2e
```

---

## 📜 License & Disclaimer

Distributed under the **MIT License**. See `LICENSE` for details.

*Disclaimer: NetSecure Assess is designed strictly for educational and authorized defensive security assessments. Users are responsible for ensuring compliance with all local laws and organizational security policies.*
