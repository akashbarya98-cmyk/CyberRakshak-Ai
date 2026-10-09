# CyberRakshak AI — Cybersecurity Intelligence Platform

CyberRakshak AI is a full-stack cybersecurity intelligence platform providing personal scam detection, passive business security posture assessments, interactive cyber risk correlation graphs, and an AI Security Copilot.

---

## Architecture Overview

- **Frontend:** React 19 SPA with TypeScript, Tailwind CSS, Lucide icons, responsive sidebar and dashboard layout.
- **Backend:** Node.js Express server with Vite middleware integration in development, running on port 3000.
- **AI Engine:** Google Gemini (`gemini-3.8-flash` via modern `@google/genai` SDK) for grounded explanations and multimodal OCR. All API keys remain strictly server-side.
- **Persistence:** Atomically written, file-backed JSON database (`data/cyberrakshak_db.json`) supporting schema migrations, logical multi-workspace isolation (`ws-personal` and `ws-business`), and audit logs.
- **Security Engine:**
  - Deterministic risk prioritization formula:  
    `Risk = (0.30 × Severity) + (0.25 × Impact) + (0.20 × Exposure) + (0.15 × Confidence) + (0.10 × Urgency)`
  - Full-spectrum SSRF Guard restricting loopback, RFC1918 private subnets, cloud metadata (169.254.169.254), IPv6 unique-local/link-local, non-standard ports, and DNS rebinding.
  - Passive TLS port 443 certificate handshakes and HTTP security header inspections (HSTS, CSP, X-Frame-Options) without intrusive or destructive payloads.
  - Explicit owner authorization check prior to executing any external business domain scan.

---

## Quick Start & Setup

### 1. Installation
Install project dependencies:
```bash
npm install
```

### 2. Environment Variables
Create your local `.env` file based on `.env.example`:
```bash
cp .env.example .env
```

| Variable | Required | Description |
|---|---|---|
| `GEMINI_API_KEY` | Optional | Google Gemini API key for Security Copilot and OCR. If omitted, expert deterministic cybersecurity advisories are provided. |
| `APP_URL` | Optional | The public URL of the application. |
| `PORT` | Optional | Server port (default: `3000`). |
| `THREAT_INTELLIGENCE_API_KEY` | Optional | External Google Safe Browsing / Web Risk API key for live feed querying. If omitted, deterministic local lookalike & heuristic feeds are used. |

### 3. Run Development Server
```bash
npm run dev
```
The server will start on `http://0.0.0.0:3000`.

### 4. Run Automated Tests
```bash
npm test
```
Executes all 39 tests spanning SSRF protection, risk calculation math, scam heuristic analyzers, owner authorization, workspace scoping, and persistence.

### 5. Build for Production
```bash
npm run build
npm start
```

---

## Security Controls & Policies

1. **SSRF Guard (`server/ssrfGuard.ts`):**
   - Validates all outbound host targets prior to making HTTP requests.
   - Blocks private IPv4 CIDR blocks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `100.64.0.0/10`).
   - Blocks IPv6 loopback (`::1`), link-local (`fe80::/10`), unique-local (`fc00::/7`), and IPv4-mapped IPv6.
   - Enforces pre-flight DNS resolution of all A and AAAA records to block DNS rebinding.
   - Enforces maximum redirect limits (3 hops) with re-validation on each jump.
   - Imposes 4-second socket timeouts and a 512KB response body size limit.

2. **Personal Scam Analysis Workflow (`server/scamEngine.ts`):**
   - Sanitizes raw inputs, strips unicode control characters, and enforces character limits.
   - Extracts structured indicators: URLs, domain names, 10-digit Indian mobile numbers (+91), and UPI payment addresses (`@okaxis`, `@paytm`, `@ybl`, etc.).
   - Applies deterministic rule matching against urgent coercive tactics, fee solicitations, and credential harvesting.
   - Expresses explicit uncertainty notes when content is ambiguous or lacks corroborating evidence.

3. **Business Security Assessment Engine (`server/businessEngine.ts`):**
   - Rejects unauthorized scan attempts unless the user explicitly checks the authorization confirmation.
   - Probes TLS certificate validity and days until expiration via a non-intrusive handshake on port 443.
   - Probes HTTP headers for HSTS, CSP, and X-Frame-Options.
   - Explicitly records `checksUnavailable` when network timeouts occur without fabricating false vulnerabilities.

4. **Cyber Risk Graph (`server/riskGraphEngine.ts` & `src/components/graph/CyberRiskGraphView.tsx`):**
   - Correlates domains, assets, findings, and threat indicators in real time.
   - Visually differentiates confirmed relationships (solid arrows) from inferred associations (dashed lines).
   - Clear labeling of `Sample Demonstration Data` versus `Live Verified Observation`.

5. **AI Security Copilot (`src/components/copilot/CopilotView.tsx`):**
   - Answers security queries grounded in real scan records and assessment findings.
   - Multilingual support including Hindi and Hinglish.
   - Server-side Gemini model integration with zero client-side key exposure.

---

## Demonstration Data vs Live Verified Records

To prevent deceptive presentation of security results:
- Seed records in `cyberrakshak_db.json` are stamped with `isDemo: true` and rendered with a purple `[Sample Demonstration Data]` badge.
- Real user operations (e.g. running a personal scam analysis or assessing an authorized business website) are stored with `isDemo: false` and rendered with a green `[Live Verified Result]` badge.
- Factory demo data can be reset anytime via **Settings > Factory Demo Reset**.

---

## Known Limitations

- **Passive Non-Destructive Scans:** CyberRakshak AI assesses external attack surfaces using passive TLS handshakes and HTTP response headers. It deliberately does not perform aggressive port scanning, brute-forcing, or exploit execution.
- **External Threat Feeds:** Real-time threat feeds require a valid `THREAT_INTELLIGENCE_API_KEY`. Without it, CyberRakshak AI transparently falls back to local lookalike and linguistic rules.
