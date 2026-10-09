/**
 * CyberRakshak AI — Deterministic Risk Prioritization & Security Utilities
 * 
 * Master Formula:
 * Risk Priority = 0.30 × Severity + 0.25 × Impact + 0.20 × Exposure + 0.15 × Confidence + 0.10 × Urgency
 * 
 * Scoring Inputs & Weights:
 * - Technical Severity (30%): Intrinsic harm potential based on OWASP/CVSS classification (Critical: 100, High: 75, Medium: 50, Low: 25).
 * - Business Impact (25%): Potential disruption to operations, data confidentiality, financial loss, or trust.
 * - Asset Exposure (20%): Public internet exposure, reachability, or attack surface placement.
 * - Confidence Level (15%): Certainty of evidence (100% for direct TLS/HTTP header observations, 60% for heuristic rules, 30% for weak signals).
 * - Remediation Urgency (10%): Active exploitation, imminent certificate expiration, or active scam campaign.
 * 
 * Normalization:
 * - Each factor is normalized and strictly clamped to [0, 100].
 * - Handles edge cases: NaN, negative values, values > 100, non-numeric values, and empty objects.
 * - The composite score is rounded to an integer between 0 and 100.
 * 
 * Separation of Concerns:
 * - Technical Severity: Inherent flaw severity ('Critical' | 'High' | 'Medium' | 'Low').
 * - Business Priority: Operational action ranking ('P1 - Immediate' | 'P2 - High' | 'P3 - Moderate' | 'P4 - Low').
 * - Confidence: Evidence verification certainty ('Verified' | 'Probable' | 'Inconclusive').
 * 
 * Documented Limitations:
 * - Passive network probes evaluate externally observable configurations only (e.g. HTTP headers, TLS versions).
 * - Absence of a threat intelligence match or passive finding does not guarantee total system safety.
 * - Prioritization reflects perimeter risk, not internal application logic vulnerabilities.
 */

export interface RiskFactors {
  severity: number;    // 0 - 100 (Low: 25, Medium: 50, High: 75, Critical: 100)
  impact: number;      // 0 - 100
  exposure: number;    // 0 - 100
  confidence: number;  // 0 - 100
  urgency: number;     // 0 - 100
}

export interface RiskPriorityResult {
  score: number;
  level: 'Low' | 'Medium' | 'High' | 'Critical';
  formulaBreakdown: {
    severityWeighted: number;
    impactWeighted: number;
    exposureWeighted: number;
    confidenceWeighted: number;
    urgencyWeighted: number;
  };
  explanation: string;
}

export function sanitizeRiskFactor(val: any): number {
  if (typeof val !== 'number' || isNaN(val)) {
    return 0;
  }
  return Math.max(0, Math.min(100, val));
}

export function calculateRiskPriority(factors: Partial<RiskFactors> | null | undefined): RiskPriorityResult {
  const safeFactors = factors || {};

  const s = sanitizeRiskFactor(safeFactors.severity);
  const i = sanitizeRiskFactor(safeFactors.impact);
  const e = sanitizeRiskFactor(safeFactors.exposure);
  const c = sanitizeRiskFactor(safeFactors.confidence);
  const u = sanitizeRiskFactor(safeFactors.urgency);

  const severityWeighted = 0.30 * s;
  const impactWeighted = 0.25 * i;
  const exposureWeighted = 0.20 * e;
  const confidenceWeighted = 0.15 * c;
  const urgencyWeighted = 0.10 * u;

  const totalScore = Math.round(
    severityWeighted + impactWeighted + exposureWeighted + confidenceWeighted + urgencyWeighted
  );

  let level: 'Low' | 'Medium' | 'High' | 'Critical' = 'Low';
  if (totalScore >= 80) level = 'Critical';
  else if (totalScore >= 60) level = 'High';
  else if (totalScore >= 40) level = 'Medium';

  return {
    score: totalScore,
    level,
    formulaBreakdown: {
      severityWeighted: Number(severityWeighted.toFixed(1)),
      impactWeighted: Number(impactWeighted.toFixed(1)),
      exposureWeighted: Number(exposureWeighted.toFixed(1)),
      confidenceWeighted: Number(confidenceWeighted.toFixed(1)),
      urgencyWeighted: Number(urgencyWeighted.toFixed(1))
    },
    explanation: `Calculated Priority: ${totalScore}/100 [${level}] derived from 30% Severity (${s}), 25% Impact (${i}), 20% Exposure (${e}), 15% Confidence (${c}), and 10% Urgency (${u}).`
  };
}

/**
 * Separates Technical Severity, Business Priority, and Evidence Confidence
 */
export interface TriFactorEvaluation {
  technicalSeverity: 'Critical' | 'High' | 'Medium' | 'Low';
  businessPriority: 'P1 - Immediate' | 'P2 - High' | 'P3 - Moderate' | 'P4 - Low';
  confidence: 'Verified' | 'Probable' | 'Inconclusive';
  compositePriorityScore: number;
  assessmentLimitations: string;
}

export function evaluateTriFactorRisk(params: {
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  businessCriticality?: 'Mission-Critical' | 'High' | 'Standard' | 'Low';
  hasDirectObservation?: boolean;
  isExternalFacing?: boolean;
}): TriFactorEvaluation {
  const {
    severity,
    businessCriticality = 'Standard',
    hasDirectObservation = true,
    isExternalFacing = true
  } = params;

  // 1. Technical Severity mapping
  const severityScoreMap = { Critical: 100, High: 75, Medium: 50, Low: 25 };
  const baseSeverityScore = severityScoreMap[severity] || 50;

  // 2. Business Impact mapping
  const impactScoreMap = { 'Mission-Critical': 100, High: 80, Standard: 50, Low: 20 };
  const impactScore = impactScoreMap[businessCriticality] || 50;

  // 3. Exposure mapping
  const exposureScore = isExternalFacing ? 85 : 30;

  // 4. Confidence mapping
  const confidenceScore = hasDirectObservation ? 100 : 50;
  const confidence: 'Verified' | 'Probable' | 'Inconclusive' = hasDirectObservation ? 'Verified' : 'Probable';

  // 5. Composite Priority Calculation
  const priorityCalc = calculateRiskPriority({
    severity: baseSeverityScore,
    impact: impactScore,
    exposure: exposureScore,
    confidence: confidenceScore,
    urgency: severity === 'Critical' ? 90 : 50
  });

  // 6. Explicit Business Priority Separation
  let businessPriority: 'P1 - Immediate' | 'P2 - High' | 'P3 - Moderate' | 'P4 - Low' = 'P3 - Moderate';
  if (priorityCalc.score >= 80 || (severity === 'Critical' && businessCriticality === 'Mission-Critical')) {
    businessPriority = 'P1 - Immediate';
  } else if (priorityCalc.score >= 60 || severity === 'High') {
    businessPriority = 'P2 - High';
  } else if (priorityCalc.score < 35 && severity === 'Low') {
    businessPriority = 'P4 - Low';
  }

  return {
    technicalSeverity: severity,
    businessPriority,
    confidence,
    compositePriorityScore: priorityCalc.score,
    assessmentLimitations: 'Passive perimeter observation only; internal application logic and authenticated state not evaluated.'
  };
}

/**
 * SSRF Safeguards: Validates target hosts before any outbound HTTP/TLS connection.
 */
export function isAllowedPublicHost(host: string): { allowed: boolean; reason?: string } {
  const trimmed = String(host || '').trim().toLowerCase();

  if (!trimmed) {
    return { allowed: false, reason: 'Empty host string.' };
  }

  if (
    trimmed === 'localhost' ||
    trimmed === '127.0.0.1' ||
    trimmed === '::1' ||
    trimmed.startsWith('127.') ||
    trimmed.endsWith('.local') ||
    trimmed.endsWith('.internal') ||
    trimmed.endsWith('.lan')
  ) {
    return { allowed: false, reason: 'Local and loopback network addresses are strictly prohibited.' };
  }

  if (trimmed === '169.254.169.254' || trimmed.includes('metadata.google.internal')) {
    return { allowed: false, reason: 'Access to cloud metadata endpoints is blocked.' };
  }

  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const ipMatch = trimmed.match(ipv4Regex);
  if (ipMatch) {
    const oct1 = parseInt(ipMatch[1], 10);
    const oct2 = parseInt(ipMatch[2], 10);

    if (oct1 === 10) return { allowed: false, reason: 'Private RFC1918 subnet (10.0.0.0/8) is restricted.' };
    if (oct1 === 172 && oct2 >= 16 && oct2 <= 31) return { allowed: false, reason: 'Private RFC1918 subnet (172.16.0.0/12) is restricted.' };
    if (oct1 === 192 && oct2 === 168) return { allowed: false, reason: 'Private RFC1918 subnet (192.168.0.0/16) is restricted.' };
    if (oct1 === 0 || oct1 >= 224) return { allowed: false, reason: 'Reserved/multicast IP address is restricted.' };
  }

  return { allowed: true };
}
