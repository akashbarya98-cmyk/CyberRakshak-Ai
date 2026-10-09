import tls from 'tls';
import { validateHostForSSRF, safeFetch } from './ssrfGuard.ts';
import { FindingRecord } from './db.ts';

export interface BusinessAssessmentResult {
  domain: string;
  industry: string;
  businessSize: string;
  overallScore: number;
  riskClassification: 'Good' | 'Moderate Risk' | 'High Risk' | 'Critical Risk';
  status: 'Completed' | 'Inconclusive';
  authorizedByOwner: boolean;
  findings: FindingRecord[];
  checksUnavailable: string[];
  observedEvidence: {
    tlsIssuer?: string;
    tlsDaysRemaining?: number;
    tlsProtocol?: string;
    httpStatus?: number;
    hstsPresent: boolean;
    cspPresent: boolean;
    xFramePresent: boolean;
    serverBanner?: string;
  };
  timestamp: number;
  date: string;
}

export async function runBusinessAssessment(params: {
  domain: string;
  industry?: string;
  businessSize?: string;
  authorizedByOwner: boolean;
  workspaceId: string;
}): Promise<BusinessAssessmentResult> {
  const { domain, industry = 'Technology', businessSize = '1-10 employees', authorizedByOwner, workspaceId } = params;

  // 1. Authorization check
  if (!authorizedByOwner) {
    throw new Error('Unauthorized assessment: You may assess only digital systems you own or have explicit authorization to test.');
  }

  // 2. Normalize domain
  const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim().toLowerCase();
  if (!cleanDomain) {
    throw new Error('Valid domain name is required.');
  }

  // 3. SSRF Pre-flight Validation & DNS Resolution Pinning
  const ssrfCheck = await validateHostForSSRF(cleanDomain);
  if (!ssrfCheck.valid) {
    throw new Error(`SSRF Guard Blocked: ${ssrfCheck.reason}`);
  }
  const pinnedIp = ssrfCheck.resolvedIps?.[0] || cleanDomain;

  const findings: FindingRecord[] = [];
  const checksUnavailable: string[] = [];
  let score = 90;

  let observedEvidence: BusinessAssessmentResult['observedEvidence'] = {
    hstsPresent: false,
    cspPresent: false,
    xFramePresent: false
  };

  // 4. Passive TLS Inspection via port 443 pinned to verified IP
  try {
    const tlsData = await new Promise<{
      valid: boolean;
      daysRemaining?: number;
      issuer?: string;
      protocol?: string;
      error?: string;
    }>((resolve) => {
      const socket = tls.connect(
        {
          host: pinnedIp,
          port: 443,
          servername: cleanDomain, // Preserve SNI for virtual hosts
          timeout: 3500
        },
        () => {
          const cert = socket.getPeerCertificate();
          const protocol = socket.getProtocol() || undefined;
          socket.end();

          if (cert && cert.valid_to) {
            const expiry = new Date(cert.valid_to).getTime();
            const now = Date.now();
            const daysRemaining = Math.floor((expiry - now) / (1000 * 60 * 60 * 24));
            const issuerVal = cert.issuer?.O || cert.issuer?.CN;
            const issuer = Array.isArray(issuerVal) ? issuerVal.join(', ') : (issuerVal || 'Unknown Certificate Authority');
            resolve({ valid: true, daysRemaining, issuer, protocol });
          } else {
            resolve({ valid: false, error: 'No certificate returned' });
          }
        }
      );

      socket.on('error', (err) => resolve({ valid: false, error: err.message }));
      socket.on('timeout', () => {
        socket.destroy();
        resolve({ valid: false, error: 'Port 443 connection timed out (3500ms)' });
      });
    });

    if (tlsData.valid && typeof tlsData.daysRemaining === 'number') {
      observedEvidence.tlsIssuer = tlsData.issuer;
      observedEvidence.tlsDaysRemaining = tlsData.daysRemaining;
      observedEvidence.tlsProtocol = tlsData.protocol;

      if (tlsData.daysRemaining < 0) {
        score -= 35;
        findings.push({
          id: `bf-${Date.now()}-tls-expired`,
          workspaceId,
          title: 'TLS Certificate Expired',
          category: 'Infrastructure',
          severity: 'Critical',
          confidence: '100% (Direct TLS handshake observation)',
          date: new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
          status: 'Open',
          description: `The TLS certificate issued by ${tlsData.issuer} expired ${Math.abs(tlsData.daysRemaining)} days ago. Browsers will display security warnings.`,
          source: 'Observed TLS Certificate Handshake',
          impact: 'Visitors will be blocked from accessing the site by browser security intersitials.',
          remediation: 'Renew and deploy a valid TLS certificate immediately via your hosting provider or Let\'s Encrypt.',
          priorityScore: 95,
          isDemo: false
        });
      } else if (tlsData.daysRemaining <= 15) {
        score -= 20;
        findings.push({
          id: `bf-${Date.now()}-tls-soon`,
          workspaceId,
          title: 'SSL/TLS Certificate Expiring Soon',
          category: 'Infrastructure',
          severity: 'High',
          confidence: '100% (Direct TLS handshake observation)',
          date: new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
          status: 'Open',
          description: `TLS certificate issued by ${tlsData.issuer} expires in ${tlsData.daysRemaining} days. Automated renewal appears non-functional.`,
          source: 'Observed TLS Certificate Handshake',
          impact: 'Risk of downtime and browser warning screens when certificate lapses.',
          remediation: 'Renew certificate using Certbot or host management console before expiry.',
          priorityScore: 82,
          isDemo: false
        });
      } else {
        // Healthy TLS
        findings.push({
          id: `bf-${Date.now()}-tls-ok`,
          workspaceId,
          title: 'Active TLS Certificate Valid',
          category: 'Infrastructure',
          severity: 'Low',
          confidence: '100% (Direct TLS handshake observation)',
          date: new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
          status: 'Resolved',
          description: `TLS certificate (${tlsData.protocol || 'TLS'}) issued by ${tlsData.issuer} is valid for ${tlsData.daysRemaining} more days.`,
          source: 'Observed TLS Certificate Handshake',
          impact: 'Data in transit is encrypted against passive eavesdropping.',
          remediation: 'Maintain automated renewal schedules.',
          priorityScore: 10,
          isDemo: false
        });
      }
    } else {
      score -= 25;
      checksUnavailable.push(`TLS inspection incomplete: ${tlsData.error}`);
      findings.push({
        id: `bf-${Date.now()}-tls-err`,
        workspaceId,
        title: 'HTTPS Port 443 Unreachable or Incomplete Handshake',
        category: 'Infrastructure',
        severity: 'High',
        confidence: '90%',
        date: new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
        status: 'Open',
        description: `Passive TLS probe failed: ${tlsData.error}. Target host may not support direct HTTPS or is firewall-restricted.`,
        source: 'Passive TLS Connection Test',
        impact: 'Web communications may fall back to unencrypted HTTP transmission.',
        remediation: 'Ensure port 443 is open and configured with a trusted TLS certificate.',
        priorityScore: 78,
        isDemo: false
      });
    }
  } catch (err: any) {
    checksUnavailable.push(`TLS probe error: ${err.message}`);
  }

  // 5. Passive HTTP Security Headers Probe
  try {
    const probeRes = await safeFetch(`https://${cleanDomain}`, {
      method: 'HEAD',
      timeoutMs: 4000
    });

    if (probeRes.ok || probeRes.status > 0) {
      observedEvidence.httpStatus = probeRes.status;
      const hsts = probeRes.headers.get('strict-transport-security');
      const csp = probeRes.headers.get('content-security-policy');
      const xFrame = probeRes.headers.get('x-frame-options');
      const xContentType = probeRes.headers.get('x-content-type-options');
      const serverHeader = probeRes.headers.get('server');

      if (serverHeader) observedEvidence.serverBanner = serverHeader;

      // HSTS Check
      if (hsts) {
        observedEvidence.hstsPresent = true;
      } else {
        score -= 15;
        findings.push({
          id: `bf-${Date.now()}-hsts-missing`,
          workspaceId,
          title: 'Missing HTTP Strict Transport Security (HSTS)',
          category: 'Web Security',
          severity: 'Medium',
          confidence: '100% (Direct response header observation)',
          date: new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
          status: 'Open',
          description: 'HSTS header is absent. Browsers are not forced to communicate strictly via HTTPS.',
          source: 'Observed HTTP Response Headers',
          impact: 'Leaves users exposed to SSL-stripping and downgrade Man-in-the-Middle attacks.',
          remediation: 'Configure "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" in web server.',
          priorityScore: 68,
          isDemo: false
        });
      }

      // CSP Check
      if (csp) {
        observedEvidence.cspPresent = true;
      } else {
        score -= 15;
        findings.push({
          id: `bf-${Date.now()}-csp-missing`,
          workspaceId,
          title: 'Missing Content-Security-Policy (CSP)',
          category: 'Web Security',
          severity: 'Medium',
          confidence: '100% (Direct response header observation)',
          date: new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
          status: 'Open',
          description: 'No Content-Security-Policy header defined to restrict origin of executable scripts.',
          source: 'Observed HTTP Response Headers',
          impact: 'Higher exposure to cross-site scripting (XSS) and unauthorized resource exfiltration.',
          remediation: 'Define a Content-Security-Policy whitelist specifying trusted origins for script-src and default-src.',
          priorityScore: 65,
          isDemo: false
        });
      }

      // Clickjacking Check
      if (xFrame) {
        observedEvidence.xFramePresent = true;
      } else {
        score -= 10;
        findings.push({
          id: `bf-${Date.now()}-xframe-missing`,
          workspaceId,
          title: 'Missing Clickjacking Defense (X-Frame-Options)',
          category: 'Web Security',
          severity: 'Medium',
          confidence: '100% (Direct response header observation)',
          date: new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
          status: 'Open',
          description: 'X-Frame-Options header not configured. Webpages can potentially be embedded in unauthorized iframes.',
          source: 'Observed HTTP Response Headers',
          impact: 'Increases susceptibility to UI redressing and clickjacking.',
          remediation: 'Set "X-Frame-Options: SAMEORIGIN" or configure CSP "frame-ancestors \'self\'".',
          priorityScore: 58,
          isDemo: false
        });
      }

      // Server version disclosure
      if (serverHeader && /\d+\.\d+/.test(serverHeader)) {
        score -= 5;
        findings.push({
          id: `bf-${Date.now()}-server-banner`,
          workspaceId,
          title: 'Web Server Version Banner Disclosure',
          category: 'Information Disclosure',
          severity: 'Low',
          confidence: '100% (Observed Server header)',
          date: new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
          status: 'Open',
          description: `Server header exposes detailed software release numbers: "${serverHeader}".`,
          source: 'Observed HTTP Response Headers',
          impact: 'Facilitates automated vulnerability targeting against known software releases.',
          remediation: 'Disable version disclosure banners (e.g., server_tokens off in Nginx, ServerSignature Off in Apache).',
          priorityScore: 35,
          isDemo: false
        });
      }
    } else {
      checksUnavailable.push(`HTTP headers probe incomplete: ${probeRes.error || 'Host unreachable'}`);
    }
  } catch (httpErr: any) {
    checksUnavailable.push(`HTTP probe error: ${httpErr.message}`);
  }

  score = Math.max(25, Math.min(100, score));

  let riskClassification: BusinessAssessmentResult['riskClassification'] = 'Good';
  if (score < 50) riskClassification = 'High Risk';
  else if (score < 75) riskClassification = 'Moderate Risk';

  return {
    domain: cleanDomain,
    industry,
    businessSize,
    overallScore: score,
    riskClassification,
    status: checksUnavailable.length > 1 && findings.length <= 1 ? 'Inconclusive' : 'Completed',
    authorizedByOwner,
    findings,
    checksUnavailable,
    observedEvidence,
    timestamp: Date.now(),
    date: new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
  };
}
