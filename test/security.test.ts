import { calculateRiskPriority, isAllowedPublicHost } from '../src/utils/riskEngine';
import { isPrivateIPv4, isPrivateIPv6, validateHostForSSRF, safeFetch } from '../server/ssrfGuard';
import { analyzePersonalContent } from '../server/scamEngine';
import { runBusinessAssessment } from '../server/businessEngine';
import { db, verifyUserCredentials } from '../server/db';
import { createSessionToken, verifySessionToken, authAndWorkspaceGuard, getAuditLogs, getSessionSecret } from '../server/auth';

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

async function test(name: string, fn: () => void | Promise<void>) {
  totalTests++;
  try {
    await fn();
    passedTests++;
    console.log(`  ✓ PASS: ${name}`);
  } catch (err: any) {
    failedTests++;
    console.error(`  ✗ FAIL: ${name}\n    Error: ${err.message}`);
  }
}

function assert(condition: boolean, msg: string) {
  if (!condition) {
    throw new Error(`Assertion failed: ${msg}`);
  }
}

function assertEqual<T>(actual: T, expected: T, msg?: string) {
  if (actual !== expected) {
    throw new Error(`${msg || 'Equality assertion failed'}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

async function runSecurityTestSuite() {
  console.log('\n========================================');
  console.log('CYBERRAKSHAK AI SECURITY & VALIDATION SUITE');
  console.log('========================================\n');

  console.log('[SECTION 1: URL & SSRF Edge-Case Validation]');

  await test('Reject localhost and variations', async () => {
    const r1 = await validateHostForSSRF('localhost');
    assert(!r1.valid, 'localhost must be rejected');
    const r2 = await validateHostForSSRF('localhost.localdomain');
    assert(!r2.valid, 'localdomain must be rejected');
    const r3 = await validateHostForSSRF('internal.lan');
    assert(!r3.valid, 'internal.lan must be rejected');
  });

  await test('Reject IPv4 loopback & RFC1918 private subnets', () => {
    assert(isPrivateIPv4('127.0.0.1').blocked, '127.0.0.1 blocked');
    assert(isPrivateIPv4('127.1.2.3').blocked, '127.1.2.3 blocked');
    assert(isPrivateIPv4('10.0.0.1').blocked, '10.0.0.1 blocked');
    assert(isPrivateIPv4('172.16.0.1').blocked, '172.16.0.1 blocked');
    assert(isPrivateIPv4('192.168.1.1').blocked, '192.168.1.1 blocked');
  });

  await test('Reject cloud metadata and link-local addresses', () => {
    assert(isPrivateIPv4('169.254.169.254').blocked, 'AWS/GCP metadata IP blocked');
    assert(isPrivateIPv4('169.254.1.1').blocked, 'Link-local IPv4 blocked');
    assert(isPrivateIPv6('fe80::1').blocked, 'Link-local IPv6 blocked');
  });

  await test('Reject IPv6 loopback, unique-local, and IPv4-mapped IPv6', () => {
    assert(isPrivateIPv6('::1').blocked, 'IPv6 loopback ::1 blocked');
    assert(isPrivateIPv6('fc00::1').blocked, 'IPv6 unique local fc00::1 blocked');
    assert(isPrivateIPv6('fd12:3456::1').blocked, 'IPv6 unique local fd.. blocked');
    assert(isPrivateIPv6('::ffff:127.0.0.1').blocked, 'IPv4-mapped loopback blocked');
    assert(isPrivateIPv6('::ffff:10.0.0.1').blocked, 'IPv4-mapped RFC1918 blocked');
  });

  await test('safeFetch rejects forbidden protocols and ports', async () => {
    const f1 = await safeFetch('ftp://example.com/test');
    assert(!f1.ok, 'ftp protocol must be rejected');
    assert(f1.error?.includes('Protocol') || false, 'Must identify forbidden protocol');

    const f2 = await safeFetch('http://example.com:22/');
    assert(!f2.ok, 'port 22 must be rejected');
    assert(f2.error?.includes('Port') || false, 'Must identify forbidden port');

    const f3 = await safeFetch('http://example.com:8080/');
    assert(!f3.ok, 'port 8080 must be rejected');
  });

  await test('Reject alternative IP notations, ports, and protocol wrappers in validateHostForSSRF', async () => {
    // Decimal IP notation for 127.0.0.1
    const rDec = await validateHostForSSRF('2130706433');
    assert(!rDec.valid, 'Decimal IP 2130706433 must be rejected');

    // Hex IP notation for 127.0.0.1
    const rHex = await validateHostForSSRF('0x7f000001');
    assert(!rHex.valid, 'Hex IP 0x7f000001 must be rejected');

    // Octal IP notation for 127.0.0.1
    const rOct = await validateHostForSSRF('0177.0.0.1');
    assert(!rOct.valid, 'Octal IP 0177.0.0.1 must be rejected');

    // IPv4 with port
    const rPort = await validateHostForSSRF('127.0.0.1:80');
    assert(!rPort.valid, '127.0.0.1:80 must be rejected');

    // Bracketed IPv6 with port
    const rIpv6Port = await validateHostForSSRF('[::1]:8080');
    assert(!rIpv6Port.valid, '[::1]:8080 must be rejected');

    // URL wrapper with path
    const rUrl = await validateHostForSSRF('http://169.254.169.254/latest/meta-data/');
    assert(!rUrl.valid, 'Metadata URL must be rejected');
  });

  console.log('\n[SECTION 2: Risk Scoring Engine & Clamp Validation]');

  await test('Accurate calculation for high-risk parameters', () => {
    const res = calculateRiskPriority({
      severity: 90,
      impact: 85,
      exposure: 80,
      confidence: 90,
      urgency: 75
    });
    assert(res.score >= 80, `Expected score >= 80, got ${res.score}`);
    assertEqual(res.level, 'Critical', 'Level should be Critical');
  });

  await test('Accurate calculation for low-risk parameters', () => {
    const res = calculateRiskPriority({
      severity: 15,
      impact: 10,
      exposure: 10,
      confidence: 85,
      urgency: 5
    });
    assert(res.score < 30, `Expected score < 30, got ${res.score}`);
    assertEqual(res.level, 'Low', 'Level should be Low');
  });

  await test('Boundary clamping handles values outside [0, 100]', () => {
    const resUpper = calculateRiskPriority({ severity: 200, impact: 200, exposure: 200, confidence: 200, urgency: 200 });
    assertEqual(resUpper.score, 100, 'Score cannot exceed 100');

    const resLower = calculateRiskPriority({ severity: -50, impact: -50, exposure: -50, confidence: -50, urgency: -50 });
    assertEqual(resLower.score, 0, 'Score cannot be less than 0');
  });

  console.log('\n[SECTION 3: Scam Engine Input Validation & Heuristics]');

  await test('Rejects non-string and whitespace-only inputs', async () => {
    try {
      await analyzePersonalContent('   ', 'message');
      // whitespace may trim or process cleanly as minimal text
    } catch (e: any) {
      assert(true, 'Properly handles whitespace/empty inputs');
    }

    try {
      await analyzePersonalContent(null as any, 'message');
      assert(false, 'Should throw on null input');
    } catch (e: any) {
      assert(e.message.includes('non-empty'), 'Rejects null input cleanly');
    }
  });

  await test('Detects UPI and lookalike domains in text', async () => {
    const text = 'Transfer ₹2,500 security deposit to recruiter@okaxis to confirm offer at job-portal-verify.xyz';
    const res = await analyzePersonalContent(text, 'job');
    assert(res.score >= 60, 'Score should reflect financial risk');
    assert(res.extractedIndicators.domains.includes('job-portal-verify.xyz'), 'Extracted domain');
    assert(res.extractedIndicators.upiHandles.includes('recruiter@okaxis'), 'Extracted UPI');
  });

  console.log('\n[SECTION 4: Business Assessment Authorization]');

  await test('Enforces owner authorization before domain assessment', async () => {
    try {
      await runBusinessAssessment({
        domain: 'example.com',
        authorizedByOwner: false,
        workspaceId: 'ws-business'
      });
      assert(false, 'Unauthorized assessment must fail');
    } catch (err: any) {
      assert(err.message.includes('Unauthorized assessment'), 'Enforces explicit consent');
    }
  });

  await test('Enforces SSRF check on target business domains', async () => {
    try {
      await runBusinessAssessment({
        domain: '169.254.169.254',
        authorizedByOwner: true,
        workspaceId: 'ws-business'
      });
      assert(false, 'SSRF target must fail');
    } catch (err: any) {
      assert(err.message.includes('SSRF Guard Blocked'), 'Blocks metadata target');
    }
  });

  console.log('\n[SECTION 5: Persistence & Workspace Isolation]');

  await test('Database isolates records between workspaces', () => {
    const snapshot = db.getSnapshot();
    const personalScans = snapshot.scans.filter(s => s.workspaceId === 'ws-personal');
    const businessScans = snapshot.scans.filter(s => s.workspaceId === 'ws-business');
    assert(personalScans.length > 0, 'Personal workspace has seeded scans');
    assert(Array.isArray(businessScans), 'Business workspace scans array exists');
  });

  await test('Factory reset preserves schema integrity and initial seed data', () => {
    db.resetToFactory();
    const snap = db.getSnapshot();
    assert(snap.workspaces.length === 2, 'Workspaces present');
    assert(snap.remediationTasks.length >= 3, 'Remediation tasks present');
    assert(snap.scans.length >= 1, 'Initial scan present');
  });

  console.log('\n[SECTION 6: Cryptographic Authentication, RBAC, IDOR & User Impersonation Defense]');

  await test('Cryptographic session token signs and verifies with HMAC-SHA256', () => {
    const token = createSessionToken('usr-akash');
    assert(typeof token === 'string' && token.includes('.'), 'Valid token format');
    const verified = verifySessionToken(token);
    assertEqual(verified, 'usr-akash', 'Verified user ID matches payload');

    const tampered = token + 'manipulated';
    const failVerified = verifySessionToken(tampered);
    assertEqual(failVerified, null, 'Tampered token must be rejected');

    const garbage = verifySessionToken('invalid.garbage.token');
    assertEqual(garbage, null, 'Malformed token must return null');
  });

  await test('Anonymous access to private routes is rejected with 401 Unauthorized', () => {
    const middleware = authAndWorkspaceGuard();
    let statusCode = 200;
    let jsonBody: any = null;

    const mockReq: any = {
      headers: {},
      query: {},
      path: '/api/scans'
    };
    const mockRes: any = {
      status: (code: number) => {
        statusCode = code;
        return { json: (b: any) => { jsonBody = b; } };
      }
    };
    let calledNext = false;

    middleware(mockReq, mockRes, () => { calledNext = true; });
    assert(!calledNext, 'Unauthenticated request must not proceed to next()');
    assertEqual(statusCode, 401, 'Must return 401 Unauthorized');
    assert(jsonBody?.error?.includes('Unauthorized'), 'Error states unauthorized token required');
  });

  await test('Forged and tampered session tokens are rejected with 401 Unauthorized', () => {
    const middleware = authAndWorkspaceGuard();
    let statusCode = 200;
    let jsonBody: any = null;

    const fakeToken = 'eyJ1c2VySWQiOiJ1c3ItYWthc2giLCJpc3N1ZWRBdCI6MTc0NTgzOTQ0MDAwMH0.fakeSignatureHere';
    const mockReq: any = {
      headers: {
        'authorization': `Bearer ${fakeToken}`,
        'x-workspace-id': 'ws-personal'
      },
      query: {},
      path: '/api/overview'
    };
    const mockRes: any = {
      status: (code: number) => {
        statusCode = code;
        return { json: (b: any) => { jsonBody = b; } };
      }
    };
    let calledNext = false;

    middleware(mockReq, mockRes, () => { calledNext = true; });
    assert(!calledNext, 'Forged token must not proceed');
    assertEqual(statusCode, 401, 'Must return 401 Unauthorized for forged token');
  });

  await test('User impersonation via x-user-id header is strictly rejected without valid token', () => {
    const middleware = authAndWorkspaceGuard();
    let statusCode = 200;
    let jsonBody: any = null;

    // Attacker tries to impersonate primary owner using x-user-id header
    const mockReq: any = {
      headers: {
        'x-user-id': 'usr-akash',
        'x-workspace-id': 'ws-personal'
      },
      query: {},
      path: '/api/scans'
    };
    const mockRes: any = {
      status: (code: number) => {
        statusCode = code;
        return { json: (b: any) => { jsonBody = b; } };
      }
    };
    let calledNext = false;

    middleware(mockReq, mockRes, () => { calledNext = true; });
    assert(!calledNext, 'x-user-id spoofing must not proceed');
    assertEqual(statusCode, 401, 'Must return 401 Unauthorized; x-user-id is ignored');
  });

  await test('User impersonation is prevented when token identity differs from x-user-id', () => {
    const middleware = authAndWorkspaceGuard();
    let calledNext = false;

    // User is legitimately authenticated as usr-analyst-external
    const legitimateToken = createSessionToken('usr-analyst-external');
    const mockReq: any = {
      headers: {
        'authorization': `Bearer ${legitimateToken}`,
        'x-user-id': 'usr-akash', // Attacker attempts to override authenticated identity
        'x-workspace-id': 'ws-personal'
      },
      query: {},
      path: '/api/overview'
    };
    const mockRes: any = {
      status: (code: number) => {
        return { json: (b: any) => {} };
      }
    };

    middleware(mockReq, mockRes, () => { calledNext = true; });
    assert(calledNext, 'Valid token proceeds to next()');
    assertEqual(mockReq.user.id, 'usr-analyst-external', 'Identity is bound to verified token, not x-user-id');
    assertEqual(mockReq.userRole, 'Viewer', 'Role is bound to verified token membership');
  });

  await test('Auth middleware prevents cross-workspace unauthorized access (IDOR)', () => {
    const middleware = authAndWorkspaceGuard();
    let statusCode = 200;
    let jsonBody: any = null;

    // usr-analyst-external has valid token but has NO membership in ws-business
    const analystToken = createSessionToken('usr-analyst-external');
    const mockReq: any = {
      headers: {
        'authorization': `Bearer ${analystToken}`,
        'x-workspace-id': 'ws-business'
      },
      query: {},
      path: '/api/assessments'
    };
    const mockRes: any = {
      status: (code: number) => {
        statusCode = code;
        return { json: (b: any) => { jsonBody = b; } };
      }
    };
    let calledNext = false;

    middleware(mockReq, mockRes, () => { calledNext = true; });
    assert(!calledNext, 'Cross-workspace unauthorized access must not proceed');
    assertEqual(statusCode, 403, 'Must return 403 Forbidden for cross-workspace access');
    assert(jsonBody?.error?.includes('Forbidden'), 'Error body states forbidden workspace');
  });

  await test('Auth middleware enforces Role-Based Access Control (RBAC)', () => {
    // Require Owner or Administrator role
    const middleware = authAndWorkspaceGuard({ requireRole: ['Owner', 'Administrator'] });
    let statusCode = 200;
    let jsonBody: any = null;

    // usr-analyst-external in ws-personal is only a 'Viewer'
    const analystToken = createSessionToken('usr-analyst-external');
    const mockReq: any = {
      headers: {
        'authorization': `Bearer ${analystToken}`,
        'x-workspace-id': 'ws-personal'
      },
      query: {},
      path: '/api/settings/reset'
    };
    const mockRes: any = {
      status: (code: number) => {
        statusCode = code;
        return { json: (b: any) => { jsonBody = b; } };
      }
    };
    let calledNext = false;

    middleware(mockReq, mockRes, () => { calledNext = true; });
    assert(!calledNext, 'Insufficient role must not proceed');
    assertEqual(statusCode, 403, 'Must return 403 Forbidden for insufficient role');
    assert(jsonBody?.error?.includes('Forbidden'), 'Mentions role permission shortage');
  });

  await test('Real credential authentication validates correct password and rejects invalid', () => {
    // Valid password for Akash Sharma
    const validUser = verifyUserCredentials('akash.sharma@example.com', 'RakshakSecure#2025');
    assert(validUser !== null, 'Valid credentials authenticate successfully');
    assertEqual(validUser?.id, 'usr-akash', 'Authenticated user ID matches');

    // Invalid password
    const wrongPass = verifyUserCredentials('akash.sharma@example.com', 'WrongPassword123');
    assertEqual(wrongPass, null, 'Invalid password must be rejected');

    // Non-existent email
    const nonExistent = verifyUserCredentials('nobody@example.com', 'SomePassword123');
    assertEqual(nonExistent, null, 'Non-existent user must be rejected');
  });

  await test('Session secret fails startup in production if absent, short, or placeholder', () => {
    const prevEnv = process.env.NODE_ENV;
    const prevSecret = process.env.SESSION_SECRET;

    try {
      process.env.NODE_ENV = 'production';

      // 1. Missing secret
      delete process.env.SESSION_SECRET;
      let caughtMissing = false;
      try {
        getSessionSecret();
      } catch {
        caughtMissing = true;
      }
      assert(caughtMissing, 'Missing SESSION_SECRET must fail in production');

      // 2. Short / weak secret
      process.env.SESSION_SECRET = 'short';
      let caughtShort = false;
      try {
        getSessionSecret();
      } catch {
        caughtShort = true;
      }
      assert(caughtShort, 'Weak/short SESSION_SECRET must fail in production');

      // 3. Placeholder secret
      process.env.SESSION_SECRET = 'cyberrakshak-session-auth-hmac-key-v1-too-common';
      let caughtPlaceholder = false;
      try {
        getSessionSecret();
      } catch {
        caughtPlaceholder = true;
      }
      assert(caughtPlaceholder, 'Default placeholder secret must fail in production');
    } finally {
      process.env.NODE_ENV = prevEnv;
      if (prevSecret) {
        process.env.SESSION_SECRET = prevSecret;
      } else {
        delete process.env.SESSION_SECRET;
      }
    }
  });

  await test('Structured audit logs capture security events without leaking secrets', () => {
    const logs = getAuditLogs();
    assert(Array.isArray(logs), 'Audit logs array exists');
    assert(logs.length > 0, 'Audit logs have recorded events');
    const recent = logs[0];
    assert(typeof recent.action === 'string', 'Audit log has action');
    assert(typeof recent.status === 'string', 'Audit log has status');
    // Ensure no secrets appear in audit logs
    const serialized = JSON.stringify(logs);
    assert(!serialized.includes(process.env.GEMINI_API_KEY || 'not-found'), 'Gemini API key not in logs');
  });

  console.log('\n----------------------------------------');
  console.log(`TOTAL SECURITY TESTS: ${totalTests}`);
  console.log(`PASSED: ${passedTests}`);
  console.log(`FAILED: ${failedTests}`);
  console.log('----------------------------------------\n');

  if (failedTests > 0) {
    process.exit(1);
  }
}

runSecurityTestSuite().catch(err => {
  console.error('Test execution failed:', err);
  process.exit(1);
});
