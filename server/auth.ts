import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';
import { db, User, Workspace } from './db.ts';

/**
 * CyberRakshak AI — Security Hardening & Session Authentication Module
 * 
 * Provides:
 * 1. Cryptographic session token generation & verification.
 * 2. Authenticated user identity resolution with tamper-resistant HMAC signing.
 * 3. Strict Workspace Membership & Role-Based Access Control (RBAC):
 *    - Owner / Administrator: full read & write (scans, assessments, remediations, hygiene).
 *    - Analyst: run scans, trigger assessments, update remediation statuses.
 *    - Viewer: read-only access across private telemetry & reports.
 * 4. Cross-workspace / IDOR protection across every private route.
 * 5. Structured Audit Logging for compliance and incident forensics (no sensitive payload/secrets logged).
 * 6. In-memory Rate Limiting to deter brute-force and resource exhaustion.
 */

// Dynamic session secret resolution with strict production validation
let ephemeralSecret: string | null = null;

export function getSessionSecret(): string {
  const envSecret = process.env.SESSION_SECRET;
  const isProd = process.env.NODE_ENV === 'production';

  if (isProd) {
    if (!envSecret || envSecret.length < 32 || envSecret.includes('cyberrakshak-session-auth-hmac-key') || envSecret === 'changeme' || envSecret === 'secret') {
      throw new Error('FATAL SECURITY CONFIGURATION: In production mode, SESSION_SECRET environment variable is strictly required and must be at least 32 characters in length. Server startup halted.');
    }
    return envSecret;
  }

  if (envSecret && envSecret.length >= 16) {
    return envSecret;
  }

  if (!ephemeralSecret) {
    ephemeralSecret = crypto.randomBytes(32).toString('hex');
  }
  return ephemeralSecret;
}

export function isDemoModeAllowed(): boolean {
  return process.env.NODE_ENV !== 'production' && process.env.ENABLE_DEMO_MODE !== 'false';
}

export interface AuthenticatedUser extends User {
  workspaces: {
    workspaceId: string;
    role: 'Owner' | 'Administrator' | 'Analyst' | 'Viewer';
  }[];
}

export interface SecurityAuditLog {
  id: string;
  timestamp: string;
  userId: string;
  userEmail: string;
  workspaceId: string;
  action: string;
  resource: string;
  status: 'SUCCESS' | 'DENIED' | 'ERROR';
  details?: string;
  ip?: string;
}

// In-memory structured security audit log
const auditLogs: SecurityAuditLog[] = [];

export function recordAuditEvent(event: Omit<SecurityAuditLog, 'id' | 'timestamp'>) {
  const record: SecurityAuditLog = {
    id: `audit-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
    timestamp: new Date().toISOString(),
    ...event
  };
  auditLogs.unshift(record);
  if (auditLogs.length > 500) {
    auditLogs.pop();
  }
}

export function getAuditLogs(workspaceId?: string): SecurityAuditLog[] {
  if (workspaceId) {
    return auditLogs.filter(l => l.workspaceId === workspaceId);
  }
  return [...auditLogs];
}

/**
 * Sign a user session token with HMAC-SHA256
 */
export function createSessionToken(userId: string): string {
  const secret = getSessionSecret();
  const payload = Buffer.from(JSON.stringify({ userId, issuedAt: Date.now() })).toString('base64url');
  const signature = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

/**
 * Verify session token and return user ID if valid
 */
export function verifySessionToken(token: string): string | null {
  try {
    if (!token || typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [payload, signature] = parts;
    const secret = getSessionSecret();
    const expectedSignature = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
    
    // Constant-time comparison
    const sigBuf = Buffer.from(signature);
    const expBuf = Buffer.from(expectedSignature);
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
      return null;
    }
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf-8'));
    if (!data.userId || typeof data.userId !== 'string') return null;
    return data.userId;
  } catch {
    return null;
  }
}

/**
 * Global or Route Middleware: Authenticate & Authorize Workspace
 * - Rejects unauthenticated requests with 401 Unauthorized.
 * - Does NOT accept x-user-id as an identity source (prevents user impersonation).
 * - Enforces workspace membership (prevents IDOR).
 * - Enforces role-based permissions (RBAC).
 */
export function authAndWorkspaceGuard(options: {
  requireRole?: ('Owner' | 'Administrator' | 'Analyst' | 'Viewer')[];
} = {}) {
  return (req: Request, res: Response, next: NextFunction) => {
    const snapshot = db.getSnapshot();

    // 1. Resolve User SOLELY from valid cryptographic Bearer token
    let userId: string | null = null;
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.slice(7).trim();
      userId = verifySessionToken(token);
    }

    // Explicit rejection: no default fallback, no x-user-id fallback
    if (!userId) {
      recordAuditEvent({
        userId: 'anonymous',
        userEmail: 'unauthenticated',
        workspaceId: (req.headers['x-workspace-id'] as string) || 'unknown',
        action: 'API_REQUEST_BLOCKED',
        resource: req.path,
        status: 'DENIED',
        details: 'Missing or invalid authentication credentials (valid Bearer token required)',
        ip: req.ip
      });
      return res.status(401).json({ error: 'Unauthorized: Valid authentication token required.' });
    }

    const matchedUser = snapshot.users.find(u => u.id === userId);
    if (!matchedUser) {
      return res.status(401).json({ error: 'Unauthorized: User account not found.' });
    }

    // 2. Resolve Workspace from header or query
    const requestedWsId = (req.headers['x-workspace-id'] as string) || (req.query.workspaceId as string) || matchedUser.currentWorkspaceId;
    const targetWorkspace = snapshot.workspaces.find(w => w.id === requestedWsId);

    if (!targetWorkspace) {
      return res.status(404).json({ error: `Workspace not found: "${requestedWsId}"` });
    }

    // 3. Enforce Workspace Membership & Isolation
    // Check if user has explicit membership or ownership in this workspace
    const userMembership = matchedUser.memberships?.find(m => m.workspaceId === targetWorkspace.id);
    const isOwner = targetWorkspace.ownerId === matchedUser.id;

    if (!isOwner && !userMembership) {
      recordAuditEvent({
        userId: matchedUser.id,
        userEmail: matchedUser.email,
        workspaceId: targetWorkspace.id,
        action: 'CROSS_WORKSPACE_ACCESS_BLOCKED',
        resource: req.path,
        status: 'DENIED',
        details: `User "${matchedUser.email}" is not a member of workspace "${targetWorkspace.name}" (${targetWorkspace.id})`,
        ip: req.ip
      });
      return res.status(403).json({
        error: `Forbidden: You do not have membership permissions in workspace "${targetWorkspace.name}".`
      });
    }

    // Map effective role from explicit user membership or ownership
    let effectiveRole: 'Owner' | 'Administrator' | 'Analyst' | 'Viewer' = 
      isOwner ? 'Owner' : (userMembership?.role || 'Viewer');

    // Attach verified user, workspace, and role to request object
    (req as any).user = matchedUser;
    (req as any).workspace = targetWorkspace;
    (req as any).workspaceId = targetWorkspace.id;
    (req as any).userRole = effectiveRole;

    // 4. Role-based Access Control (RBAC) check
    if (options.requireRole && options.requireRole.length > 0) {
      const roleHierarchy: Record<'Owner' | 'Administrator' | 'Analyst' | 'Viewer', number> = {
        'Owner': 4,
        'Administrator': 3,
        'Analyst': 2,
        'Viewer': 1
      };

      const userRank = roleHierarchy[effectiveRole] || 1;
      const minRequiredRank = Math.min(...options.requireRole.map(r => roleHierarchy[r] || 1));

      if (userRank < minRequiredRank) {
        recordAuditEvent({
          userId: matchedUser.id,
          userEmail: matchedUser.email,
          workspaceId: targetWorkspace.id,
          action: 'ACCESS_FORBIDDEN_ROLE',
          resource: req.path,
          status: 'DENIED',
          details: `User role "${effectiveRole}" does not satisfy required roles: [${options.requireRole.join(', ')}]`,
          ip: req.ip
        });
        return res.status(403).json({ 
          error: `Forbidden: Role "${effectiveRole}" does not have sufficient permission for this operation.` 
        });
      }
    }

    next();
  };
}

/**
 * Lightweight, in-memory sliding window Rate Limiter
 */
const rateLimitBuckets = new Map<string, { count: number; resetAt: number }>();

export function rateLimit(options: { windowMs: number; maxRequests: number }) {
  return (req: Request, res: Response, next: NextFunction) => {
    const key = (req.ip || '127.0.0.1') + ':' + req.baseUrl + req.path;
    const now = Date.now();
    let bucket = rateLimitBuckets.get(key);

    if (!bucket || now > bucket.resetAt) {
      bucket = { count: 1, resetAt: now + options.windowMs };
      rateLimitBuckets.set(key, bucket);
    } else {
      bucket.count++;
    }

    if (bucket.count > options.maxRequests) {
      return res.status(429).json({
        error: 'Too Many Requests: Rate limit exceeded. Please wait before making further requests.'
      });
    }

    next();
  };
}
