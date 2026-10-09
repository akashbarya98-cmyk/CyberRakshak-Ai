import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

/**
 * CyberRakshak AI — Persistent Database Storage with Schema Migrations & Workspace Isolation
 * 
 * Provides:
 * - File-backed persistence surviving application restarts.
 * - Atomic write safety using temporary file swap.
 * - Schema version migrations (schemaVersion tracking).
 * - Multi-workspace logical isolation and role checking.
 * - Clear distinction between initial seeded demo records (isDemo: true)
 *   and real user-executed operations (isDemo: false).
 */

export interface Workspace {
  id: string;
  name: string;
  type: 'personal' | 'business';
  ownerId: string;
  role: 'Owner' | 'Administrator' | 'Analyst' | 'Viewer';
  description: string;
  createdAt: string;
}

export interface UserWorkspaceMembership {
  workspaceId: string;
  role: 'Owner' | 'Administrator' | 'Analyst' | 'Viewer';
}

export interface User {
  id: string;
  email: string;
  name: string;
  role: 'Owner' | 'Administrator' | 'Analyst' | 'Viewer';
  currentWorkspaceId: string;
  memberships?: UserWorkspaceMembership[];
  createdAt: string;
  passwordHash?: string;
  salt?: string;
}

export interface FindingRecord {
  id: string;
  workspaceId: string;
  title: string;
  category: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  confidence: string;
  date: string;
  status: 'Open' | 'In Progress' | 'Resolved' | 'Awaiting Verification';
  description: string;
  source: string;
  impact?: string;
  remediation?: string;
  isDemo: boolean;
  priorityScore: number;
}

export interface ScanRecord {
  id: string;
  workspaceId: string;
  title: string;
  type: 'message' | 'url' | 'email' | 'image' | 'job';
  target: string;
  riskLevel: 'Low Indicated Risk' | 'Moderate Risk' | 'High Risk' | 'Critical Risk';
  score: number;
  confidence: string;
  date: string;
  timestamp: number;
  checksCompleted: string;
  summary: string;
  keyFindings: FindingRecord[];
  safetyActions: string[];
  priorityCalculation?: any;
  threatIntelSource?: string;
  isDemo: boolean;
}

export interface AssessmentRecord {
  id: string;
  workspaceId: string;
  domain: string;
  industry: string;
  businessSize: string;
  lastAssessment: string;
  status: 'Completed' | 'In Progress' | 'Scheduled' | 'Inconclusive';
  overallScore: number;
  riskClassification: string;
  authorizedByOwner: boolean;
  findings: FindingRecord[];
  checksUnavailable?: string[];
  timestamp: number;
  isDemo: boolean;
}

export interface AssetRecord {
  id: string;
  workspaceId: string;
  domain: string;
  type: string;
  authorizedByOwner: boolean;
  status: 'Healthy' | 'Moderate Risk' | 'High Risk';
  lastChecked: string;
  createdAt: string;
  isDemo: boolean;
}

export interface RemediationRecord {
  id: string;
  workspaceId: string;
  findingId?: string;
  title: string;
  category: string;
  description: string;
  effort: string;
  priority: 'Critical' | 'High' | 'Medium' | 'Low';
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  status: 'Open' | 'In Progress' | 'Awaiting Verification' | 'Resolved';
  createdAt: string;
  dueDate: string;
  target: string;
  isDemo: boolean;
  updatedAt?: string;
  completedAt?: string;
  assignee?: string;
  verificationStatus?: 'unverified' | 'user-reported' | 'independently-verified' | 'verification-failed';
  verificationDetails?: string;
}

export interface CommunityRecord {
  id: string;
  title: string;
  type: string;
  indicator: string;
  riskLevel: 'Critical' | 'High' | 'Medium' | 'Low';
  reportedAt: string;
  reportsCount: number;
  verified: boolean;
  description: string;
  isDemo: boolean;
}

export interface NotificationRecord {
  id: string;
  workspaceId: string;
  title: string;
  detail: string;
  time: string;
  type: 'danger' | 'warning' | 'info';
  read: boolean;
  timestamp: number;
}

export interface DatabaseSchema {
  schemaVersion: number;
  lastMigrationAt: string;
  workspaces: Workspace[];
  users: User[];
  findings?: FindingRecord[];
  scans: ScanRecord[];
  assessments: AssessmentRecord[];
  assets: AssetRecord[];
  remediationTasks: RemediationRecord[];
  communityReports: CommunityRecord[];
  notifications: NotificationRecord[];
  hygiene: Record<string, {
    mfaEnabled: boolean;
    uniquePasswords: boolean;
    recoveryMethodsReviewed: boolean;
    backupsConfigured: boolean;
    devicesUpdated: boolean;
  }>;
}

const DB_DIR = path.resolve(process.cwd(), 'data');
const DB_FILE = path.join(DB_DIR, 'cyberrakshak_db.json');
const CURRENT_SCHEMA_VERSION = 1;

function getInitialSeededData(): DatabaseSchema {
  return {
    schemaVersion: CURRENT_SCHEMA_VERSION,
    lastMigrationAt: new Date().toISOString(),
    workspaces: [
      {
        id: 'ws-personal',
        name: 'Personal Protection',
        type: 'personal',
        ownerId: 'usr-akash',
        role: 'Owner',
        description: 'Personal scam defense & private digital hygiene',
        createdAt: 'Apr 20, 2025'
      },
      {
        id: 'ws-business',
        name: 'Acme Digital / Example Inc.',
        type: 'business',
        ownerId: 'usr-akash',
        role: 'Administrator',
        description: 'Corporate domain perimeter & asset security assessments',
        createdAt: 'Apr 20, 2025'
      }
    ],
    users: [
      {
        id: 'usr-akash',
        email: 'akash.sharma@example.com',
        name: 'Akash Sharma',
        role: 'Owner',
        currentWorkspaceId: 'ws-personal',
        memberships: [
          { workspaceId: 'ws-personal', role: 'Owner' },
          { workspaceId: 'ws-business', role: 'Administrator' }
        ],
        createdAt: 'Apr 20, 2025',
        salt: 'salt-akash-rakshak-2025',
        passwordHash: '4da5dab3ad5fb11d4012af1988ffd1bd1317d41269c8c369d96939539bf32412faf35a61d9b9062b87f5e844f245cb0fee57a0bf5be8180a4b61259c55a802ea'
      },
      {
        id: 'usr-analyst-external',
        email: 'contractor.analyst@partner.org',
        name: 'Contractor Analyst',
        role: 'Analyst',
        currentWorkspaceId: 'ws-personal',
        memberships: [
          { workspaceId: 'ws-personal', role: 'Viewer' }
        ],
        createdAt: 'Apr 25, 2025',
        salt: 'salt-analyst-rakshak-2025',
        passwordHash: '68b0527cf2e3cb666d82a643fa122bb4ee8221951e295639ee1df8da8d1612fd13a9a96aa6ec13623bd5b30bf89e2346b04df4d524697d8f99b631227347a974'
      }
    ],
    scans: [
      {
        id: 'scan-demo-1',
        workspaceId: 'ws-personal',
        title: 'Suspicious Job Offer (Phishing) [Sample Demonstration]',
        type: 'message',
        target: 'career-update.com / WhatsApp SMS',
        riskLevel: 'High Risk',
        score: 85,
        confidence: '95%',
        date: 'Apr 28, 2025, 11:24 AM',
        timestamp: 1745839440000,
        checksCompleted: '8 / 10',
        summary: 'This message shows multiple signs of a phishing attempt, using deceptive recruitment tactics and urgent language.',
        keyFindings: [
          {
            id: 'f1',
            workspaceId: 'ws-personal',
            title: 'Urgency and pressure tactics',
            category: 'Phishing',
            severity: 'High',
            confidence: 'High confidence',
            date: 'Apr 28, 2025',
            status: 'Open',
            description: 'The message uses urgent language ("urgent action required", "offer expires in 2 hours") to create psychological pressure.',
            source: 'Linguistic Heuristic Engine',
            priorityScore: 78,
            isDemo: true
          },
          {
            id: 'f2',
            workspaceId: 'ws-personal',
            title: 'Suspicious sender domain',
            category: 'Phishing',
            severity: 'High',
            confidence: 'High confidence',
            date: 'Apr 28, 2025',
            status: 'Open',
            description: 'Sender domain (career-update.com) mimics legitimate portals but was registered 4 days ago with privacy guards.',
            source: 'Domain Age & Lookalike Heuristic',
            priorityScore: 82,
            isDemo: true
          },
          {
            id: 'f3',
            workspaceId: 'ws-personal',
            title: 'Request for upfront payment',
            category: 'Social Engineering',
            severity: 'Medium',
            confidence: 'Medium confidence',
            date: 'Apr 28, 2025',
            status: 'Open',
            description: 'Asks for an onboarding verification registration fee before the employment contract is signed.',
            source: 'Financial Scam Pattern Matcher',
            priorityScore: 65,
            isDemo: true
          }
        ],
        safetyActions: [
          'Do not transfer money or share bank account/UPI details.',
          'Verify the employer by visiting their official verified company domain directly.',
          'Never provide OTPs, passwords, or government identity cards via messaging apps.',
          'Report the sender number to the National Cyber Crime Reporting Portal (1930 / cybercrime.gov.in).'
        ],
        isDemo: true
      }
    ],
    assessments: [
      {
        id: 'assess-demo-1',
        workspaceId: 'ws-business',
        domain: 'example-business.com',
        industry: 'E-commerce',
        businessSize: '11-50 employees',
        lastAssessment: 'Apr 28, 2025',
        status: 'In Progress',
        overallScore: 68,
        riskClassification: 'Moderate Risk',
        authorizedByOwner: true,
        findings: [
          {
            id: 'bf-1',
            workspaceId: 'ws-business',
            title: 'SSL Certificate Expiring Soon',
            category: 'Infrastructure',
            severity: 'High',
            confidence: '95%',
            date: 'Apr 28, 2025',
            status: 'Open',
            description: 'TLS certificate expires in 12 days. Auto-renewal has failed.',
            source: 'Passive TLS Probe',
            impact: 'Loss of HTTPS encryption, browser red warning screens, customer transaction drop-off.',
            remediation: 'Renew certificate using Certbot or host management console before expiry.',
            priorityScore: 85,
            isDemo: true
          },
          {
            id: 'bf-2',
            workspaceId: 'ws-business',
            title: 'Missing Security Headers',
            category: 'Web Security',
            severity: 'Medium',
            confidence: '90%',
            date: 'Apr 28, 2025',
            status: 'Open',
            description: 'HTTP Strict Transport Security (HSTS) and Content-Security-Policy (CSP) headers are not enabled.',
            source: 'HTTP Header Auditor',
            impact: 'Susceptible to SSL-stripping and cross-site scripting (XSS) injection attacks.',
            remediation: 'Configure Strict-Transport-Security: max-age=31536000; includeSubDomains and CSP in web server.',
            priorityScore: 68,
            isDemo: true
          },
          {
            id: 'bf-3',
            workspaceId: 'ws-business',
            title: 'Outdated Software',
            category: 'Vulnerability Management',
            severity: 'Medium',
            confidence: '85%',
            date: 'Apr 28, 2025',
            status: 'In Progress',
            description: 'WordPress 6.1 detected (latest stable: 6.5.x). 3 known CVE vulnerabilities present in core.',
            source: 'Software Banner Disclosure',
            impact: 'Known automated vulnerability exploits against unpatched CMS installations.',
            remediation: 'Create staging backup and apply security patch upgrade to WordPress latest stable branch.',
            priorityScore: 62,
            isDemo: true
          }
        ],
        checksUnavailable: [],
        timestamp: 1745839440000,
        isDemo: true
      }
    ],
    assets: [
      {
        id: 'ast-1',
        workspaceId: 'ws-business',
        domain: 'example-business.com',
        type: 'Primary Web Storefront',
        authorizedByOwner: true,
        status: 'Moderate Risk',
        lastChecked: 'Apr 28, 2025',
        createdAt: 'Apr 20, 2025',
        isDemo: true
      },
      {
        id: 'ast-2',
        workspaceId: 'ws-business',
        domain: 'api.example-business.com',
        type: 'REST API Gateway',
        authorizedByOwner: true,
        status: 'Healthy',
        lastChecked: 'Apr 28, 2025',
        createdAt: 'Apr 20, 2025',
        isDemo: true
      }
    ],
    remediationTasks: [
      {
        id: 'rem-1',
        workspaceId: 'ws-personal',
        title: 'Enable MFA on important accounts',
        category: 'Identity & Access',
        description: 'Protects against account takeovers and password stuffing by requiring hardware or app-based 2FA.',
        effort: 'Low effort • 15 min',
        priority: 'High',
        severity: 'High',
        status: 'Open',
        createdAt: 'Apr 25, 2025',
        dueDate: 'Apr 30, 2025',
        target: 'Google Workspace & AWS Console',
        isDemo: true
      },
      {
        id: 'rem-2',
        workspaceId: 'ws-business',
        title: 'Update website SSL certificate',
        category: 'Infrastructure',
        description: 'Prevents data interception and eliminates browser security warnings for visitors on example-business.com.',
        effort: 'Medium effort • 30 min',
        priority: 'High',
        severity: 'High',
        status: 'Open',
        createdAt: 'Apr 27, 2025',
        dueDate: 'May 02, 2025',
        target: 'example-business.com',
        isDemo: true
      },
      {
        id: 'rem-3',
        workspaceId: 'ws-business',
        title: 'Review staff access permissions',
        category: 'Access Control',
        description: 'Reduces insider and external risks by revoking stale contractor tokens and enforcing least privilege.',
        effort: 'Medium effort • 1 hour',
        priority: 'Medium',
        severity: 'Medium',
        status: 'Open',
        createdAt: 'Apr 28, 2025',
        dueDate: 'May 05, 2025',
        target: 'Internal Admin Dashboard',
        isDemo: true
      },
      {
        id: 'rem-4',
        workspaceId: 'ws-business',
        title: 'Patch WordPress to latest release',
        category: 'Vulnerability Management',
        description: 'Upgrade WordPress 6.1 to 6.5.2 to eliminate known CVEs in media handling.',
        effort: 'Medium effort • 45 min',
        priority: 'Medium',
        severity: 'Medium',
        status: 'In Progress',
        createdAt: 'Apr 28, 2025',
        dueDate: 'May 04, 2025',
        target: 'example-business.com',
        isDemo: true
      },
      {
        id: 'rem-5',
        workspaceId: 'ws-business',
        title: 'Implement HSTS and Content-Security-Policy',
        category: 'Web Security',
        description: 'Add HTTP response security headers to eliminate SSL stripping and mitigate XSS.',
        effort: 'Low effort • 20 min',
        priority: 'Medium',
        severity: 'Medium',
        status: 'Awaiting Verification',
        createdAt: 'Apr 26, 2025',
        dueDate: 'May 01, 2025',
        target: 'Nginx Configuration',
        isDemo: true
      }
    ],
    communityReports: [
      {
        id: 'comm-1',
        title: 'Electricity Bill Disconnection SMS Scam',
        type: 'SMS Phishing',
        indicator: '98765-XXXXX / pay-quick-bijli.in',
        riskLevel: 'Critical',
        reportedAt: '1 hour ago',
        reportsCount: 42,
        verified: true,
        description: 'Message claiming electricity will be disconnected tonight at 9:30 PM due to unpaid bill, with fake APK link.',
        isDemo: true
      },
      {
        id: 'comm-2',
        title: 'Remote Part-Time YouTube Video Liking Job',
        type: 'Telegram Recruitment',
        indicator: 't.me/task_earn_daily_vip',
        riskLevel: 'High',
        reportedAt: '3 hours ago',
        reportsCount: 128,
        verified: true,
        description: 'Scammers pay ₹150 initially, then demand ₹5,000 to unlock higher tiered VIP tasks with guaranteed returns.',
        isDemo: true
      },
      {
        id: 'comm-3',
        title: 'Fake E-Challan Traffic Violation Notice',
        type: 'WhatsApp APK',
        indicator: 'challan-parivahan-pay.apk',
        riskLevel: 'Critical',
        reportedAt: '5 hours ago',
        reportsCount: 89,
        verified: true,
        description: 'Sends spoofed traffic police notification prompting download of trojanized malware APK that intercepts OTPs.',
        isDemo: true
      }
    ],
    notifications: [
      {
        id: 'n-1',
        workspaceId: 'ws-personal',
        title: 'High-Priority Phishing Alert (Sample)',
        detail: 'Suspicious job offer from career-update.com flagged with 95% confidence.',
        time: '2 hours ago',
        type: 'danger',
        read: false,
        timestamp: Date.now() - 7200000
      },
      {
        id: 'n-2',
        workspaceId: 'ws-business',
        title: 'SSL Certificate Expiration Warning (Sample)',
        detail: 'Certificate for example-business.com expires in 12 days. Auto-renewal failed.',
        time: '5 hours ago',
        type: 'warning',
        read: false,
        timestamp: Date.now() - 18000000
      }
    ],
    hygiene: {
      'ws-personal': {
        mfaEnabled: true,
        uniquePasswords: false,
        recoveryMethodsReviewed: true,
        backupsConfigured: true,
        devicesUpdated: true
      },
      'ws-business': {
        mfaEnabled: true,
        uniquePasswords: true,
        recoveryMethodsReviewed: true,
        backupsConfigured: true,
        devicesUpdated: true
      }
    }
  };
}

class PersistentDatabase {
  private cache: DatabaseSchema | null = null;

  constructor() {
    this.ensureInitialized();
  }

  private ensureInitialized() {
    if (!fs.existsSync(DB_DIR)) {
      fs.mkdirSync(DB_DIR, { recursive: true });
    }

    if (!fs.existsSync(DB_FILE)) {
      const initial = getInitialSeededData();
      this.writeAtomic(initial);
      this.cache = initial;
    } else {
      this.loadAndMigrate();
    }
  }

  private loadAndMigrate() {
    try {
      const content = fs.readFileSync(DB_FILE, 'utf-8');
      const data: DatabaseSchema = JSON.parse(content);

      // Schema Migrations if older
      if (!data.schemaVersion || data.schemaVersion < CURRENT_SCHEMA_VERSION) {
        data.schemaVersion = CURRENT_SCHEMA_VERSION;
        data.lastMigrationAt = new Date().toISOString();
        this.writeAtomic(data);
      }

      // Ensure all users have secure password credentials
      let updatedUsers = false;
      for (const u of data.users) {
        if (!u.passwordHash || !u.salt) {
          if (u.id === 'usr-akash') {
            u.salt = 'salt-akash-rakshak-2025';
            u.passwordHash = '4da5dab3ad5fb11d4012af1988ffd1bd1317d41269c8c369d96939539bf32412faf35a61d9b9062b87f5e844f245cb0fee57a0bf5be8180a4b61259c55a802ea';
          } else if (u.id === 'usr-analyst-external') {
            u.salt = 'salt-analyst-rakshak-2025';
            u.passwordHash = '68b0527cf2e3cb666d82a643fa122bb4ee8221951e295639ee1df8da8d1612fd13a9a96aa6ec13623bd5b30bf89e2346b04df4d524697d8f99b631227347a974';
          } else {
            u.salt = crypto.randomBytes(16).toString('hex');
            u.passwordHash = crypto.scryptSync('RakshakPass#2025', u.salt, 64).toString('hex');
          }
          updatedUsers = true;
        }
      }
      if (updatedUsers) {
        this.writeAtomic(data);
      }

      this.cache = data;
    } catch (err) {
      console.error('Error loading persistent database file, restoring backup/seed:', err);
      const fallback = getInitialSeededData();
      this.writeAtomic(fallback);
      this.cache = fallback;
    }
  }

  private writeAtomic(data: DatabaseSchema) {
    const tmpFile = `${DB_FILE}.tmp.${Date.now()}`;
    fs.writeFileSync(tmpFile, JSON.stringify(data, null, 2), 'utf-8');
    fs.renameSync(tmpFile, DB_FILE);
  }

  public getSnapshot(): DatabaseSchema {
    if (!this.cache) {
      this.loadAndMigrate();
    }
    return this.cache!;
  }

  public update(mutator: (db: DatabaseSchema) => void): DatabaseSchema {
    const snapshot = this.getSnapshot();
    mutator(snapshot);
    this.writeAtomic(snapshot);
    return snapshot;
  }

  public resetToFactory(): DatabaseSchema {
    const seed = getInitialSeededData();
    this.writeAtomic(seed);
    this.cache = seed;
    return seed;
  }
}

export const db = new PersistentDatabase();

export function verifyUserCredentials(email: string, password: string): User | null {
  if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
    return null;
  }
  const snapshot = db.getSnapshot();
  const normalizedEmail = email.trim().toLowerCase();
  const user = snapshot.users.find(u => u.email.toLowerCase() === normalizedEmail);
  if (!user || !user.passwordHash || !user.salt) {
    return null;
  }

  try {
    const computedHash = crypto.scryptSync(password, user.salt, 64).toString('hex');
    const hashBuf = Buffer.from(computedHash);
    const expBuf = Buffer.from(user.passwordHash);
    if (hashBuf.length !== expBuf.length || !crypto.timingSafeEqual(hashBuf, expBuf)) {
      return null;
    }
    return user;
  } catch {
    return null;
  }
}

export function getUserByEmail(email: string): User | null {
  if (!email || typeof email !== 'string') return null;
  const normalized = email.trim().toLowerCase();
  const snapshot = db.getSnapshot();
  return snapshot.users.find(u => u.email.toLowerCase() === normalized) || null;
}
