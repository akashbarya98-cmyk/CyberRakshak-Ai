import { Finding, ScanResult, BusinessAssessment, RemediationTask, GraphNode, GraphLink, CommunityReport } from '../types';

export const INITIAL_FINDINGS: Finding[] = [
  { id: 'f-1', title: 'Suspicious Job Offer (Phishing)', category: 'Phishing', severity: 'High', confidence: '95%', date: 'Apr 28, 2025', status: 'Open' },
  { id: 'f-2', title: 'Unsecured Website (HTTP)', category: 'Website', severity: 'Medium', confidence: '78%', date: 'Apr 27, 2025', status: 'Open' },
  { id: 'f-3', title: 'Credential Leak Detected', category: 'Credentials', severity: 'High', confidence: '92%', date: 'Apr 26, 2025', status: 'In Progress' },
  { id: 'f-4', title: 'Weak Password Policy', category: 'Account', severity: 'Medium', confidence: '70%', date: 'Apr 25, 2025', status: 'Open' },
  { id: 'f-5', title: 'Suspicious SMS', category: 'Social Engineering', severity: 'Low', confidence: '65%', date: 'Apr 24, 2025', status: 'Resolved' }
];

export const INITIAL_PRIORITY_ACTIONS: RemediationTask[] = [
  {
    id: 'rem-1',
    title: 'Enable MFA on important accounts',
    category: 'Identity',
    description: 'Protects against account takeovers',
    effort: 'Low effort • 15 min',
    priority: 'High',
    severity: 'High',
    status: 'Open',
    createdAt: 'Apr 25, 2025',
    dueDate: 'Apr 30, 2025',
    target: 'Google Workspace & AWS Console'
  },
  {
    id: 'rem-2',
    title: 'Update website SSL certificate',
    category: 'Infrastructure',
    description: 'Prevents data interception',
    effort: 'Medium effort • 30 min',
    priority: 'High',
    severity: 'High',
    status: 'Open',
    createdAt: 'Apr 27, 2025',
    dueDate: 'May 02, 2025',
    target: 'example-business.com'
  },
  {
    id: 'rem-3',
    title: 'Review staff access permissions',
    category: 'Access Control',
    description: 'Reduces insider and external risks',
    effort: 'Medium effort • 1 hour',
    priority: 'Medium',
    severity: 'Medium',
    status: 'Open',
    createdAt: 'Apr 28, 2025',
    dueDate: 'May 05, 2025',
    target: 'Internal Admin Dashboard'
  }
];

export const INITIAL_SCAN_RESULT: ScanResult = {
  id: 'scan-1',
  title: 'Suspicious Job Offer (Phishing)',
  type: 'message',
  target: 'career-update.com / WhatsApp SMS',
  riskLevel: 'High Risk',
  score: 85,
  confidence: '95%',
  date: 'Apr 28, 2025, 11:24 AM',
  timestamp: Date.now() - 2 * 60 * 60 * 1000,
  checksCompleted: '8 / 10',
  summary: 'This message shows multiple signs of a phishing attempt.',
  keyFindings: [
    {
      id: 'f1',
      title: 'Urgency and pressure tactics',
      description: 'The message uses urgent language to create pressure.',
      severity: 'High',
      confidence: 'High confidence',
      source: 'Linguistic Heuristic'
    },
    {
      id: 'f2',
      title: 'Suspicious sender domain',
      description: 'Sender domain (career-update.com) looks like a lookalike.',
      severity: 'High',
      confidence: 'High confidence',
      source: 'Lookalike Analysis'
    },
    {
      id: 'f3',
      title: 'Request for upfront payment',
      description: 'Asks for a fee before the job offer is confirmed.',
      severity: 'Medium',
      confidence: 'Medium confidence',
      source: 'Payment Pattern Check'
    }
  ],
  safetyActions: [
    'Verify the sender independently via official direct channels.',
    'Do not transfer any upfront registration or screening fee.',
    'Never share OTPs, bank passwords, or ID card photocopies via chat.',
    'Report the sender number to the National Cyber Crime Portal.'
  ]
};

export const INITIAL_ASSESSMENT: BusinessAssessment = {
  id: 'assess-1',
  domain: 'example-business.com',
  industry: 'E-commerce',
  businessSize: '11-50 employees',
  lastAssessment: 'Apr 28, 2025',
  status: 'In Progress',
  overallScore: 68,
  riskClassification: 'Moderate Risk',
  findings: [
    {
      id: 'bf-1',
      title: 'SSL Certificate Expiring Soon',
      description: 'Expires in 12 days',
      severity: 'High',
      confidence: '95%',
      impact: 'Will cause browser warning screens and transaction failures.',
      remediation: 'Renew TLS certificate on web server or CDN console.'
    },
    {
      id: 'bf-2',
      title: 'Missing Security Headers',
      description: 'HSTS not enabled',
      severity: 'Medium',
      confidence: '90%',
      impact: 'Enables man-in-the-middle attacks and SSL stripping.',
      remediation: 'Add Strict-Transport-Security and CSP headers.'
    },
    {
      id: 'bf-3',
      title: 'Outdated Software',
      description: 'WordPress 6.1 (latest: 6.5)',
      severity: 'Medium',
      confidence: '85%',
      impact: 'Known CVE vulnerabilities are present in outdated core.',
      remediation: 'Upgrade WordPress CMS to latest stable branch.'
    }
  ]
};

export const INITIAL_GRAPH_NODES: GraphNode[] = [
  { 
    id: 'n-domain-1', 
    label: 'example.com', 
    type: 'Domain', 
    category: 'domain', 
    risk: 'Medium', 
    x: 400, 
    y: 280,
    details: { 
      reputation: 'Checking...', 
      relatedFindings: 2, 
      relatedAssets: 1, 
      firstSeen: 'Apr 27, 2025' 
    } 
  },
  { 
    id: 'n-find-1', 
    label: 'Fake Job Offer', 
    type: 'Finding', 
    category: 'finding', 
    risk: 'High', 
    x: 340, 
    y: 120,
    details: { 
      severity: 'High', 
      type: 'Phishing', 
      target: 'career-update.com',
      reputation: 'Flagged Malicious',
      firstSeen: 'Apr 28, 2025'
    } 
  },
  { 
    id: 'n-find-2', 
    label: 'Phishing', 
    type: 'Finding', 
    category: 'finding', 
    risk: 'High', 
    x: 200, 
    y: 180,
    details: { 
      pattern: 'Urgency + Payment Request',
      severity: 'High',
      firstSeen: 'Apr 26, 2025'
    } 
  },
  { 
    id: 'n-rep-1', 
    label: 'User Report', 
    type: 'Report', 
    category: 'report', 
    risk: 'High', 
    x: 520, 
    y: 170,
    details: { 
      channel: 'WhatsApp SMS', 
      source: 'Akash Sharma',
      reputation: 'Verified Suspicious',
      firstSeen: 'Apr 28, 2025'
    } 
  },
  { 
    id: 'n-asset-1', 
    label: 'Web Asset', 
    type: 'Asset', 
    category: 'asset', 
    risk: 'Low', 
    x: 530, 
    y: 390,
    details: { 
      host: 'Production Web App',
      reputation: 'Healthy',
      firstSeen: 'Apr 20, 2025'
    } 
  },
  { 
    id: 'n-org-1', 
    label: 'Org: Example Inc.', 
    type: 'Organization', 
    category: 'organization', 
    risk: 'Low', 
    x: 400, 
    y: 440,
    details: { 
      status: 'Declared Workspace',
      reputation: 'Verified Business',
      firstSeen: 'Apr 15, 2025'
    } 
  },
  { 
    id: 'n-ind-1', 
    label: 'Suspicious SMS', 
    type: 'Indicator', 
    category: 'indicator', 
    risk: 'Medium', 
    x: 220, 
    y: 380,
    details: { 
      origin: 'Spoofed Sender ID',
      reputation: 'Suspicious',
      firstSeen: 'Apr 24, 2025'
    } 
  }
];

export const INITIAL_GRAPH_LINKS: GraphLink[] = [
  { source: 'n-find-1', target: 'n-domain-1', relation: 'References domain', confirmed: true },
  { source: 'n-find-2', target: 'n-find-1', relation: 'Classified as', confirmed: true },
  { source: 'n-rep-1', target: 'n-domain-1', relation: 'Reported indicator', confirmed: true },
  { source: 'n-domain-1', target: 'n-asset-1', relation: 'Belongs to asset', confirmed: true },
  { source: 'n-asset-1', target: 'n-org-1', relation: 'Managed by', confirmed: true },
  { source: 'n-ind-1', target: 'n-find-1', relation: 'Associated pattern', confirmed: false },
  { source: 'n-ind-1', target: 'n-domain-1', relation: 'Embedded redirect', confirmed: false }
];

export const INITIAL_COMMUNITY_REPORTS: CommunityReport[] = [
  {
    id: 'comm-1',
    title: 'Electricity Bill Disconnection SMS Scam',
    type: 'SMS Phishing',
    indicator: '98765-XXXXX / pay-quick-bijli.in',
    riskLevel: 'Critical',
    reportedAt: '1 hour ago',
    reportsCount: 42,
    verified: true,
    description: 'Message claiming electricity will be disconnected tonight at 9:30 PM due to unpaid bill, with fake APK link.'
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
    description: 'Scammers pay ₹150 initially, then demand ₹5,000 to unlock higher tiered VIP tasks with guaranteed returns.'
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
    description: 'Sends spoofed traffic police notification prompting download of trojanized malware APK that intercepts OTPs.'
  }
];
