export type ViewMode = 
  | 'overview' 
  | 'personal' 
  | 'business' 
  | 'graph' 
  | 'copilot' 
  | 'threat' 
  | 'remediation' 
  | 'reports' 
  | 'settings'
  | 'community';

export type RiskLevel = 'Low Indicated Risk' | 'Moderate Risk' | 'High Risk' | 'Critical Risk' | 'Good';
export type Severity = 'Critical' | 'High' | 'Medium' | 'Low';

export interface Finding {
  id: string;
  title: string;
  category?: string;
  severity: Severity;
  confidence: string;
  date?: string;
  status?: 'Open' | 'In Progress' | 'Resolved' | 'Awaiting Verification';
  description?: string;
  source?: string;
  impact?: string;
  remediation?: string;
  isDemo?: boolean;
  priorityScore?: number;
}

export interface ScanResult {
  id: string;
  title: string;
  type: 'message' | 'url' | 'email' | 'image' | 'job';
  target: string;
  riskLevel: RiskLevel;
  score: number;
  confidence: string;
  date: string;
  timestamp: number;
  checksCompleted: string;
  summary: string;
  keyFindings: Finding[];
  safetyActions: string[];
  isDemo?: boolean;
  threatIntelSource?: string;
  uncertaintyNotes?: string;
}

export interface BusinessAssessment {
  id: string;
  domain: string;
  industry: string;
  businessSize: string;
  lastAssessment: string;
  status: 'Completed' | 'In Progress' | 'Scheduled' | 'Inconclusive';
  overallScore: number;
  riskClassification: string;
  findings: Finding[];
  isDemo?: boolean;
  checksUnavailable?: string[];
  observedEvidence?: {
    tlsIssuer?: string;
    tlsDaysRemaining?: number;
    tlsProtocol?: string;
    httpStatus?: number;
    hstsPresent?: boolean;
    cspPresent?: boolean;
    xFramePresent?: boolean;
  };
}

export interface RemediationTask {
  id: string;
  workspaceId?: string;
  findingId?: string;
  title: string;
  category: string;
  description: string;
  effort: string;
  priority: 'Critical' | 'High' | 'Medium' | 'Low';
  severity: Severity;
  status: 'Open' | 'In Progress' | 'Awaiting Verification' | 'Resolved';
  createdAt: string;
  dueDate: string;
  target: string;
  isDemo?: boolean;
  completedAt?: string;
  assignee?: string;
  verificationStatus?: 'unverified' | 'user-reported' | 'independently-verified' | 'verification-failed';
  verificationDetails?: string;
}

export interface GraphNode {
  id: string;
  label: string;
  type: 'Domain' | 'URL' | 'Finding' | 'Indicator' | 'Organization' | 'Asset' | 'Report';
  category: 'domain' | 'url' | 'finding' | 'indicator' | 'organization' | 'asset' | 'report';
  risk: 'Critical' | 'High' | 'Medium' | 'Low';
  x?: number;
  y?: number;
  details: {
    reputation?: string;
    relatedFindings?: number;
    relatedAssets?: number;
    firstSeen?: string;
    severity?: string;
    target?: string;
    channel?: string;
    source?: string;
    provenance?: string;
    observationTime?: string;
    uncertainty?: 'None (Direct Observation)' | 'Low (Verified Feed)' | 'Medium (Heuristic Inference)' | 'High (Unverified)';
    isDemo?: boolean;
    [key: string]: any;
  };
}

export interface GraphLink {
  source: string;
  target: string;
  relation: string;
  confirmed: boolean;
  evidenceSource?: string;
  provenance?: string;
  uncertainty?: string;
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}

export interface CommunityReport {
  id: string;
  title: string;
  type: string;
  indicator: string;
  riskLevel: 'Critical' | 'High' | 'Medium' | 'Low';
  reportedAt: string;
  reportsCount: number;
  verified: boolean;
  description: string;
  isDemo?: boolean;
}

export interface NotificationItem {
  id: string;
  workspaceId?: string;
  title: string;
  detail: string;
  time: string;
  type: 'danger' | 'warning' | 'info';
  read?: boolean;
  timestamp?: number;
}

export interface OverviewData {
  posture: {
    status: string;
    score: number;
    change: string;
    trend: Array<{ date: string; score: number }>;
  };
  metrics: {
    highPriorityFindings: number;
    highPriorityChange: string;
    scansCompleted: number;
    scansChange: string;
    recommendationsPending: number;
    recommendationsChange: string;
  };
  recentFindings: Finding[];
  priorityActions: RemediationTask[];
  recentActivity: Array<{
    id: string;
    type: string;
    detail: string;
    time: string;
    status: string;
    statusType: 'danger' | 'warning' | 'info' | 'success';
  }>;
}

export interface WorkspaceUser {
  id: string;
  name: string;
  email: string;
  role: string;
  currentWorkspaceId: string;
}

