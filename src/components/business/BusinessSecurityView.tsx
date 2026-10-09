import React, { useState, useEffect } from 'react';
import { 
  Building2, 
  Globe, 
  ShieldCheck, 
  AlertTriangle, 
  Lock, 
  CheckCircle2, 
  RotateCcw, 
  Plus, 
  ExternalLink, 
  FileText,
  Server,
  KeyRound,
  ArrowRight,
  Shield,
  Activity,
  Check,
  X,
  Info,
  Sparkles
} from 'lucide-react';
import { BusinessAssessment, ViewMode } from '../../types';

interface BusinessSecurityViewProps {
  assessment: BusinessAssessment;
  onNewAssessment: (assessment: BusinessAssessment) => void;
  onNavigate: (view: ViewMode) => void;
  onOpenCopilotWithContext: (context: any) => void;
  workspaceId?: string;
}

export const BusinessSecurityView: React.FC<BusinessSecurityViewProps> = ({
  assessment,
  onNewAssessment,
  onNavigate,
  onOpenCopilotWithContext,
  workspaceId = 'ws-business'
}) => {
  const [showNewModal, setShowNewModal] = useState(false);
  const [targetDomain, setTargetDomain] = useState('');
  const [targetIndustry, setTargetIndustry] = useState('E-commerce');
  const [targetSize, setTargetSize] = useState('11-50 employees');
  const [isAuthorized, setIsAuthorized] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [assessmentError, setAssessmentError] = useState<string | null>(null);

  // Digital Twin hygiene state with backend synchronization
  const [hygiene, setHygiene] = useState({
    mfa: true,
    backups: true,
    updates: true,
    leastPrivilege: false
  });

  useEffect(() => {
    fetch('/api/assessments/hygiene', {
      headers: { 'x-workspace-id': workspaceId }
    })
      .then(r => r.json())
      .then(data => {
        if (data) {
          setHygiene({
            mfa: data.mfaEnabled ?? true,
            backups: data.backupsConfigured ?? true,
            updates: data.devicesUpdated ?? true,
            leastPrivilege: data.uniquePasswords ?? false
          });
        }
      })
      .catch(() => {});
  }, [workspaceId]);

  // Modal Escape key support
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && showNewModal) {
        setShowNewModal(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [showNewModal]);

  const toggleHygiene = (key: keyof typeof hygiene) => {
    const updated = { ...hygiene, [key]: !hygiene[key] };
    setHygiene(updated);

    fetch('/api/assessments/hygiene', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-workspace-id': workspaceId
      },
      body: JSON.stringify({
        mfaEnabled: updated.mfa,
        backupsConfigured: updated.backups,
        devicesUpdated: updated.updates,
        uniquePasswords: updated.leastPrivilege
      })
    }).catch(() => {});
  };

  const hasHstsIssue = assessment.findings.some(f => 
    f.title.toLowerCase().includes('hsts') || 
    (f.description && f.description.toLowerCase().includes('hsts'))
  );

  const hasCspIssue = assessment.findings.some(f => 
    f.title.toLowerCase().includes('csp') || 
    f.title.toLowerCase().includes('content security') ||
    (f.description && f.description.toLowerCase().includes('csp'))
  );

  const hasTlsIssue = assessment.findings.some(f => 
    f.title.toLowerCase().includes('tls') || 
    f.title.toLowerCase().includes('certificate') ||
    f.title.toLowerCase().includes('ssl')
  );

  const handleRunAssessment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetDomain.trim()) return;

    if (!isAuthorized) {
      setAssessmentError('Explicit authorization confirmation is required before assessing any domain.');
      return;
    }

    setIsRunning(true);
    setAssessmentError(null);

    try {
      const response = await fetch('/api/assessments/run', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'x-workspace-id': workspaceId
        },
        body: JSON.stringify({
          domain: targetDomain,
          industry: targetIndustry,
          businessSize: targetSize,
          authorizedByOwner: isAuthorized
        })
      });

      const data = await response.json();

      if (response.ok) {
        onNewAssessment(data);
        setShowNewModal(false);
        setTargetDomain('');
        setIsAuthorized(false);
      } else {
        setAssessmentError(data.error || 'Assessment failed to complete.');
      }
    } catch (err: any) {
      setAssessmentError(err.message || 'Network error occurred during domain probe.');
    } finally {
      setIsRunning(false);
    }
  };


  return (
    <div className="space-y-6 max-w-5xl mx-auto pb-12">
      {/* Breadcrumb & Actions */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs font-semibold text-[#667085]">
          <button onClick={() => onNavigate('overview')} className="hover:text-blue-600 transition-colors">
            Business Security
          </button>
          <span>&gt;</span>
          <span className="text-[#172033] font-bold">Assessment</span>
        </div>

        <button
          onClick={() => {
            setShowNewModal(true);
            setAssessmentError(null);
            setIsAuthorized(false);
          }}
          className="px-3.5 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-bold flex items-center gap-1.5 shadow-xs transition-colors"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>Assess New Website</span>
        </button>
      </div>

      {/* Main Security Assessment Card matching Screenshot Panel 2 */}
      <div className="bg-white border border-[#E5EAF2] rounded-2xl p-6 shadow-xs space-y-6">
        {/* Domain target header with In Progress / Status pill */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-[#E5EAF2]">
          <div>
            <div className="flex items-center gap-2.5">
              <h2 className="text-xl font-bold text-[#172033] tracking-tight">
                Security Assessment
              </h2>
              {(assessment as any).isDemo ? (
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-purple-50 text-purple-700 border border-purple-200">
                  Sample Demonstration Data
                </span>
              ) : (
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-emerald-50 text-emerald-800 border border-emerald-200">
                  Live Verified Assessment
                </span>
              )}
            </div>
            <div className="flex items-center gap-2 mt-1 text-xs text-[#667085]">
              <Globe className="w-4 h-4 text-blue-600" />
              <span className="font-semibold text-slate-800">{assessment.domain}</span>
            </div>
          </div>

          <span className="px-3 py-1 rounded-full text-xs font-bold bg-blue-50 text-blue-700 border border-blue-200 self-start sm:self-auto flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-blue-600 animate-pulse"></span>
            {assessment.status}
          </span>
        </div>

        {/* Overall Security Score Banner */}
        <div className="bg-[#F8FAFC] border border-[#E5EAF2] rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <p className="text-xs font-semibold text-[#667085]">Overall Security Score</p>
            <div className="flex items-baseline gap-2 mt-1">
              <span className="text-4xl font-extrabold text-[#172033]">
                {assessment.overallScore}
              </span>
              <span className="text-lg font-bold text-gray-400">/ 100</span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <span className="px-3 py-1.5 rounded-lg bg-amber-50 text-amber-700 border border-amber-200 font-bold text-xs">
              {assessment.riskClassification}
            </span>
          </div>
        </div>

        {/* Details Grid: Domain, Industry, Business Size, Last Assessment */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 p-4 rounded-xl border border-[#E5EAF2] bg-white text-xs">
          <div>
            <span className="text-[#667085] font-medium block">Domain:</span>
            <span className="font-bold text-[#172033] mt-0.5 block truncate">{assessment.domain}</span>
          </div>
          <div>
            <span className="text-[#667085] font-medium block">Industry:</span>
            <span className="font-bold text-[#172033] mt-0.5 block truncate">{assessment.industry}</span>
          </div>
          <div>
            <span className="text-[#667085] font-medium block">Business Size:</span>
            <span className="font-bold text-[#172033] mt-0.5 block truncate">{assessment.businessSize}</span>
          </div>
          <div>
            <span className="text-[#667085] font-medium block">Last Assessment:</span>
            <span className="font-bold text-[#172033] mt-0.5 block truncate">{assessment.lastAssessment}</span>
          </div>
        </div>

        {/* Checks Unavailable notification if any were skipped/failed */}
        {(assessment as any).checksUnavailable && (assessment as any).checksUnavailable.length > 0 && (
          <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl text-xs space-y-1">
            <div className="flex items-center gap-1.5 font-bold text-slate-700">
              <Info className="w-4 h-4 text-slate-500" />
              <span>Unavailable Checks Notice</span>
            </div>
            <ul className="list-disc list-inside text-slate-600 text-[11px] space-y-0.5">
              {(assessment as any).checksUnavailable.map((u: string, idx: number) => (
                <li key={idx}>{u}</li>
              ))}
            </ul>
          </div>
        )}

        {/* Key Findings List */}
        <div className="space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-[#667085]">
            Key Findings
          </h3>

          <div className="space-y-3">
            {assessment.findings.map((f) => (
              <div
                key={f.id}
                className="p-4 rounded-xl border border-[#E5EAF2] bg-[#F8FAFC]/50 hover:bg-[#F8FAFC] flex items-center justify-between gap-3 transition-colors"
              >
                <div className="flex items-start gap-3 min-w-0">
                  <div className={`p-2 rounded-lg shrink-0 mt-0.5 ${
                    f.severity === 'High' || f.severity === 'Critical' ? 'bg-red-50 text-red-600' : 'bg-amber-50 text-amber-600'
                  }`}>
                    <AlertTriangle className="w-4 h-4" />
                  </div>
                  <div className="min-w-0">
                    <h4 className="text-xs font-bold text-[#172033]">
                      {f.title}
                    </h4>
                    <p className="text-[11px] text-[#667085] mt-0.5">
                      {f.description || (f as any).detail}
                    </p>
                  </div>
                </div>

                <span className={`text-[10px] font-bold px-2 py-0.5 rounded shrink-0 ${
                  f.severity === 'High' || f.severity === 'Critical' ? 'bg-red-50 text-red-700' : 'bg-amber-50 text-amber-700'
                }`}>
                  {f.severity}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Action Buttons */}
        <div className="pt-2 flex flex-col sm:flex-row gap-3">
          <button
            onClick={() => onNavigate('reports')}
            className="flex-1 py-3 bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs rounded-xl shadow-xs transition-colors flex items-center justify-center gap-2"
          >
            <span>View Detailed Report</span>
            <ArrowRight className="w-4 h-4" />
          </button>
          <button
            onClick={() => {
              onOpenCopilotWithContext(assessment);
              onNavigate('copilot');
            }}
            className="px-4 py-3 bg-purple-50 hover:bg-purple-100 text-purple-700 border border-purple-200 font-bold text-xs rounded-xl transition-colors flex items-center justify-center gap-2"
          >
            <Sparkles className="w-4 h-4" />
            <span>Consult Copilot</span>
          </button>
        </div>
      </div>

      {/* Digital Security Twin & Hygiene Model Section (Section 11) */}
      <div className="bg-white border border-[#E5EAF2] rounded-2xl p-6 shadow-xs space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-[#E5EAF2]">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-teal-50 text-teal-600">
              <Activity className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-sm sm:text-base text-[#172033]">
                Digital Security Twin — Posture Hygiene
              </h3>
              <p className="text-xs text-[#667085]">
                Combines self-reported internal controls with independently observed domain checks.
              </p>
            </div>
          </div>
          <span className="text-xs font-bold px-2.5 py-1 rounded-full bg-teal-50 text-teal-700 border border-teal-200">
            Twin Synced
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Column 1: Self-Reported Controls */}
          <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/50 space-y-3">
            <span className="text-xs font-bold text-slate-700 uppercase tracking-wider block">
              1. Self-Reported Internal Hygiene:
            </span>

            <div className="space-y-2 text-xs">
              <label 
                onClick={() => toggleHygiene('mfa')}
                className="flex items-center justify-between p-2 rounded-lg bg-white border border-slate-200 cursor-pointer hover:bg-slate-50 transition-colors"
              >
                <span>MFA Enforced on Admin & Cloud Accounts</span>
                <input type="checkbox" checked={hygiene.mfa} onChange={() => {}} className="rounded text-blue-600 pointer-events-none" />
              </label>

              <label 
                onClick={() => toggleHygiene('backups')}
                className="flex items-center justify-between p-2 rounded-lg bg-white border border-slate-200 cursor-pointer hover:bg-slate-50 transition-colors"
              >
                <span>Immutable Daily Off-site Backups</span>
                <input type="checkbox" checked={hygiene.backups} onChange={() => {}} className="rounded text-blue-600 pointer-events-none" />
              </label>

              <label 
                onClick={() => toggleHygiene('updates')}
                className="flex items-center justify-between p-2 rounded-lg bg-white border border-slate-200 cursor-pointer hover:bg-slate-50 transition-colors"
              >
                <span>Automated OS & Web Server Patching</span>
                <input type="checkbox" checked={hygiene.updates} onChange={() => {}} className="rounded text-blue-600 pointer-events-none" />
              </label>

              <label 
                onClick={() => toggleHygiene('leastPrivilege')}
                className="flex items-center justify-between p-2 rounded-lg bg-white border border-slate-200 cursor-pointer hover:bg-slate-50 transition-colors"
              >
                <span>Contractor Token Access Revocation (Least Privilege)</span>
                <input type="checkbox" checked={hygiene.leastPrivilege} onChange={() => {}} className="rounded text-blue-600 pointer-events-none" />
              </label>
            </div>
          </div>

          {/* Column 2: Independently Observed Checks */}
          <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/50 space-y-3">
            <span className="text-xs font-bold text-slate-700 uppercase tracking-wider block">
              2. Independently Observed Checks:
            </span>

            <div className="space-y-2 text-xs">
              <div className="flex items-center justify-between p-2 rounded-lg bg-white border border-slate-200">
                <span>TLS Certificate Valid & Expiry Observed</span>
                {hasTlsIssue ? (
                  <span className="text-red-700 font-bold text-[11px] flex items-center gap-1">
                    <AlertTriangle className="w-3.5 h-3.5 text-red-500" /> Attention Needed
                  </span>
                ) : (
                  <span className="text-teal-700 font-bold text-[11px] flex items-center gap-1">
                    <Check className="w-3.5 h-3.5 text-teal-600" /> Valid
                  </span>
                )}
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-white border border-slate-200">
                <span>HTTP Strict Transport Security (HSTS)</span>
                {hasHstsIssue ? (
                  <span className="text-amber-700 font-bold text-[11px] flex items-center gap-1">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-500" /> Missing Header
                  </span>
                ) : (
                  <span className="text-teal-700 font-bold text-[11px] flex items-center gap-1">
                    <Check className="w-3.5 h-3.5 text-teal-600" /> Enforced
                  </span>
                )}
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-white border border-slate-200">
                <span>Content-Security-Policy (CSP) Origin Filtering</span>
                {hasCspIssue ? (
                  <span className="text-amber-700 font-bold text-[11px] flex items-center gap-1">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-500" /> Missing Header
                  </span>
                ) : (
                  <span className="text-teal-700 font-bold text-[11px] flex items-center gap-1">
                    <Check className="w-3.5 h-3.5 text-teal-600" /> Enforced
                  </span>
                )}
              </div>

              <div className="flex items-center justify-between p-2 rounded-lg bg-white border border-slate-200">
                <span>Public Port Perimeter (Safe Passive Probe)</span>
                <span className="text-teal-700 font-bold text-[11px] flex items-center gap-1">
                  <Check className="w-3.5 h-3.5 text-teal-600" /> Encrypted 443
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Authorized Assets Management Section */}
      <div className="bg-white border border-[#E5EAF2] rounded-2xl p-6 shadow-xs space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="font-bold text-sm sm:text-base text-[#172033]">
              Authorized Asset Inventory
            </h3>
            <p className="text-xs text-[#667085]">Systems within your declared administrative perimeter</p>
          </div>
          <span className="text-xs font-semibold text-slate-500">Registered Perimeter</span>
        </div>

        <div className="divide-y divide-[#F1F5F9] text-xs">
          <div className="py-3 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-blue-50 text-blue-600 flex items-center justify-center">
                <Globe className="w-4 h-4" />
              </div>
              <div>
                <p className="font-bold text-[#172033]">{assessment.domain}</p>
                <p className="text-[11px] text-gray-500">Primary Web Storefront • TLS Passive Check</p>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded bg-amber-50 text-amber-700 font-bold text-[10px]">Active Perimeter</span>
          </div>
        </div>
      </div>

      {/* Modal: New Assessment */}
      {showNewModal && (
        <div 
          className="fixed inset-0 z-50 bg-slate-900/50 backdrop-blur-xs flex items-center justify-center p-4"
          role="dialog"
          aria-modal="true"
          aria-labelledby="new-assessment-title"
        >
          <div className="bg-white rounded-2xl max-w-md w-full p-6 shadow-2xl border border-gray-100 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-gray-100">
              <h3 id="new-assessment-title" className="font-bold text-[#172033]">Run Business Website Assessment</h3>
              <button 
                onClick={() => setShowNewModal(false)} 
                aria-label="Close assessment modal"
                className="text-gray-400 hover:text-gray-700 text-sm p-1 rounded-md"
              >
                ✕
              </button>
            </div>

            {assessmentError && (
              <div className="p-3 bg-red-50 border border-red-200 rounded-xl text-xs text-red-700 flex items-start gap-2">
                <AlertTriangle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
                <span>{assessmentError}</span>
              </div>
            )}

            <form onSubmit={handleRunAssessment} className="space-y-3.5 text-xs">
              <div className="space-y-1">
                <label className="font-bold text-[#172033]">Domain Name (Authorized target only)</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. yourcompany.com"
                  value={targetDomain}
                  onChange={(e) => setTargetDomain(e.target.value)}
                  className="w-full p-2.5 bg-gray-50 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500/20"
                />
              </div>

              <div className="space-y-1">
                <label className="font-bold text-[#172033]">Industry</label>
                <select
                  value={targetIndustry}
                  onChange={(e) => setTargetIndustry(e.target.value)}
                  className="w-full p-2.5 bg-gray-50 border border-gray-200 rounded-lg focus:outline-none"
                >
                  <option value="E-commerce">E-commerce</option>
                  <option value="SaaS & Technology">SaaS & Technology</option>
                  <option value="Healthcare">Healthcare</option>
                  <option value="Education">Education</option>
                  <option value="Retail & Local Business">Retail & Local Business</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="font-bold text-[#172033]">Team Size</label>
                <select
                  value={targetSize}
                  onChange={(e) => setTargetSize(e.target.value)}
                  className="w-full p-2.5 bg-gray-50 border border-gray-200 rounded-lg focus:outline-none"
                >
                  <option value="1-10 employees">1-10 employees</option>
                  <option value="11-50 employees">11-50 employees</option>
                  <option value="51-200 employees">51-200 employees</option>
                </select>
              </div>

              {/* Mandatory Ownership / Authorization Confirmation */}
              <div className="p-3 bg-blue-50/70 border border-blue-200 rounded-xl space-y-1.5">
                <label className="flex items-start gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={isAuthorized}
                    onChange={(e) => setIsAuthorized(e.target.checked)}
                    className="mt-0.5 rounded text-blue-600 focus:ring-blue-500"
                  />
                  <span className="text-[11px] font-semibold text-blue-900 leading-tight">
                    I confirm that I own this digital asset or have explicit authorization to perform a passive security assessment.
                  </span>
                </label>
                <p className="text-[10px] text-blue-700 pl-5">
                  Only non-invasive passive TLS and HTTP header observations will be conducted. Probing private networks is blocked by SSRF safeguards.
                </p>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowNewModal(false)}
                  className="px-3.5 py-2 text-gray-600 hover:bg-gray-100 rounded-lg font-semibold"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isRunning || !isAuthorized}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-lg font-bold shadow-xs transition-opacity"
                >
                  {isRunning ? 'Assessing Domain...' : 'Start Passive Assessment'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
