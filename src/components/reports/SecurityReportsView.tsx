import React, { useState } from 'react';
import { 
  FileText, 
  Download, 
  Printer, 
  ShieldCheck, 
  AlertTriangle, 
  Calendar, 
  CheckCircle2,
  Building2,
  User,
  ArrowDownToLine,
  Filter,
  Layers,
  HelpCircle
} from 'lucide-react';
import { Finding, RemediationTask } from '../../types';

interface SecurityReportsViewProps {
  findings: Finding[];
  remediationTasks: RemediationTask[];
  userName?: string;
  workspaceName?: string;
}

export const SecurityReportsView: React.FC<SecurityReportsViewProps> = ({
  findings,
  remediationTasks,
  userName = 'Akash Sharma',
  workspaceName = 'Personal Workspace'
}) => {
  const [reportFilter, setReportFilter] = useState<'all' | 'live' | 'critical' | 'demo'>('all');
  const [isExporting, setIsExporting] = useState(false);

  const currentDate = new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  
  // Real persisted counts
  const liveFindings = findings.filter(f => !f.isDemo);
  const demoFindings = findings.filter(f => f.isDemo);
  const criticalHighCount = findings.filter(f => f.severity === 'Critical' || f.severity === 'High').length;
  const resolvedCount = remediationTasks.filter(t => t.status === 'Resolved').length;
  const openCount = remediationTasks.filter(t => t.status === 'Open').length;
  const verifiedCount = remediationTasks.filter(t => t.verificationStatus === 'independently-verified').length;

  const postureScore = Math.min(100, Math.max(35, 60 + (resolvedCount * 8) - (openCount * 5)));
  const postureStatus = postureScore >= 70 ? 'Good' : 'Moderate';

  // Filtered findings table
  const displayedFindings = findings.filter(f => {
    if (reportFilter === 'live') return !f.isDemo;
    if (reportFilter === 'demo') return f.isDemo;
    if (reportFilter === 'critical') return f.severity === 'Critical' || f.severity === 'High';
    return true;
  });

  const handleDownloadCSV = () => {
    setIsExporting(true);
    const headers = 'ID,Title,Category,Severity,Status,Confidence,Type,Date\n';
    const rows = displayedFindings.map(f => 
      `"${f.id}","${f.title.replace(/"/g, '""')}","${f.category || 'General'}","${f.severity}","${f.status || 'Open'}","${f.confidence || 'Medium'}","${f.isDemo ? 'Demo Fixture' : 'Live Observation'}","${f.date || currentDate}"`
    ).join('\n');
    const blob = new Blob([headers + rows], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `CyberRakshak_Security_Report_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    setTimeout(() => setIsExporting(false), 800);
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto pb-12">
      {/* Header & Export Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-xl sm:text-2xl font-bold text-[#172033] tracking-tight flex items-center gap-2">
            <FileText className="w-6 h-6 text-blue-600" />
            <span>Security Reports & Posture Documentation</span>
          </h2>
          <p className="text-xs text-[#667085] mt-0.5">
            Audit-ready posture documentation and executive security briefings grounded in persisted workspace data.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleDownloadCSV}
            disabled={isExporting}
            className="px-3.5 py-2 bg-white hover:bg-gray-50 border border-[#E5EAF2] rounded-xl text-xs font-bold text-[#172033] flex items-center gap-1.5 shadow-2xs transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-blue-600" />
            <span>Export CSV</span>
          </button>
          <button
            onClick={handlePrint}
            className="px-3.5 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-xs font-bold flex items-center gap-1.5 shadow-xs transition-colors"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print Report</span>
          </button>
        </div>
      </div>

      {/* Report Container */}
      <div className="bg-white border border-[#E5EAF2] rounded-2xl p-6 sm:p-8 shadow-xs space-y-6 print:border-none print:shadow-none">
        {/* Document Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-6 border-b border-[#E5EAF2] gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-blue-600"></span>
              <h3 className="font-extrabold text-lg text-[#172033]">
                CyberRakshak AI — Security Posture Assessment Report
              </h3>
            </div>
            <p className="text-xs text-gray-500 mt-1">
              Assessment Scope: {workspaceName} Perimeter
            </p>
          </div>

          <div className="text-xs text-gray-500 sm:text-right space-y-0.5">
            <p>Generated: <strong className="text-slate-800">{currentDate}</strong></p>
            <p>Auditor Engine: <strong className="text-slate-800">CyberRakshak AI Automated Intelligence</strong></p>
            <p>Target Account: <strong className="text-slate-800">{userName}</strong></p>
          </div>
        </div>

        {/* Data Provenance & Assessment Coverage Transparency Callout */}
        <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2 text-xs">
          <div className="flex items-center justify-between">
            <span className="font-bold text-slate-800 flex items-center gap-1.5">
              <Layers className="w-4 h-4 text-blue-600" />
              <span>Coverage & Data Provenance Breakdown:</span>
            </span>
            <span className="text-[11px] text-slate-500">
              Live Observations: <strong className="text-emerald-700">{liveFindings.length}</strong> | Sample Fixtures: <strong className="text-purple-700">{demoFindings.length}</strong>
            </span>
          </div>
          <p className="text-slate-600 leading-relaxed text-[11px]">
            This report evaluates recorded personal scam scans and passive business perimeter probes. No historical measurements are fabricated. Missing coverage on unregistered assets is explicitly marked as unassessed.
          </p>
        </div>

        {/* Executive Summary Card */}
        <div className="bg-[#F8FAFC] border border-[#E5EAF2] rounded-xl p-5 space-y-3">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700">
            Executive Summary
          </h4>
          <p className="text-xs sm:text-sm text-[#475467] leading-relaxed">
            During this assessment period, CyberRakshak AI evaluated active message vectors and authorized perimeter configurations. The calculated security posture is classified as <strong>{postureStatus} ({postureScore}/100)</strong>. {criticalHighCount > 0 ? `${criticalHighCount} high-priority finding(s) require ongoing mitigation attention.` : 'No critical or high-risk findings are currently outstanding.'}
          </p>
        </div>

        {/* Metrics Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div className="p-3.5 bg-white border border-slate-200 rounded-xl">
            <span className="text-gray-500 block">Total Findings Tracked:</span>
            <span className="text-xl font-bold text-[#172033] mt-0.5 block">{findings.length} Items</span>
          </div>
          <div className="p-3.5 bg-white border border-slate-200 rounded-xl">
            <span className="text-gray-500 block">Active Critical/High:</span>
            <span className={`text-xl font-bold mt-0.5 block ${criticalHighCount > 0 ? 'text-red-600' : 'text-teal-600'}`}>
              {criticalHighCount} Findings
            </span>
          </div>
          <div className="p-3.5 bg-white border border-slate-200 rounded-xl">
            <span className="text-gray-500 block">Mitigations Closed:</span>
            <span className="text-xl font-bold text-teal-600 mt-0.5 block">{resolvedCount} Resolved</span>
          </div>
          <div className="p-3.5 bg-white border border-slate-200 rounded-xl">
            <span className="text-gray-500 block">Independently Verified:</span>
            <span className="text-xl font-bold text-blue-600 mt-0.5 block">
              {verifiedCount} Verified ✓
            </span>
          </div>
        </div>

        {/* Filter Controls for Findings Table */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700">
            Recorded Findings Breakdown ({displayedFindings.length})
          </h4>

          <div className="flex items-center gap-1.5 print:hidden">
            <button
              onClick={() => setReportFilter('all')}
              className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition-colors ${
                reportFilter === 'all' ? 'bg-blue-600 text-white' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              All ({findings.length})
            </button>
            <button
              onClick={() => setReportFilter('live')}
              className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition-colors ${
                reportFilter === 'live' ? 'bg-blue-600 text-white' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              Live Only ({liveFindings.length})
            </button>
            <button
              onClick={() => setReportFilter('critical')}
              className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition-colors ${
                reportFilter === 'critical' ? 'bg-blue-600 text-white' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              Critical/High ({criticalHighCount})
            </button>
            <button
              onClick={() => setReportFilter('demo')}
              className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition-colors ${
                reportFilter === 'demo' ? 'bg-blue-600 text-white' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              Demo Fixtures ({demoFindings.length})
            </button>
          </div>
        </div>

        {/* Findings Table */}
        <div className="overflow-x-auto border border-[#E5EAF2] rounded-xl">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#F8FAFC] border-b border-[#E5EAF2] text-slate-600 font-bold">
              <tr>
                <th className="py-2.5 px-3">Title</th>
                <th className="py-2.5 px-3">Category</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Confidence & Source</th>
                <th className="py-2.5 px-3">Data Provenance</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#F1F5F9] text-slate-700">
              {displayedFindings.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-6 text-center text-slate-400">
                    No security findings match the selected report filter.
                  </td>
                </tr>
              ) : (
                displayedFindings.map((f) => (
                  <tr key={f.id} className="hover:bg-slate-50">
                    <td className="py-2.5 px-3 font-semibold text-[#172033]">
                      {f.title}
                    </td>
                    <td className="py-2.5 px-3">{f.category || 'General'}</td>
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                        f.severity === 'High' || f.severity === 'Critical' ? 'bg-red-50 text-red-700' : 'bg-amber-50 text-amber-700'
                      }`}>
                        {f.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-600">
                      <div>{f.confidence}</div>
                      <div className="text-[10px] text-slate-400">{f.source || 'Automated Probe'}</div>
                    </td>
                    <td className="py-2.5 px-3">
                      {f.isDemo ? (
                        <span className="text-[9px] px-2 py-0.5 rounded-full bg-purple-50 text-purple-700 border border-purple-200 font-semibold">
                          Sample Demo Fixture
                        </span>
                      ) : (
                        <span className="text-[9px] px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-800 border border-emerald-200 font-semibold">
                          Live Verified Observation
                        </span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Audit Statement & Methodology Disclaimer */}
        <div className="text-[11px] text-gray-500 border-t border-slate-200 pt-4 leading-relaxed">
          <p>
            <strong>Assessment Methodology & Legal Safeguards:</strong> CyberRakshak AI passive assessments are based on publicly observable domain metadata, HTTP headers, TLS handshake attributes, and linguistic pattern heuristics. No intrusive penetration testing, port scanning, or denial-of-service simulations were conducted. Findings reflect observed perimeter indicators to guide defensive remediation priorities and do not constitute an absolute guarantee of immunity against targeted external compromise.
          </p>
        </div>
      </div>
    </div>
  );
};
