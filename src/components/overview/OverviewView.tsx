import React, { useState } from 'react';
import { 
  ShieldCheck, 
  AlertTriangle, 
  Scan, 
  FolderLock, 
  ArrowRight, 
  Mail, 
  Building2, 
  Lightbulb, 
  Info, 
  CheckCircle2, 
  ChevronRight, 
  Globe, 
  Lock, 
  UserCheck, 
  Network,
  TrendingUp,
  TrendingDown,
  ShieldAlert,
  Clock,
  Sparkles,
  Inbox
} from 'lucide-react';
import { ViewMode, Finding, RemediationTask, OverviewData } from '../../types';

interface OverviewViewProps {
  onNavigate: (view: ViewMode) => void;
  onSelectFinding?: (findingId: string) => void;
  findings: Finding[];
  priorityActions: RemediationTask[];
  onFixAction: (taskId: string) => void;
  overviewData?: OverviewData | null;
  userName?: string;
  isLoading?: boolean;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  onNavigate,
  onSelectFinding,
  findings,
  priorityActions,
  onFixAction,
  overviewData,
  userName = 'Akash',
  isLoading = false
}) => {
  const [trendRange, setTrendRange] = useState<'7' | '30'>('7');
  const [hoveredPoint, setHoveredPoint] = useState<{ x: number; y: number; date: string; score: number } | null>(null);

  // Derive dynamic posture & metrics from backend overview data, with robust fallbacks
  const posture = overviewData?.posture || {
    status: 'Good',
    score: 75,
    change: '+12%',
    trend: [
      { date: 'Apr 22', score: 38 },
      { date: 'Apr 23', score: 45 },
      { date: 'Apr 24', score: 48 },
      { date: 'Apr 25', score: 53 },
      { date: 'Apr 26', score: 60 },
      { date: 'Apr 27', score: 66 },
      { date: 'Apr 28', score: 75 }
    ]
  };

  const metrics = overviewData?.metrics || {
    highPriorityFindings: findings.filter(f => f.severity === 'High' || f.severity === 'Critical').length,
    highPriorityChange: '-40%',
    scansCompleted: 18,
    scansChange: '+50%',
    recommendationsPending: priorityActions.filter(t => t.status === 'Open').length,
    recommendationsChange: '-29%'
  };

  const recentActivity = overviewData?.recentActivity && overviewData.recentActivity.length > 0 
    ? overviewData.recentActivity 
    : [
        { id: 'a-1', type: 'Scanned message', detail: 'Suspicious SMS analyzed', time: '2 hours ago', status: 'High Risk', statusType: 'danger' as const },
        { id: 'a-2', type: 'Business assessment', detail: 'example-business.com', time: '5 hours ago', status: 'Completed', statusType: 'success' as const },
        { id: 'a-3', type: 'Finding resolved', detail: 'Weak password policy', time: '1 day ago', status: 'Resolved', statusType: 'success' as const },
        { id: 'a-4', type: 'New report', detail: 'Community submission', time: '1 day ago', status: 'Info', statusType: 'info' as const }
      ];

  const trendData30Days = [
    { date: 'Day 1', score: Math.max(20, posture.score - 40) },
    { date: 'Day 7', score: Math.max(28, posture.score - 30) },
    { date: 'Day 14', score: Math.max(40, posture.score - 20) },
    { date: 'Day 21', score: Math.max(55, posture.score - 10) },
    { date: 'Today', score: posture.score }
  ];

  const activeTrendData = trendRange === '7' && posture.trend && posture.trend.length > 0
    ? posture.trend
    : trendData30Days;

  // SVG Chart Dimensions
  const chartWidth = 420;
  const chartHeight = 180;
  const paddingLeft = 32;
  const paddingBottom = 28;
  const paddingTop = 16;
  const paddingRight = 16;

  const innerWidth = chartWidth - paddingLeft - paddingRight;
  const innerHeight = chartHeight - paddingTop - paddingBottom;

  const points = activeTrendData.map((d, index) => {
    const divisor = Math.max(1, activeTrendData.length - 1);
    const x = paddingLeft + (index / divisor) * innerWidth;
    const y = paddingTop + innerHeight - (Math.min(100, Math.max(0, d.score)) / 100) * innerHeight;
    return { ...d, x, y };
  });

  const pathD = points.reduce((acc, p, i) => {
    return i === 0 ? `M ${p.x} ${p.y}` : `${acc} L ${p.x} ${p.y}`;
  }, '');

  const areaD = points.length > 0 
    ? `${pathD} L ${points[points.length - 1].x} ${paddingTop + innerHeight} L ${points[0].x} ${paddingTop + innerHeight} Z`
    : '';

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* 1. Welcome Section & 3 Hero Action Cards */}
      <div className="space-y-4">
        <div>
          <h2 className="text-2xl sm:text-3xl font-extrabold text-[#172033] tracking-tight">
            Good day, {userName}.
          </h2>
          <p className="text-sm sm:text-base text-[#667085] mt-1">
            Your digital safety, made understandable.
          </p>
        </div>

        {/* 3 Prominent Action Cards + Right Graphic Quote Banner */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          <div className="lg:col-span-8 grid grid-cols-1 md:grid-cols-3 gap-3.5">
            {/* Card 1: Scan a Suspicious Message */}
            <button
              onClick={() => onNavigate('personal')}
              className="group relative overflow-hidden bg-gradient-to-r from-[#2563EB] to-[#1D4ED8] hover:from-[#1D4ED8] hover:to-[#1E40AF] p-4 sm:p-4.5 rounded-2xl text-white text-left shadow-sm hover:shadow-md transition-all flex flex-col justify-between"
            >
              <div className="flex items-start justify-between">
                <div className="w-10 h-10 rounded-xl bg-white/20 backdrop-blur-xs flex items-center justify-center shrink-0">
                  <Mail className="w-5 h-5 text-white" />
                </div>
                <div className="w-7 h-7 rounded-full bg-white/10 group-hover:bg-white/25 flex items-center justify-center transition-colors">
                  <ArrowRight className="w-4 h-4 text-white group-hover:translate-x-0.5 transition-transform" />
                </div>
              </div>
              <div className="mt-4">
                <h3 className="font-bold text-sm sm:text-base leading-tight">
                  Scan a Suspicious Message
                </h3>
                <p className="text-xs text-blue-100 mt-1 line-clamp-1">
                  Check emails, URLs, SMS, images
                </p>
              </div>
            </button>

            {/* Card 2: Assess a Business Website */}
            <button
              onClick={() => onNavigate('business')}
              className="group relative overflow-hidden bg-gradient-to-r from-[#7C3AED] to-[#6D28D9] hover:from-[#6D28D9] hover:to-[#5B21B6] p-4 sm:p-4.5 rounded-2xl text-white text-left shadow-sm hover:shadow-md transition-all flex flex-col justify-between"
            >
              <div className="flex items-start justify-between">
                <div className="w-10 h-10 rounded-xl bg-white/20 backdrop-blur-xs flex items-center justify-center shrink-0">
                  <Building2 className="w-5 h-5 text-white" />
                </div>
                <div className="w-7 h-7 rounded-full bg-white/10 group-hover:bg-white/25 flex items-center justify-center transition-colors">
                  <ArrowRight className="w-4 h-4 text-white group-hover:translate-x-0.5 transition-transform" />
                </div>
              </div>
              <div className="mt-4">
                <h3 className="font-bold text-sm sm:text-base leading-tight">
                  Assess a Business Website
                </h3>
                <p className="text-xs text-purple-100 mt-1 line-clamp-1">
                  Run a security assessment
                </p>
              </div>
            </button>

            {/* Card 3: View Security Recommendations */}
            <button
              onClick={() => onNavigate('remediation')}
              className="group bg-white hover:bg-slate-50 border border-[#E5EAF2] hover:border-blue-300 p-4 sm:p-4.5 rounded-2xl text-left shadow-xs hover:shadow-sm transition-all flex flex-col justify-between"
            >
              <div className="flex items-start justify-between">
                <div className="w-10 h-10 rounded-xl bg-amber-50 border border-amber-100 flex items-center justify-center shrink-0">
                  <Lightbulb className="w-5 h-5 text-amber-500" />
                </div>
                <div className="w-7 h-7 rounded-full bg-slate-100 group-hover:bg-blue-50 flex items-center justify-center transition-colors">
                  <ArrowRight className="w-4 h-4 text-gray-500 group-hover:text-blue-600 group-hover:translate-x-0.5 transition-all" />
                </div>
              </div>
              <div className="mt-4">
                <h3 className="font-bold text-sm sm:text-base text-[#172033] leading-tight">
                  View Security Recommendations
                </h3>
                <p className="text-xs text-[#667085] mt-1 line-clamp-1">
                  Get personalized tips
                </p>
              </div>
            </button>
          </div>

          {/* Right Graphic Banner: Proactive Defense */}
          <div className="lg:col-span-4 bg-gradient-to-br from-[#1E293B] via-[#0F172A] to-[#172554] rounded-2xl p-4 sm:p-5 text-white flex items-center justify-between relative overflow-hidden shadow-sm">
            <div className="relative z-10 space-y-1 max-w-[210px]">
              <span className="text-[10px] font-semibold tracking-wider uppercase text-blue-400">
                PROACTIVE DEFENSE
              </span>
              <p className="text-base sm:text-lg font-bold italic leading-snug">
                "Smarter insights. Safer decisions."
              </p>
              <p className="text-xs text-slate-300 pt-1">
                AI and deterministic security combined for zero blind spots.
              </p>
            </div>

            <div className="relative shrink-0 w-24 h-24 flex items-center justify-center">
              <div className="absolute inset-0 bg-blue-500/20 rounded-full blur-xl animate-pulse"></div>
              <div className="w-18 h-18 rounded-2xl bg-blue-600/30 border border-blue-400/50 flex items-center justify-center relative">
                <ShieldAlert className="w-10 h-10 text-cyan-400" />
                <div className="absolute top-1 left-2 w-1.5 h-1.5 rounded-full bg-teal-300"></div>
                <div className="absolute bottom-2 right-2 w-1.5 h-1.5 rounded-full bg-indigo-300"></div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 2. Stat Summary Cards (4 Cards Grid) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Overall Security Posture */}
        <div className="bg-white border border-[#E5EAF2] rounded-2xl p-5 shadow-xs hover:border-slate-300 transition-colors">
          <div className="flex items-center justify-between">
            <div className="w-10 h-10 rounded-xl bg-teal-50 border border-teal-100 flex items-center justify-center text-teal-600">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <span className="inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded-full bg-teal-50 text-teal-700">
              <TrendingUp className="w-3 h-3" /> {posture.change}
            </span>
          </div>
          <div className="mt-3">
            <p className="text-xs font-medium text-[#667085]">Overall Security Posture</p>
            <div className="flex items-baseline gap-2 mt-0.5">
              <h3 className="text-2xl font-bold text-[#172033]">{posture.score}/100</h3>
              <span className="text-xs font-semibold text-slate-500">[{posture.status}]</span>
            </div>
            <p className="text-xs text-[#667085] mt-1 leading-relaxed">
              Dynamically derived from active findings and mitigations.
            </p>
          </div>
        </div>

        {/* Card 2: High-Priority Findings */}
        <div className="bg-white border border-[#E5EAF2] rounded-2xl p-5 shadow-xs hover:border-slate-300 transition-colors">
          <div className="flex items-center justify-between">
            <div className="w-10 h-10 rounded-xl bg-red-50 border border-red-100 flex items-center justify-center text-red-600">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <span className="inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded-full bg-red-50 text-red-700">
              <TrendingDown className="w-3 h-3" /> {metrics.highPriorityChange}
            </span>
          </div>
          <div className="mt-3">
            <p className="text-xs font-medium text-[#667085]">High-Priority Findings</p>
            <h3 className="text-2xl font-bold text-[#172033] mt-0.5">
              {metrics.highPriorityFindings}
            </h3>
            <p className="text-xs text-[#DC2626] font-medium mt-1">
              {metrics.highPriorityFindings > 0 ? 'Requires your attention' : 'No urgent alerts'}
            </p>
          </div>
        </div>

        {/* Card 3: Scans Completed */}
        <div className="bg-white border border-[#E5EAF2] rounded-2xl p-5 shadow-xs hover:border-slate-300 transition-colors">
          <div className="flex items-center justify-between">
            <div className="w-10 h-10 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600">
              <Scan className="w-5 h-5" />
            </div>
            <span className="inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded-full bg-teal-50 text-teal-700">
              <TrendingUp className="w-3 h-3" /> {metrics.scansChange}
            </span>
          </div>
          <div className="mt-3">
            <p className="text-xs font-medium text-[#667085]">Scans Completed</p>
            <h3 className="text-2xl font-bold text-[#172033] mt-0.5">
              {metrics.scansCompleted}
            </h3>
            <p className="text-xs text-[#667085] mt-1">
              Active workspace evaluations
            </p>
          </div>
        </div>

        {/* Card 4: Recommendations Pending */}
        <div className="bg-white border border-[#E5EAF2] rounded-2xl p-5 shadow-xs hover:border-slate-300 transition-colors">
          <div className="flex items-center justify-between">
            <div className="w-10 h-10 rounded-xl bg-indigo-50 border border-indigo-100 flex items-center justify-center text-indigo-600">
              <FolderLock className="w-5 h-5" />
            </div>
            <span className="inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded-full bg-slate-100 text-slate-700">
              <TrendingDown className="w-3 h-3" /> {metrics.recommendationsChange}
            </span>
          </div>
          <div className="mt-3">
            <p className="text-xs font-medium text-[#667085]">Recommendations Pending</p>
            <h3 className="text-2xl font-bold text-[#172033] mt-0.5">
              {metrics.recommendationsPending}
            </h3>
            <p className="text-xs text-[#667085] mt-1">
              Across personal & business
            </p>
          </div>
        </div>
      </div>

      {/* 3. Middle Section: Posture Trend Chart, Recent Findings, Priority Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left Column (5 cols): Security Posture Trend */}
        <div className="lg:col-span-5 bg-white border border-[#E5EAF2] rounded-2xl p-5 shadow-xs flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-[#E5EAF2]">
              <div className="flex items-center gap-1.5">
                <h3 className="font-bold text-sm sm:text-base text-[#172033]">
                  Security Posture Trend
                </h3>
                <span title="Calculated risk and hygiene score out of 100">
                  <Info className="w-4 h-4 text-[#98A2B3] cursor-help" />
                </span>
              </div>
              <select
                aria-label="Select trend window"
                value={trendRange}
                onChange={(e) => setTrendRange(e.target.value as '7' | '30')}
                className="text-xs font-semibold text-[#475467] bg-[#F8FAFC] border border-[#E5EAF2] rounded-lg px-2.5 py-1 focus:outline-none"
              >
                <option value="7">Last 7 days</option>
                <option value="30">Last 30 days</option>
              </select>
            </div>

            {/* Line Chart */}
            <div className="relative mt-4 w-full h-[200px] flex items-center justify-center">
              <svg 
                viewBox={`0 0 ${chartWidth} ${chartHeight}`} 
                className="w-full h-full overflow-visible"
              >
                <defs>
                  <linearGradient id="trendGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#2563EB" stopOpacity="0.25" />
                    <stop offset="100%" stopColor="#2563EB" stopOpacity="0.0" />
                  </linearGradient>
                </defs>

                {/* Y-axis grid lines (0, 25, 50, 75, 100) */}
                {[0, 25, 50, 75, 100].map((val) => {
                  const y = paddingTop + innerHeight - (val / 100) * innerHeight;
                  return (
                    <g key={val}>
                      <line 
                        x1={paddingLeft} 
                        y1={y} 
                        x2={chartWidth - paddingRight} 
                        y2={y} 
                        stroke="#F1F5F9" 
                        strokeWidth="1" 
                      />
                      <text 
                        x={paddingLeft - 8} 
                        y={y + 3} 
                        textAnchor="end" 
                        fontSize="9" 
                        fill="#94A3B8"
                        fontFamily="sans-serif"
                      >
                        {val}
                      </text>
                    </g>
                  );
                })}

                {/* Area under curve */}
                {areaD && <path d={areaD} fill="url(#trendGradient)" />}

                {/* Main line curve */}
                {pathD && (
                  <path 
                    d={pathD} 
                    fill="none" 
                    stroke="#2563EB" 
                    strokeWidth="2.5" 
                    strokeLinecap="round" 
                    strokeLinejoin="round" 
                  />
                )}

                {/* Data points & X-axis labels */}
                {points.map((p, idx) => (
                  <g key={idx}>
                    <circle 
                      cx={p.x} 
                      cy={p.y} 
                      r="4" 
                      fill="#FFFFFF" 
                      stroke="#2563EB" 
                      strokeWidth="2"
                      className="cursor-pointer hover:scale-125 transition-transform"
                      onMouseEnter={() => setHoveredPoint(p)}
                      onMouseLeave={() => setHoveredPoint(null)}
                    />
                    <text 
                      x={p.x} 
                      y={chartHeight - 6} 
                      textAnchor="middle" 
                      fontSize="9.5" 
                      fill="#64748B"
                    >
                      {p.date}
                    </text>
                  </g>
                ))}
              </svg>

              {/* Tooltip on Hover */}
              {hoveredPoint && (
                <div 
                  className="absolute pointer-events-none bg-slate-900 text-white text-[11px] font-semibold px-2 py-1 rounded shadow-md -translate-x-1/2 -translate-y-8"
                  style={{
                    left: `${(hoveredPoint.x / chartWidth) * 100}%`,
                    top: `${(hoveredPoint.y / chartHeight) * 100}%`
                  }}
                >
                  Score: {hoveredPoint.score}/100 ({hoveredPoint.date})
                </div>
              )}
            </div>
          </div>

          <div className="pt-3 border-t border-[#E5EAF2] flex items-center justify-between text-xs text-[#667085]">
            <span>Baseline: <strong className="text-slate-700">{points[0]?.score || 40} ({points[0]?.date || 'Start'})</strong></span>
            <span>Current: <strong className="text-blue-600 font-bold">{posture.score}/100</strong></span>
          </div>
        </div>

        {/* Center Column (4 cols): Recent Security Findings */}
        <div className="lg:col-span-4 bg-white border border-[#E5EAF2] rounded-2xl p-5 shadow-xs flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-[#E5EAF2]">
              <h3 className="font-bold text-sm sm:text-base text-[#172033]">
                Recent Security Findings
              </h3>
              <button 
                onClick={() => onNavigate('personal')}
                className="text-xs font-semibold text-blue-600 hover:text-blue-700 flex items-center gap-1"
              >
                View all <ArrowRight className="w-3 h-3" />
              </button>
            </div>

            {findings.length === 0 ? (
              <div className="py-12 text-center space-y-2">
                <div className="w-9 h-9 rounded-full bg-slate-100 text-slate-400 flex items-center justify-center mx-auto">
                  <Inbox className="w-4 h-4" />
                </div>
                <p className="text-xs font-semibold text-slate-600">No active findings recorded</p>
                <p className="text-[11px] text-slate-400">Run a message or domain scan to evaluate risks.</p>
              </div>
            ) : (
              <div className="divide-y divide-[#F1F5F9] mt-2">
                {findings.slice(0, 5).map((f) => {
                  const dotColor = f.severity === 'High' || f.severity === 'Critical' ? 'bg-red-500' :
                                   f.severity === 'Medium' ? 'bg-amber-500' :
                                   'bg-teal-500';

                  return (
                    <div 
                      key={f.id}
                      onClick={() => {
                        if (onSelectFinding) onSelectFinding(f.id);
                        onNavigate('personal');
                      }}
                      className="py-2.5 px-1 hover:bg-[#F8FAFC] rounded-lg transition-colors cursor-pointer flex items-center justify-between gap-2"
                    >
                      <div className="min-w-0 flex items-start gap-2">
                        <span className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${dotColor}`}></span>
                        <div className="min-w-0">
                          <p className="text-xs font-semibold text-[#172033] truncate">
                            {f.title}
                          </p>
                          <div className="flex items-center gap-2 mt-0.5">
                            <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-100 text-slate-600 font-medium">
                              {f.category || 'Threat'}
                            </span>
                            <span className="text-[10px] text-[#98A2B3]">
                              {f.date}
                            </span>
                            {f.isDemo && (
                              <span className="text-[9px] px-1 rounded bg-purple-50 text-purple-700 border border-purple-200">
                                Demo
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                      <ChevronRight className="w-4 h-4 text-gray-400 shrink-0" />
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          <div className="pt-2 text-center text-xs text-slate-400">
            {findings.length} security findings tracked
          </div>
        </div>

        {/* Right Column (3 cols): Priority Actions */}
        <div className="lg:col-span-3 bg-white border border-[#E5EAF2] rounded-2xl p-5 shadow-xs flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-[#E5EAF2]">
              <h3 className="font-bold text-sm sm:text-base text-[#172033]">
                Priority Actions
              </h3>
              <button 
                onClick={() => onNavigate('remediation')}
                className="text-xs font-semibold text-blue-600 hover:text-blue-700 flex items-center gap-1"
              >
                View all <ArrowRight className="w-3 h-3" />
              </button>
            </div>

            {priorityActions.length === 0 ? (
              <div className="py-12 text-center space-y-2">
                <div className="w-9 h-9 rounded-full bg-slate-100 text-slate-400 flex items-center justify-center mx-auto">
                  <CheckCircle2 className="w-4 h-4 text-teal-600" />
                </div>
                <p className="text-xs font-semibold text-slate-600">All tasks resolved</p>
                <p className="text-[11px] text-slate-400">Security posture is up to date.</p>
              </div>
            ) : (
              <div className="space-y-3 mt-3">
                {priorityActions.slice(0, 3).map((task, idx) => {
                  const icon = idx === 0 ? <ShieldCheck className="w-4 h-4 text-red-500" /> :
                               idx === 1 ? <Lock className="w-4 h-4 text-amber-500" /> :
                               <UserCheck className="w-4 h-4 text-blue-500" />;

                  return (
                    <div 
                      key={task.id}
                      className="p-3 rounded-xl border border-[#E5EAF2] bg-[#F8FAFC]/50 hover:bg-white hover:shadow-xs transition-all space-y-2"
                    >
                      <div className="flex items-start gap-2">
                        <div className="p-1.5 rounded-lg bg-white border border-slate-200 shrink-0">
                          {icon}
                        </div>
                        <div className="min-w-0">
                          <p className="text-xs font-bold text-[#172033] leading-snug">
                            {task.title}
                          </p>
                          <p className="text-[11px] text-[#667085] mt-0.5 line-clamp-1">
                            {task.description}
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center justify-between pt-1">
                        <span className="text-[10px] text-[#667085] font-medium">
                          {task.effort}
                        </span>
                        <button
                          onClick={() => onFixAction(task.id)}
                          className="px-2.5 py-1 text-xs font-semibold bg-blue-600 hover:bg-blue-700 text-white rounded-md shadow-2xs transition-colors"
                        >
                          Fix now
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          <div className="pt-2 text-center text-xs text-slate-400">
            Guided remediation plans
          </div>
        </div>
      </div>

      {/* 4. Bottom Row: Protection Activity + Quick Access Modules */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Protection Activity */}
        <div className="lg:col-span-6 bg-white border border-[#E5EAF2] rounded-2xl p-5 shadow-xs">
          <div className="flex items-center justify-between pb-3 border-b border-[#E5EAF2]">
            <h3 className="font-bold text-sm sm:text-base text-[#172033]">
              Protection Activity
            </h3>
            <span className="text-xs text-slate-400">Real-time log</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-3">
            {recentActivity.map((act) => {
              const Icon = act.type.toLowerCase().includes('message') || act.type.toLowerCase().includes('sms') ? Mail :
                           act.type.toLowerCase().includes('business') || act.type.toLowerCase().includes('assessment') ? Globe :
                           act.type.toLowerCase().includes('finding') || act.type.toLowerCase().includes('resolved') ? CheckCircle2 :
                           Info;

              const badgeColor = act.statusType === 'danger' ? 'bg-red-100 text-red-700' :
                                 act.statusType === 'warning' ? 'bg-amber-100 text-amber-700' :
                                 act.statusType === 'success' ? 'bg-teal-100 text-teal-700' :
                                 'bg-blue-100 text-blue-700';

              return (
                <div key={act.id} className="p-3 rounded-xl bg-[#F8FAFC] border border-[#E5EAF2] space-y-1">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5 text-xs font-bold text-[#172033]">
                      <Icon className="w-3.5 h-3.5 text-blue-600" />
                      <span>{act.type}</span>
                    </div>
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${badgeColor}`}>
                      {act.status}
                    </span>
                  </div>
                  <p className="text-[11px] text-[#667085] truncate">{act.detail}</p>
                  <p className="text-[10px] text-[#98A2B3]">{act.time}</p>
                </div>
              );
            })}
          </div>
        </div>

        {/* Quick Access Modules */}
        <div className="lg:col-span-6 bg-white border border-[#E5EAF2] rounded-2xl p-5 shadow-xs">
          <div className="flex items-center justify-between pb-3 border-b border-[#E5EAF2]">
            <h3 className="font-bold text-sm sm:text-base text-[#172033]">
              Quick Access
            </h3>
            <span className="text-xs text-slate-400">Core workspaces</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-3">
            {/* Module 1: Personal Protection */}
            <button
              onClick={() => onNavigate('personal')}
              className="p-3.5 rounded-xl border border-[#E5EAF2] hover:border-blue-300 hover:bg-blue-50/40 text-left transition-all group flex flex-col justify-between"
            >
              <div className="w-9 h-9 rounded-lg bg-blue-50 text-blue-600 flex items-center justify-center group-hover:scale-105 transition-transform">
                <ShieldCheck className="w-5 h-5" />
              </div>
              <div className="mt-3">
                <h4 className="text-xs font-bold text-[#172033] group-hover:text-blue-600">
                  Personal Protection
                </h4>
                <p className="text-[11px] text-[#667085] mt-0.5">
                  Scan messages, emails, URLs and more
                </p>
              </div>
            </button>

            {/* Module 2: Business Security */}
            <button
              onClick={() => onNavigate('business')}
              className="p-3.5 rounded-xl border border-[#E5EAF2] hover:border-indigo-300 hover:bg-indigo-50/40 text-left transition-all group flex flex-col justify-between"
            >
              <div className="w-9 h-9 rounded-lg bg-indigo-50 text-indigo-600 flex items-center justify-center group-hover:scale-105 transition-transform">
                <Building2 className="w-5 h-5" />
              </div>
              <div className="mt-3">
                <h4 className="text-xs font-bold text-[#172033] group-hover:text-indigo-600">
                  Business Security
                </h4>
                <p className="text-[11px] text-[#667085] mt-0.5">
                  Assess your business security
                </p>
              </div>
            </button>

            {/* Module 3: Cyber Risk Graph */}
            <button
              onClick={() => onNavigate('graph')}
              className="p-3.5 rounded-xl border border-[#E5EAF2] hover:border-purple-300 hover:bg-purple-50/40 text-left transition-all group flex flex-col justify-between"
            >
              <div className="w-9 h-9 rounded-lg bg-purple-50 text-purple-600 flex items-center justify-center group-hover:scale-105 transition-transform">
                <Network className="w-5 h-5" />
              </div>
              <div className="mt-3">
                <h4 className="text-xs font-bold text-[#172033] group-hover:text-purple-600">
                  Cyber Risk Graph
                </h4>
                <p className="text-[11px] text-[#667085] mt-0.5">
                  Explore relationships between threats & assets
                </p>
              </div>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
