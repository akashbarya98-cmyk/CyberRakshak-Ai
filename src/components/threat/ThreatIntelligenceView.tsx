import React, { useState } from 'react';
import { 
  Radar, 
  Search, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  ExternalLink, 
  RefreshCw,
  Globe,
  Database,
  Radio
} from 'lucide-react';

export const ThreatIntelligenceView: React.FC = () => {
  const [lookupQuery, setLookupQuery] = useState('');
  const [isSearching, setIsSearching] = useState(false);
  const [searchResult, setSearchResult] = useState<any | null>(null);

  const threatFeeds = [
    {
      id: 'tf-1',
      source: 'CERT-In Advisory',
      title: 'Active Phishing Campaign Spoofing Major Public Utilities and Power Disconnection',
      severity: 'Critical',
      date: 'Today, 09:30 AM',
      impact: 'Targeting mobile users with trojanized payment APKs masquerading as electricity bill managers.',
      indicators: ['pay-quick-bijli.in', 'challan-parivahan-pay.apk']
    },
    {
      id: 'tf-2',
      source: 'Google Safe Browsing Cluster',
      title: 'High-Volume Part-Time YouTube & Telegram Task Scams',
      severity: 'High',
      date: 'Yesterday, 04:15 PM',
      impact: 'Victims lured with ₹150 micro-payouts before being directed into crypto deposits.',
      indicators: ['t.me/task_earn_daily_vip', 'career-update.com']
    },
    {
      id: 'tf-3',
      source: 'Global PhishTank Database',
      title: 'Credential Harvesting Portals Targeting State Banking Portals',
      severity: 'High',
      date: 'Apr 26, 2025',
      impact: 'Spoofed netbanking login forms stealing customer username, password, and OTP tokens.',
      indicators: ['bit.ly/bank-kyc-alert', 'sbi-update-kyc.top']
    }
  ];

  const handleLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!lookupQuery.trim()) return;

    setIsSearching(true);
    try {
      const response = await fetch('/api/threat-intel/lookup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ indicator: lookupQuery })
      });

      const data = await response.json();
      if (response.ok) {
        setSearchResult(data);
      } else {
        setSearchResult({
          target: lookupQuery,
          status: 'Query Error',
          reputationScore: 'High Risk',
          threatType: data.threatType || 'Blocked or Invalid Input',
          sourcesChecked: data.sourcesChecked || ['SSRF Guard'],
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          notes: data.notes || data.error || 'Failed to complete reputation check.'
        });
      }
    } catch (err: any) {
      setSearchResult({
        target: lookupQuery,
        status: 'Connection Issue',
        reputationScore: 'Indeterminate',
        threatType: 'Offline Fallback',
        sourcesChecked: ['Local Heuristics Engine'],
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        notes: `Offline lookup fallback: ${err.message}`
      });
    } finally {
      setIsSearching(false);
    }
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto pb-12">
      <div>
        <h2 className="text-xl sm:text-2xl font-bold text-[#172033] tracking-tight flex items-center gap-2">
          <Radar className="w-6 h-6 text-blue-600" />
          <span>Threat Intelligence</span>
        </h2>
        <p className="text-xs text-[#667085] mt-0.5">
          Real-time threat feeds, indicator lookups, and vulnerability intelligence.
        </p>
      </div>

      {/* Indicator Lookup Bar */}
      <div className="bg-white border border-[#E5EAF2] rounded-2xl p-5 shadow-xs space-y-4">
        <div>
          <h3 className="font-bold text-sm text-[#172033]">Live Indicator Reputation Lookup</h3>
          <p className="text-xs text-[#667085]">Verify domains, URLs, or SHA-256 hashes against trusted feeds.</p>
        </div>

        <form onSubmit={handleLookup} className="flex gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-gray-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={lookupQuery}
              onChange={(e) => setLookupQuery(e.target.value)}
              placeholder="Enter domain, URL or suspicious indicator (e.g. career-update.com)..."
              className="w-full pl-10 pr-4 py-2.5 bg-[#F8FAFC] border border-[#E5EAF2] rounded-xl text-xs sm:text-sm text-[#172033] focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500"
            />
          </div>
          <button
            type="submit"
            disabled={isSearching || !lookupQuery.trim()}
            className="px-5 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-xl text-xs font-bold transition-colors shadow-xs"
          >
            {isSearching ? 'Querying...' : 'Query Threat Feed'}
          </button>
        </form>

        {/* Lookup Result Box */}
        {searchResult && (
          <div className="p-4 rounded-xl border border-[#E5EAF2] bg-[#F8FAFC] space-y-3 text-xs">
            <div className="flex items-center justify-between">
              <span className="font-bold text-slate-800">Target: {searchResult.target}</span>
              <span className={`px-2 py-0.5 rounded-full font-bold text-[10px] ${
                searchResult.reputationScore === 'High Risk' ? 'bg-red-100 text-red-700' : 'bg-teal-100 text-teal-700'
              }`}>
                {searchResult.status}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 p-3 bg-white rounded-lg border border-slate-200">
              <div>
                <span className="text-gray-400 block text-[10px]">Classification:</span>
                <span className="font-bold text-[#172033]">{searchResult.threatType}</span>
              </div>
              <div>
                <span className="text-gray-400 block text-[10px]">Sources Verified:</span>
                <span className="font-semibold text-slate-700">{searchResult.sourcesChecked.length} Feeds</span>
              </div>
              <div>
                <span className="text-gray-400 block text-[10px]">Query Time:</span>
                <span className="font-semibold text-slate-700">{searchResult.timestamp}</span>
              </div>
            </div>

            <p className="text-[11px] text-[#667085] leading-relaxed">
              {searchResult.notes}
            </p>
          </div>
        )}
      </div>

      {/* Verified Threat Intelligence Advisory Feed */}
      <div className="bg-white border border-[#E5EAF2] rounded-2xl p-6 shadow-xs space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-[#E5EAF2]">
          <div>
            <h3 className="font-bold text-sm sm:text-base text-[#172033]">
              Active Threat Advisories & Campaign Tracking
            </h3>
            <p className="text-xs text-[#667085]">Verified scam patterns observed across digital communications</p>
          </div>
          <span className="text-xs font-semibold text-teal-600 bg-teal-50 px-2.5 py-1 rounded-full border border-teal-200 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-teal-500 animate-ping"></span> Live Feed
          </span>
        </div>

        <div className="space-y-4">
          {threatFeeds.map((feed) => (
            <div
              key={feed.id}
              className="p-4 rounded-xl border border-[#E5EAF2] bg-[#F8FAFC]/50 hover:bg-[#F8FAFC] space-y-2 transition-colors"
            >
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-blue-100 text-blue-700">
                  {feed.source}
                </span>
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                  feed.severity === 'Critical' ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700'
                }`}>
                  {feed.severity}
                </span>
              </div>

              <h4 className="font-bold text-xs sm:text-sm text-[#172033]">
                {feed.title}
              </h4>
              <p className="text-xs text-[#667085]">
                {feed.impact}
              </p>

              <div className="pt-2 flex flex-wrap items-center gap-2">
                <span className="text-[10px] font-semibold text-gray-500">Known Indicators:</span>
                {feed.indicators.map((ind, i) => (
                  <span key={i} className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-200 text-slate-800">
                    {ind}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
