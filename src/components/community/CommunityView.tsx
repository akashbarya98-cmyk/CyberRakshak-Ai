import React, { useState, useEffect } from 'react';
import { 
  Users, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  Send, 
  Lock, 
  Eye, 
  Radio,
  FileCheck
} from 'lucide-react';
import { CommunityReport } from '../../types';
import { INITIAL_COMMUNITY_REPORTS } from '../../mock/initialData';

export const CommunityView: React.FC = () => {
  const [reports, setReports] = useState<CommunityReport[]>(INITIAL_COMMUNITY_REPORTS);
  const [title, setTitle] = useState('');
  const [type, setType] = useState('SMS Phishing');
  const [indicator, setIndicator] = useState('');
  const [description, setDescription] = useState('');
  const [showSubmitModal, setShowSubmitModal] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/community/reports')
      .then(res => res.json())
      .then(data => {
        if (Array.isArray(data) && data.length > 0) {
          setReports(data);
        }
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && showSubmitModal) {
        setShowSubmitModal(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [showSubmitModal]);

  // Redacted preview generator for PII
  const getRedactedIndicator = (text: string) => {
    return text
      .replace(/\b\d{10}\b/g, (m) => m.slice(0, 5) + '-XXXXX')
      .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, 'user@redacted-domain.com')
      .replace(/\b\d{4}\s?\d{4}\s?\d{4}\b/g, 'XXXX-XXXX-XXXX');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title || !indicator) return;

    setIsSubmitting(true);
    setSubmitError(null);

    try {
      const response = await fetch('/api/community/reports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title,
          type,
          indicator,
          description
        })
      });

      if (response.ok) {
        const saved = await response.json();
        setReports(prev => [saved, ...prev]);
        setShowSubmitModal(false);
        setTitle('');
        setIndicator('');
        setDescription('');
      } else {
        const errData = await response.json().catch(() => ({}));
        setSubmitError(errData.error || 'Failed to submit community report.');
      }
    } catch (err: any) {
      setSubmitError(err.message || 'Network error.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto pb-12">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-xl sm:text-2xl font-bold text-[#172033] tracking-tight flex items-center gap-2">
            <Users className="w-6 h-6 text-blue-600" />
            <span>Community Scam Intelligence</span>
          </h2>
          <p className="text-xs text-[#667085] mt-0.5">
            Crowdsourced, privacy-redacted scam reports helping shield the broader community.
          </p>
        </div>

        <button
          onClick={() => {
            setShowSubmitModal(true);
            setSubmitError(null);
          }}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-xs font-bold flex items-center gap-2 shadow-xs transition-colors self-start sm:self-auto"
        >
          <ShieldAlert className="w-4 h-4" />
          <span>Report New Scam</span>
        </button>
      </div>

      {/* Reports List */}
      <div className="space-y-4">
        {reports.map((report) => (
          <div
            key={report.id}
            className="bg-white border border-[#E5EAF2] rounded-2xl p-5 shadow-xs hover:border-slate-300 transition-all space-y-3"
          >
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-2.5">
                <span className="text-[10px] font-bold px-2.5 py-0.5 rounded-full bg-blue-50 text-blue-700 border border-blue-200">
                  {report.type}
                </span>
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                  report.riskLevel === 'Critical' ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700'
                }`}>
                  {report.riskLevel} Risk
                </span>
                {report.verified && (
                  <span className="flex items-center gap-1 text-[10px] font-bold text-teal-700 bg-teal-50 px-2 py-0.5 rounded-full border border-teal-200">
                    <CheckCircle2 className="w-3 h-3 text-teal-600" /> Verified Threat
                  </span>
                )}
                {(report as any).isDemo && (
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-purple-50 text-purple-700 border border-purple-200">
                    Demonstration Report
                  </span>
                )}
              </div>

              <span className="text-xs text-gray-400">
                Reported {report.reportedAt} • {report.reportsCount} citizen reports
              </span>
            </div>

            <div>
              <h3 className="font-bold text-sm sm:text-base text-[#172033]">
                {report.title}
              </h3>
              <p className="text-xs text-[#475467] mt-1 leading-relaxed">
                {report.description}
              </p>
            </div>

            <div className="pt-2 border-t border-slate-100 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <span className="text-gray-400 font-medium">Indicator:</span>
                <span className="font-mono text-[11px] bg-slate-100 px-2 py-0.5 rounded text-slate-800">
                  {report.indicator}
                </span>
              </div>
              <span className="text-[11px] text-teal-600 font-semibold flex items-center gap-1">
                <Lock className="w-3 h-3" /> PII Redacted
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Submit Scam Modal with Live PII Redactor Preview */}
      {showSubmitModal && (
        <div 
          className="fixed inset-0 z-50 bg-slate-900/50 backdrop-blur-xs flex items-center justify-center p-4"
          role="dialog"
          aria-modal="true"
          aria-labelledby="submit-modal-title"
        >
          <div className="bg-white rounded-2xl max-w-lg w-full p-6 shadow-2xl border border-gray-100 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-gray-100">
              <h3 id="submit-modal-title" className="font-bold text-[#172033]">Submit Suspicious Activity to Community</h3>
              <button 
                onClick={() => setShowSubmitModal(false)} 
                aria-label="Close submit modal"
                className="text-gray-400 hover:text-gray-700 text-sm p-1 rounded-md"
              >
                ✕
              </button>
            </div>

            {submitError && (
              <div className="p-3 rounded-xl bg-red-50 border border-red-200 text-red-700 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{submitError}</span>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-3.5 text-xs">
              <div className="space-y-1">
                <label className="font-bold text-[#172033]">Scam Campaign Title</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Courier Delivery Failed / Address Re-confirmation SMS"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  className="w-full p-2.5 bg-gray-50 border border-gray-200 rounded-lg focus:outline-none"
                />
              </div>

              <div className="space-y-1">
                <label className="font-bold text-[#172033]">Category</label>
                <select
                  value={type}
                  onChange={(e) => setType(e.target.value)}
                  className="w-full p-2.5 bg-gray-50 border border-gray-200 rounded-lg focus:outline-none"
                >
                  <option value="SMS Phishing">SMS Phishing</option>
                  <option value="WhatsApp Job Scam">WhatsApp Job Scam</option>
                  <option value="Telegram Investment Task">Telegram Investment Task</option>
                  <option value="Fake Banking KYC Portal">Fake Banking KYC Portal</option>
                  <option value="Malicious Android APK">Malicious Android APK</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="font-bold text-[#172033]">Raw Indicator (Phone, Domain, or URL)</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. 9811234567 or track-mypost-express.in"
                  value={indicator}
                  onChange={(e) => setIndicator(e.target.value)}
                  className="w-full p-2.5 bg-gray-50 border border-gray-200 rounded-lg focus:outline-none"
                />
              </div>

              {/* Automatic PII Redaction Live Preview */}
              {indicator && (
                <div className="p-3 rounded-lg bg-teal-50 border border-teal-200 space-y-1">
                  <div className="flex items-center gap-1.5 text-teal-800 font-bold text-[11px]">
                    <Eye className="w-3.5 h-3.5" />
                    <span>Auto-Redacted Public Display:</span>
                  </div>
                  <p className="font-mono text-teal-900 text-xs">
                    {getRedactedIndicator(indicator)}
                  </p>
                  <p className="text-[10px] text-teal-700">
                    * Personal phone numbers and private identifiers are permanently masked before database indexing.
                  </p>
                </div>
              )}

              <div className="space-y-1">
                <label className="font-bold text-[#172033]">Description / Tactic observed</label>
                <textarea
                  rows={3}
                  placeholder="Explain how the scam operates or what instructions the sender gave..."
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="w-full p-2.5 bg-gray-50 border border-gray-200 rounded-lg focus:outline-none"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowSubmitModal(false)}
                  className="px-3 py-1.5 text-gray-600 hover:bg-gray-100 rounded-lg font-semibold"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-bold shadow-xs"
                >
                  {isSubmitting ? 'Publishing...' : 'Publish Redacted Report'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
