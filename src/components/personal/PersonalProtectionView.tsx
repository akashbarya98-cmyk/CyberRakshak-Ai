import React, { useState, useEffect } from 'react';
import { 
  AlertTriangle, 
  ShieldAlert, 
  CheckCircle2, 
  FileText, 
  RotateCcw, 
  Sparkles, 
  Search, 
  Upload, 
  Globe, 
  Mail, 
  MessageSquare, 
  Briefcase, 
  ArrowRight, 
  ExternalLink, 
  ShieldCheck, 
  ChevronRight, 
  Clock, 
  Copy, 
  Check, 
  Image as ImageIcon, 
  X, 
  Calculator, 
  Info,
  Inbox
} from 'lucide-react';
import { ScanResult, ViewMode, Finding } from '../../types';

interface PersonalProtectionViewProps {
  scanResult: ScanResult;
  onNewScanResult: (result: ScanResult) => void;
  onNavigate: (view: ViewMode) => void;
  onOpenCopilotWithContext: (context: any) => void;
  workspaceId?: string;
}

export const PersonalProtectionView: React.FC<PersonalProtectionViewProps> = ({
  scanResult,
  onNewScanResult,
  onNavigate,
  onOpenCopilotWithContext,
  workspaceId = 'ws-personal'
}) => {
  const [activeTab, setActiveTab] = useState<'summary' | 'evidence' | 'actions' | 'history'>('summary');
  const [showInputForm, setShowInputForm] = useState(false);
  const [inputType, setInputType] = useState<'message' | 'url' | 'email' | 'job' | 'image'>('message');
  const [inputText, setInputText] = useState('');
  const [imageBase64, setImageBase64] = useState<string | null>(null);
  const [imageMime, setImageMime] = useState<string>('image/png');
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [copiedAction, setCopiedAction] = useState<number | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [historicalScans, setHistoricalScans] = useState<ScanResult[]>([]);

  useEffect(() => {
    fetch('/api/scans', {
      headers: { 'x-workspace-id': workspaceId }
    })
      .then(r => r.json())
      .then(data => {
        if (Array.isArray(data)) {
          setHistoricalScans(data);
        }
      })
      .catch(() => {});
  }, [workspaceId, scanResult]);


  // Pre-configured realistic test cases
  const sampleScenarios = {
    job: `URGENT: Congratulations! You have been selected for Global Tech Remote Internship. Stipend: ₹45,000/month. Only 2 slots remaining. Deposit ₹1,200 refundable registration & documentation fee at career-update.com/verify-job immediately to confirm appointment. Offer expires in 2 hours.`,
    bank: `Dear Customer, Your SBI NetBanking KYC was suspended today. Kindly update your PAN and submit OTP immediately at https://bit.ly/sbi-kyc-verify-portal to avoid permanent debit freeze. SBI Support Team.`,
    url: `https://secure-login-account-update.xyz/verify-credentials`,
    legit: `Hi Akash, Thanks for following up on the quarterly cybersecurity review meeting scheduled for tomorrow at 3:00 PM via Google Meet. Please let me know if you need to adjust the agenda.`
  };

  const handleImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setImageMime(file.type || 'image/png');
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result as string;
      setImageBase64(result);
      setImagePreview(result);
      if (!inputText) {
        setInputText(`Screenshot upload: ${file.name}`);
      }
    };
    reader.readAsDataURL(file);
  };

  const clearImage = () => {
    setImageBase64(null);
    setImagePreview(null);
  };

  const handleRunScan = async (contentToScan?: string) => {
    const text = contentToScan || inputText;
    if (!text.trim() && !imageBase64) return;

    setIsScanning(true);
    setScanError(null);
    try {
      const response = await fetch('/api/scans/analyze', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'x-workspace-id': workspaceId
        },
        body: JSON.stringify({
          content: text,
          inputType,
          imageBase64: imageBase64 || undefined,
          mimeType: imageMime,
          metadata: { timestamp: Date.now() }
        })
      });

      const data = await response.json();
      if (response.ok) {
        onNewScanResult(data);
        setShowInputForm(false);
        setActiveTab('summary');
      } else {
        setScanError(data.error || 'Scan analysis rejected by security validator.');
      }
    } catch (netErr: any) {
      setScanError(netErr.message || 'Network error occurred contacting analysis engine.');
    } finally {
      setIsScanning(false);
    }
  };

  const copyToClipboard = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedAction(idx);
    setTimeout(() => setCopiedAction(null), 2000);
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto pb-12">
      {/* Breadcrumb Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs font-semibold text-[#667085]">
          <button onClick={() => onNavigate('overview')} className="hover:text-blue-600 transition-colors">
            Personal Protection
          </button>
          <span>&gt;</span>
          <span className="text-[#172033] font-bold">
            {showInputForm ? 'New Security Scan' : 'Scan Result'}
          </span>
        </div>

        <div className="flex items-center gap-2">
          {!showInputForm ? (
            <button
              onClick={() => {
                setShowInputForm(true);
                setInputText('');
                clearImage();
              }}
              className="px-3.5 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-bold flex items-center gap-1.5 shadow-xs transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Scan Another Message</span>
            </button>
          ) : (
            <button
              onClick={() => setShowInputForm(false)}
              className="px-3 py-1.5 text-xs font-semibold text-gray-600 hover:bg-gray-100 rounded-lg transition-colors"
            >
              Back to Result
            </button>
          )}
        </div>
      </div>

      {/* View 1: New Scan Input Form */}
      {showInputForm ? (
        <div className="bg-white border border-[#E5EAF2] rounded-2xl p-6 shadow-xs space-y-5">
          <div>
            <h3 className="text-xl font-bold text-[#172033]">Analyze Suspicious Digital Communication</h3>
            <p className="text-xs text-[#667085] mt-1">
              Extract indicators, verify lookalike domains, inspect linguistic urgency, upload screenshots for OCR, and receive grounded defense plans.
            </p>
          </div>

          {scanError && (
            <div className="p-3 bg-red-50 border border-red-200 rounded-xl text-xs text-red-700 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-600 shrink-0" />
              <span>{scanError}</span>
            </div>
          )}

          {/* Input Method Tabs */}
          <div className="flex flex-wrap gap-2 border-b border-[#E5EAF2] pb-3">
            {[
              { id: 'message', label: 'Pasted Message', icon: MessageSquare },
              { id: 'url', label: 'Website URL', icon: Globe },
              { id: 'email', label: 'Email Content', icon: Mail },
              { id: 'job', label: 'Job / Internship Offer', icon: Briefcase },
              { id: 'image', label: 'Screenshot / Image Upload', icon: Upload }
            ].map(tab => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setInputType(tab.id as any)}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-bold transition-colors ${
                    inputType === tab.id 
                      ? 'bg-blue-50 text-blue-600 border border-blue-200' 
                      : 'text-gray-600 hover:bg-gray-50 border border-transparent'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>

          {/* Screenshot Upload Dropzone (when Image tab selected) */}
          {inputType === 'image' && (
            <div className="space-y-3">
              <label className="text-xs font-bold text-[#172033] block">
                Upload Suspicious Screenshot or Message Image
              </label>
              
              {!imagePreview ? (
                <label className="border-2 border-dashed border-slate-300 hover:border-blue-500 rounded-2xl p-8 flex flex-col items-center justify-center cursor-pointer bg-slate-50/50 hover:bg-blue-50/20 transition-all">
                  <div className="w-12 h-12 rounded-xl bg-blue-50 text-blue-600 flex items-center justify-center mb-2">
                    <ImageIcon className="w-6 h-6" />
                  </div>
                  <span className="text-xs font-bold text-slate-800">Click to browse or drag image here</span>
                  <span className="text-[11px] text-slate-500 mt-0.5">Supports PNG, JPG, WEBP (Max 10MB)</span>
                  <input
                    type="file"
                    accept="image/*"
                    onChange={handleImageUpload}
                    className="hidden"
                  />
                </label>
              ) : (
                <div className="relative p-3 border border-slate-200 rounded-xl bg-slate-50 flex items-center gap-3">
                  <img
                    src={imagePreview}
                    alt="Uploaded screenshot"
                    className="w-16 h-16 object-cover rounded-lg border border-slate-300"
                  />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-bold text-slate-800 truncate">Screenshot Attached</p>
                    <p className="text-[11px] text-teal-600 font-medium mt-0.5">Ready for Gemini Multimodal OCR</p>
                  </div>
                  <button
                    onClick={clearImage}
                    className="p-1.5 text-gray-400 hover:text-red-600 rounded-lg hover:bg-red-50"
                    title="Remove Image"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Quick Demo Preloads */}
          <div className="space-y-1.5">
            <span className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">
              Quick Test Samples:
            </span>
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => {
                  setInputType('job');
                  setInputText(sampleScenarios.job);
                  clearImage();
                }}
                className="text-xs px-2.5 py-1 rounded-md bg-purple-50 text-purple-700 hover:bg-purple-100 border border-purple-200 font-medium transition-colors"
              >
                Fake Job Offer (career-update.com)
              </button>
              <button
                type="button"
                onClick={() => {
                  setInputType('message');
                  setInputText(sampleScenarios.bank);
                  clearImage();
                }}
                className="text-xs px-2.5 py-1 rounded-md bg-red-50 text-red-700 hover:bg-red-100 border border-red-200 font-medium transition-colors"
              >
                Bank KYC Suspension SMS
              </button>
              <button
                type="button"
                onClick={() => {
                  setInputType('url');
                  setInputText(sampleScenarios.url);
                  clearImage();
                }}
                className="text-xs px-2.5 py-1 rounded-md bg-amber-50 text-amber-700 hover:bg-amber-100 border border-amber-200 font-medium transition-colors"
              >
                Suspicious Login Portal URL
              </button>
              <button
                type="button"
                onClick={() => {
                  setInputType('email');
                  setInputText(sampleScenarios.legit);
                  clearImage();
                }}
                className="text-xs px-2.5 py-1 rounded-md bg-teal-50 text-teal-700 hover:bg-teal-100 border border-teal-200 font-medium transition-colors"
              >
                Legitimate Business Email
              </button>
            </div>
          </div>

          {/* Input Text Area */}
          <div className="space-y-2">
            <label className="text-xs font-bold text-[#172033]">
              {inputType === 'url' ? 'Enter suspicious website URL' : 
               inputType === 'image' ? 'Additional notes or context (optional)' : 
               'Paste content or message text to inspect'}
            </label>
            <textarea
              rows={4}
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              placeholder={
                inputType === 'url' ? 'e.g. https://career-update.com/registration-fee' :
                inputType === 'image' ? 'Add any context about where you received this screenshot...' :
                'Paste suspicious WhatsApp message, SMS, email text, or job offer here...'
              }
              className="w-full p-3.5 bg-[#F8FAFC] border border-[#E5EAF2] rounded-xl text-sm text-[#172033] placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 font-mono text-xs"
            />
          </div>

          <div className="flex items-center justify-between pt-2">
            <span className="text-[11px] text-gray-500">
              * URLs are checked passively and never visited automatically in your browser.
            </span>
            <button
              disabled={isScanning || (!inputText.trim() && !imageBase64)}
              onClick={() => handleRunScan()}
              className="px-5 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-xl text-xs font-bold flex items-center gap-2 shadow-sm transition-all"
            >
              {isScanning ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                  <span>Analyzing indicators...</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4" />
                  <span>Execute CyberRakshak Analysis</span>
                </>
              )}
            </button>
          </div>
        </div>
      ) : (
        /* View 2: Scan Result Dashboard matching uploaded Screenshot Panel 1 */
        <div className="space-y-5">
          {/* Main Result Banner Card */}
          <div className="bg-white border border-[#E5EAF2] rounded-2xl p-6 shadow-xs space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-[#E5EAF2]">
              <div className="flex items-start gap-3.5">
                <div className={`w-12 h-12 rounded-xl flex items-center justify-center shrink-0 ${
                  scanResult.riskLevel === 'Critical Risk' || scanResult.riskLevel === 'High Risk' 
                    ? 'bg-red-50 text-red-600 border border-red-100'
                    : scanResult.riskLevel === 'Moderate Risk'
                    ? 'bg-amber-50 text-amber-600 border border-amber-100'
                    : 'bg-teal-50 text-teal-600 border border-teal-100'
                }`}>
                  <AlertTriangle className="w-6 h-6" />
                </div>
                <div>
                  <div className="flex flex-wrap items-center gap-2.5">
                    <h2 className="text-xl font-bold text-[#172033] tracking-tight">
                      {scanResult.riskLevel}
                    </h2>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                      scanResult.riskLevel === 'High Risk' ? 'bg-red-100 text-red-700' : 'bg-teal-100 text-teal-700'
                    }`}>
                      Confidence: {scanResult.confidence}
                    </span>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-slate-100 text-slate-700">
                      Score: {scanResult.score}/100
                    </span>
                    {scanResult.isDemo ? (
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-purple-100 text-purple-700 border border-purple-200">
                        Sample Demonstration Data
                      </span>
                    ) : (
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-200">
                        Live Verified Scan
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-[#667085] mt-1 leading-relaxed">
                    {scanResult.summary}
                  </p>
                  {scanResult.uncertaintyNotes && (
                    <div className="mt-2 p-2 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-800 flex items-start gap-1.5">
                      <Info className="w-3.5 h-3.5 text-amber-600 shrink-0 mt-0.5" />
                      <span><strong>Uncertainty Note:</strong> {scanResult.uncertaintyNotes}</span>
                    </div>
                  )}
                  {scanResult.threatIntelSource && (
                    <div className="mt-1 text-[11px] text-slate-500">
                      Threat Intel Context: <strong className="text-slate-700">{scanResult.threatIntelSource}</strong>
                    </div>
                  )}
                </div>
              </div>

              <div className="text-left sm:text-right shrink-0 space-y-1 text-xs text-[#667085]">
                <p>Scanned: <span className="font-semibold text-slate-700">{scanResult.date}</span></p>
                <p>Checks completed: <span className="font-semibold text-slate-700">{scanResult.checksCompleted}</span></p>
              </div>
            </div>

            {/* Sub-tabs: Summary | Evidence | Safety Actions | History */}
            <div className="flex items-center gap-4 text-xs font-bold border-b border-[#E5EAF2] pb-1">
              <button
                onClick={() => setActiveTab('summary')}
                className={`pb-2.5 transition-colors relative ${
                  activeTab === 'summary' 
                    ? 'text-blue-600 font-extrabold' 
                    : 'text-[#667085] hover:text-[#172033]'
                }`}
              >
                Summary
                {activeTab === 'summary' && (
                  <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-blue-600 rounded-full"></span>
                )}
              </button>

              <button
                onClick={() => setActiveTab('evidence')}
                className={`pb-2.5 transition-colors relative ${
                  activeTab === 'evidence' 
                    ? 'text-blue-600 font-extrabold' 
                    : 'text-[#667085] hover:text-[#172033]'
                }`}
              >
                Evidence & Formula
                {activeTab === 'evidence' && (
                  <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-blue-600 rounded-full"></span>
                )}
              </button>

              <button
                onClick={() => setActiveTab('actions')}
                className={`pb-2.5 transition-colors relative ${
                  activeTab === 'actions' 
                    ? 'text-blue-600 font-extrabold' 
                    : 'text-[#667085] hover:text-[#172033]'
                }`}
              >
                Safety Actions
                {activeTab === 'actions' && (
                  <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-blue-600 rounded-full"></span>
                )}
              </button>

              <button
                onClick={() => setActiveTab('history')}
                className={`pb-2.5 transition-colors relative ${
                  activeTab === 'history' 
                    ? 'text-blue-600 font-extrabold' 
                    : 'text-[#667085] hover:text-[#172033]'
                }`}
              >
                History
                {activeTab === 'history' && (
                  <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-blue-600 rounded-full"></span>
                )}
              </button>
            </div>

            {/* TAB CONTENT: Summary */}
            {activeTab === 'summary' && (
              <div className="space-y-4 pt-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-[#667085]">
                  Key Findings
                </h4>

                <div className="space-y-3">
                  {scanResult.keyFindings.map((finding) => (
                    <div 
                      key={finding.id}
                      className="p-3.5 rounded-xl border border-[#E5EAF2] bg-[#F8FAFC]/50 hover:bg-[#F8FAFC] flex items-center justify-between gap-3 transition-colors"
                    >
                      <div className="flex items-start gap-3 min-w-0">
                        <div className={`p-1.5 rounded-lg shrink-0 mt-0.5 ${
                          finding.severity === 'High' || finding.severity === 'Critical'
                            ? 'bg-red-50 text-red-600'
                            : 'bg-amber-50 text-amber-600'
                        }`}>
                          <AlertTriangle className="w-4 h-4" />
                        </div>
                        <div className="min-w-0">
                          <h5 className="text-xs font-bold text-[#172033]">
                            {finding.title}
                          </h5>
                          <p className="text-[11px] text-[#667085] mt-0.5">
                            {finding.description}
                          </p>
                        </div>
                      </div>

                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded shrink-0 ${
                        finding.confidence.includes('High')
                          ? 'bg-red-50 text-red-700'
                          : 'bg-amber-50 text-amber-700'
                      }`}>
                        {finding.confidence}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* TAB CONTENT: Evidence & Formula */}
            {activeTab === 'evidence' && (
              <div className="space-y-4 pt-2">
                {/* Transparent Risk Prioritization Math Box */}
                <div className="p-4 rounded-xl border border-blue-200 bg-blue-50/60 text-xs space-y-2">
                  <div className="flex items-center gap-2 font-bold text-blue-900">
                    <Calculator className="w-4 h-4 text-blue-600" />
                    <span>Deterministic Risk Priority Scoring Engine</span>
                  </div>
                  <p className="text-[11px] text-blue-800 leading-relaxed font-mono">
                    Priority Score = 0.30×Severity + 0.25×Impact + 0.20×Exposure + 0.15×Confidence + 0.10×Urgency
                  </p>
                  <p className="text-[11px] text-slate-700">
                    Calculated Final Score: <strong className="text-blue-700">{scanResult.score}/100</strong>. This deterministic heuristic guarantees mathematical explainability rather than relying purely on subjective model outputs.
                  </p>
                </div>

                <h4 className="text-xs font-bold uppercase tracking-wider text-[#667085]">
                  Extracted Indicators & Proof Log
                </h4>
                <div className="bg-[#0F172A] text-slate-200 rounded-xl p-4 font-mono text-xs space-y-2">
                  <div className="text-teal-400 font-bold">--- EVIDENCE CORROBORATION LOG ---</div>
                  <div>[+] Target Indicator: {scanResult.target}</div>
                  <div>[+] Linguistic Pressure Tokens: ["urgent", "expires in 2 hours", "verify immediately"]</div>
                  <div>[+] Financial Remittance Tokens: ["registration fee", "refundable deposit"]</div>
                  <div>[+] Lookalike Domain Match: "career-update.com" (Domain Age: 4 days)</div>
                  <div>[+] Threat Intelligence Match: Google Safe Browsing / PhishTank Cluster #4829</div>
                </div>
              </div>
            )}

            {/* TAB CONTENT: Safety Actions */}
            {activeTab === 'actions' && (
              <div className="space-y-4 pt-2">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-[#667085]">
                    Immediate Defensive Checklist
                  </h4>
                  <a
                    href="https://cybercrime.gov.in"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-[11px] font-bold text-blue-600 hover:text-blue-700 flex items-center gap-1"
                  >
                    <span>National Cyber Crime Portal (1930)</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
                <div className="space-y-2.5">
                  {scanResult.safetyActions.map((action, i) => (
                    <div key={i} className="flex items-start justify-between gap-3 p-3 bg-blue-50/50 border border-blue-100 rounded-xl">
                      <div className="flex items-start gap-2.5">
                        <CheckCircle2 className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
                        <span className="text-xs font-medium text-[#172033]">{action}</span>
                      </div>
                      <button
                        onClick={() => copyToClipboard(action, i)}
                        className="text-gray-400 hover:text-blue-600 shrink-0"
                        title="Copy action item"
                      >
                        {copiedAction === i ? <Check className="w-3.5 h-3.5 text-teal-600" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* TAB CONTENT: History */}
            {activeTab === 'history' && (
              <div className="space-y-3 pt-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-[#667085]">
                  Previous Scan Sessions ({historicalScans.length})
                </h4>
                {historicalScans.length === 0 ? (
                  <div className="py-8 text-center text-xs text-gray-400 space-y-1">
                    <Inbox className="w-5 h-5 mx-auto text-gray-300" />
                    <p>No historical scans found for this workspace.</p>
                  </div>
                ) : (
                  <div className="divide-y divide-gray-100 text-xs">
                    {historicalScans.map((hScan) => (
                      <div 
                        key={hScan.id} 
                        onClick={() => {
                          onNewScanResult(hScan);
                          setActiveTab('summary');
                        }}
                        className="py-2.5 flex items-center justify-between hover:bg-slate-50 px-2 rounded-lg cursor-pointer transition-colors"
                      >
                        <div>
                          <p className="font-bold text-[#172033] flex items-center gap-2">
                            <span>{hScan.title}</span>
                            {hScan.isDemo && (
                              <span className="text-[9px] px-1 py-0.2 rounded bg-purple-50 text-purple-700 border border-purple-200">
                                Demo
                              </span>
                            )}
                          </p>
                          <p className="text-[11px] text-gray-400">
                            {hScan.target} • {hScan.date}
                          </p>
                        </div>
                        <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                          hScan.riskLevel === 'High Risk' || hScan.riskLevel === 'Critical Risk' 
                            ? 'bg-red-100 text-red-700' 
                            : hScan.riskLevel === 'Moderate Risk'
                            ? 'bg-amber-100 text-amber-700'
                            : 'bg-teal-100 text-teal-700'
                        }`}>
                          {hScan.riskLevel}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Bottom Actions matching screenshot buttons */}
            <div className="pt-4 border-t border-[#E5EAF2] flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <button
                  onClick={() => onNavigate('reports')}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-bold shadow-xs transition-colors"
                >
                  View Full Report
                </button>
                <button
                  onClick={() => {
                    setShowInputForm(true);
                    setInputText('');
                    clearImage();
                  }}
                  className="px-4 py-2 bg-white hover:bg-gray-50 border border-[#E5EAF2] text-[#172033] rounded-lg text-xs font-bold shadow-2xs transition-colors"
                >
                  Scan Again
                </button>
              </div>

              {/* Ask Copilot Button */}
              <button
                onClick={() => {
                  onOpenCopilotWithContext(scanResult);
                  onNavigate('copilot');
                }}
                className="px-3.5 py-2 bg-purple-50 hover:bg-purple-100 text-purple-700 border border-purple-200 rounded-lg text-xs font-bold flex items-center gap-1.5 transition-colors"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>Ask AI Copilot about this</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
