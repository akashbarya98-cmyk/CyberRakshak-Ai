import React, { useState } from 'react';
import { 
  Settings, 
  User, 
  Languages, 
  ShieldAlert, 
  Trash2, 
  RotateCcw, 
  Check, 
  Sliders,
  Bell,
  EyeOff
} from 'lucide-react';

interface SettingsViewProps {
  onResetDemoData: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({ onResetDemoData }) => {
  const [language, setLanguage] = useState<'en' | 'hi' | 'hinglish'>('en');
  const [autoPurgeDays, setAutoPurgeDays] = useState('30');
  const [savedNotice, setSavedNotice] = useState(false);
  const [isResetting, setIsResetting] = useState(false);
  const [resetMessage, setResetMessage] = useState<string | null>(null);

  const handleSave = () => {
    setSavedNotice(true);
    setTimeout(() => setSavedNotice(false), 2500);
  };

  const handleReset = async () => {
    setIsResetting(true);
    try {
      await fetch('/api/settings/reset', { method: 'POST' });
      onResetDemoData();
      setResetMessage('Database and workspace reset to factory demonstration state.');
      setTimeout(() => setResetMessage(null), 3000);
    } catch {
      onResetDemoData();
      setResetMessage('Local state reset to factory demonstration state.');
      setTimeout(() => setResetMessage(null), 3000);
    } finally {
      setIsResetting(false);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto pb-12">
      <div>
        <h2 className="text-xl sm:text-2xl font-bold text-[#172033] tracking-tight flex items-center gap-2">
          <Settings className="w-6 h-6 text-blue-600" />
          <span>Platform Settings & Privacy Controls</span>
        </h2>
        <p className="text-xs text-[#667085] mt-0.5">
          Manage your account profile, localization, and privacy safeguards.
        </p>
      </div>

      <div className="bg-white border border-[#E5EAF2] rounded-2xl p-6 shadow-xs space-y-6">
        {/* User Profile */}
        <div className="pb-5 border-b border-[#E5EAF2] flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-full bg-[#1E293B] text-white font-bold flex items-center justify-center text-sm shadow-xs">
              AS
            </div>
            <div>
              <h3 className="font-bold text-sm text-[#172033]">Akash Sharma</h3>
              <p className="text-xs text-gray-500">akash.sharma@example.com • Personal Workspace</p>
            </div>
          </div>
          <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-blue-50 text-blue-700 border border-blue-200">
            Active Account
          </span>
        </div>

        {/* Language & Localization */}
        <div className="space-y-3 pb-5 border-b border-[#E5EAF2]">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-2">
            <Languages className="w-4 h-4 text-blue-600" />
            <span>AI Copilot & Interface Language</span>
          </h4>
          <p className="text-xs text-[#667085]">
            Configure preferred language for security guidance and AI Copilot explanations.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1">
            {[
              { id: 'en', label: 'English', desc: 'Standard technical terms' },
              { id: 'hi', label: 'हिंदी (Hindi)', desc: 'सुरक्षा मार्गदर्शन' },
              { id: 'hinglish', label: 'Hinglish', desc: 'Conversational mix' }
            ].map(lang => (
              <button
                key={lang.id}
                type="button"
                onClick={() => setLanguage(lang.id as any)}
                className={`p-3 rounded-xl border text-left transition-colors ${
                  language === lang.id
                    ? 'border-blue-600 bg-blue-50/50 text-blue-900 ring-1 ring-blue-600'
                    : 'border-[#E5EAF2] hover:bg-gray-50 text-gray-700'
                }`}
              >
                <div className="font-bold text-xs">{lang.label}</div>
                <div className="text-[11px] text-gray-500 mt-0.5">{lang.desc}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Data Retention & Privacy */}
        <div className="space-y-3 pb-5 border-b border-[#E5EAF2]">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-2">
            <EyeOff className="w-4 h-4 text-teal-600" />
            <span>Data Minimization & Scan Retention</span>
          </h4>
          <p className="text-xs text-[#667085]">
            Automatically purge submitted sensitive message texts after verification.
          </p>

          <div className="flex flex-wrap items-center gap-4 text-xs">
            <label htmlFor="retention-window-select" className="text-slate-700 font-semibold">Retention Window:</label>
            <select
              id="retention-window-select"
              aria-label="Select data retention window"
              value={autoPurgeDays}
              onChange={(e) => setAutoPurgeDays(e.target.value)}
              className="p-2 border border-slate-200 rounded-lg bg-gray-50 text-xs font-medium focus:outline-none"
            >
              <option value="7">Purge after 7 days</option>
              <option value="30">Purge after 30 days</option>
              <option value="90">Purge after 90 days</option>
              <option value="0">Immediately after scan (Zero persistence)</option>
            </select>
          </div>
        </div>

        {/* Reset Demo Data & Clear */}
        <div className="space-y-3 pt-1">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-2">
            <RotateCcw className="w-4 h-4 text-purple-600" />
            <span>Demonstration State</span>
          </h4>
          <p className="text-xs text-[#667085]">
            Reset sample job offers, business assessment results, and risk graph links to default seed state.
          </p>

          <div className="flex items-center gap-3">
            <button
              onClick={handleReset}
              disabled={isResetting}
              className="px-4 py-2 border border-purple-200 bg-purple-50 hover:bg-purple-100 disabled:opacity-50 text-purple-800 rounded-xl text-xs font-bold transition-colors shadow-2xs"
            >
              {isResetting ? 'Resetting Store...' : 'Reset Seed Demonstration Data'}
            </button>
            {resetMessage && (
              <span className="text-xs font-semibold text-teal-700 flex items-center gap-1">
                <Check className="w-3.5 h-3.5" />
                {resetMessage}
              </span>
            )}
          </div>
        </div>

        <div className="pt-4 border-t border-[#E5EAF2] flex items-center justify-between">
          {savedNotice && (
            <span className="text-xs font-bold text-teal-600 flex items-center gap-1">
              <Check className="w-4 h-4" /> Preferences updated
            </span>
          )}
          <button
            onClick={handleSave}
            className="ml-auto px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-xs font-bold shadow-xs transition-colors"
          >
            Save Preferences
          </button>
        </div>
      </div>
    </div>
  );
};
