import React, { useState, useEffect } from 'react';
import { Search, Bell, HelpCircle, ChevronDown, Menu, Sparkles, X, CheckCircle2 } from 'lucide-react';

interface HeaderProps {
  onOpenMobileMenu: () => void;
  onSearch: (query: string) => void;
  onOpenNotifications: () => void;
  notificationCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  onOpenMobileMenu,
  onSearch,
  onOpenNotifications,
  notificationCount
}) => {
  const [searchVal, setSearchVal] = useState('');
  const [showHelpModal, setShowHelpModal] = useState(false);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && showHelpModal) {
        setShowHelpModal(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [showHelpModal]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSearch(searchVal);
  };

  return (
    <>
      <header className="sticky top-0 z-30 bg-white/90 backdrop-blur-md border-b border-[#E5EAF2] px-4 lg:px-8 py-3 flex items-center justify-between gap-4">
        {/* Left: Mobile menu button + Search bar */}
        <div className="flex items-center gap-3 flex-1 max-w-2xl">
          <button
            onClick={onOpenMobileMenu}
            className="lg:hidden p-2 rounded-lg text-gray-500 hover:text-gray-900 hover:bg-gray-100 focus:outline-none"
            aria-label="Toggle navigation menu"
          >
            <Menu className="w-5 h-5" />
          </button>

          <form onSubmit={handleSearchSubmit} className="relative w-full">
            <Search className="w-4 h-4 text-[#98A2B3] absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              id="global-search-input"
              type="text"
              aria-label="Search CyberRakshak Intelligence"
              value={searchVal}
              onChange={(e) => {
                setSearchVal(e.target.value);
                onSearch(e.target.value);
              }}
              placeholder="Search anything... (e.g. URL, domain, finding, asset)"
              className="w-full pl-10 pr-4 py-2 bg-[#F8FAFC] border border-[#E5EAF2] rounded-lg text-sm text-[#172033] placeholder-[#98A2B3] focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 focus:bg-white transition-all"
            />
          </form>
        </div>

        {/* Right Controls */}
        <div className="flex items-center gap-2 sm:gap-3 shrink-0">
          {/* Demo Mode Badge */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-purple-50 border border-purple-200/80 text-purple-700 text-xs font-semibold shadow-xs">
            <Sparkles className="w-3.5 h-3.5 text-purple-600" />
            <span className="hidden sm:inline">Demo Mode</span>
          </div>

          {/* Notifications */}
          <button
            onClick={onOpenNotifications}
            className="relative p-2 text-[#667085] hover:text-[#172033] hover:bg-gray-100 rounded-lg transition-colors"
            title="Notifications"
            aria-label={`Open notifications (${notificationCount} unread)`}
          >
            <Bell className="w-5 h-5" />
            {notificationCount > 0 && (
              <span className="absolute top-1.5 right-1.5 min-w-[16px] h-4 px-1 rounded-full bg-red-600 text-[10px] font-bold text-white flex items-center justify-center leading-none ring-2 ring-white">
                {notificationCount}
              </span>
            )}
          </button>

          {/* Help & Documentation */}
          <button
            onClick={() => setShowHelpModal(true)}
            className="p-2 text-[#667085] hover:text-[#172033] hover:bg-gray-100 rounded-lg transition-colors"
            title="CyberRakshak Documentation & Help"
            aria-label="Open safety guide"
          >
            <HelpCircle className="w-5 h-5" />
          </button>

          {/* User Profile Pill */}
          <div className="hidden sm:flex items-center gap-2 pl-2 border-l border-[#E5EAF2]">
            <div className="w-8 h-8 rounded-full bg-[#1E293B] text-white text-xs font-bold flex items-center justify-center ring-2 ring-slate-100 shadow-xs">
              AS
            </div>
            <span className="text-sm font-semibold text-[#172033]">Akash Sharma</span>
            <ChevronDown className="w-4 h-4 text-[#98A2B3]" />
          </div>
        </div>
      </header>

      {/* Help Modal */}
      {showHelpModal && (
        <div 
          className="fixed inset-0 z-50 bg-slate-900/50 backdrop-blur-xs flex items-center justify-center p-4"
          role="dialog"
          aria-modal="true"
          aria-labelledby="help-guide-title"
        >
          <div className="bg-white rounded-2xl max-w-lg w-full p-6 shadow-2xl border border-gray-100 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-gray-100">
              <div className="flex items-center gap-2">
                <div className="p-2 bg-blue-50 text-blue-600 rounded-lg">
                  <HelpCircle className="w-5 h-5" />
                </div>
                <div>
                  <h3 id="help-guide-title" className="font-bold text-[#172033]">CyberRakshak AI Safety Guide</h3>
                  <p className="text-xs text-gray-500">Detect. Understand. Protect.</p>
                </div>
              </div>
              <button 
                onClick={() => setShowHelpModal(false)}
                aria-label="Close safety guide"
                className="p-1.5 text-gray-400 hover:text-gray-700 rounded-lg hover:bg-gray-100"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-sm text-[#475467]">
              <p>
                CyberRakshak AI is built to give both individuals and small business owners explainable, actionable digital defense intelligence.
              </p>
              <div className="space-y-2 bg-blue-50/60 p-3.5 rounded-xl border border-blue-100">
                <div className="flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
                  <span><strong>Personal Protection:</strong> Scan suspicious SMS messages, WhatsApp job offers, bank KYC links, and recruitment emails.</span>
                </div>
                <div className="flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
                  <span><strong>Business Security:</strong> Safely evaluate domain security posture, SSL/TLS validity, and HTTP security headers without invasive testing.</span>
                </div>
                <div className="flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
                  <span><strong>Cyber Risk Graph:</strong> Visually correlate findings, indicators, and assets to discover attack clusters.</span>
                </div>
                <div className="flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
                  <span><strong>AI Copilot:</strong> Query Gemini for step-by-step guidance in English, Hindi, or Hinglish.</span>
                </div>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setShowHelpModal(false)}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold rounded-lg shadow-xs transition-colors"
              >
                Got it
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
