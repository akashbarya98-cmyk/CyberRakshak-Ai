import React, { useState } from 'react';
import { 
  LayoutDashboard, 
  ShieldCheck, 
  Building2, 
  Network, 
  Sparkles, 
  Radar, 
  Wrench, 
  FileText, 
  Settings, 
  LogOut, 
  ChevronDown,
  ShieldAlert,
  Users,
  Check,
  Briefcase,
  UserCheck
} from 'lucide-react';
import { ViewMode } from '../../types';

interface SidebarProps {
  currentView: ViewMode;
  onSelectView: (view: ViewMode) => void;
  isOpenMobile: boolean;
  onCloseMobile: () => void;
  currentWorkspaceId?: string;
  onSwitchWorkspace?: (wsId: string) => void;
  onSignOut?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentView,
  onSelectView,
  isOpenMobile,
  onCloseMobile,
  currentWorkspaceId = 'ws-personal',
  onSwitchWorkspace,
  onSignOut
}) => {
  const [showWorkspaceMenu, setShowWorkspaceMenu] = useState(false);

  const navItems = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'personal', label: 'Personal Protection', icon: ShieldCheck },
    { id: 'business', label: 'Business Security', icon: Building2 },
    { id: 'graph', label: 'Cyber Risk Graph', icon: Network },
    { id: 'copilot', label: 'AI Security Copilot', icon: Sparkles },
    { id: 'threat', label: 'Threat Intelligence', icon: Radar },
    { id: 'remediation', label: 'Remediation Center', icon: Wrench },
    { id: 'reports', label: 'Security Reports', icon: FileText },
    { id: 'community', label: 'Community Intel', icon: Users },
    { id: 'settings', label: 'Settings', icon: Settings },
  ] as const;

  const isPersonal = currentWorkspaceId === 'ws-personal';

  return (
    <>
      {/* Mobile backdrop */}
      {isOpenMobile && (
        <div 
          className="fixed inset-0 bg-slate-900/40 z-40 lg:hidden backdrop-blur-xs transition-opacity"
          onClick={onCloseMobile}
        />
      )}

      <aside className={`
        fixed top-0 bottom-0 left-0 z-50 w-64 bg-white border-r border-[#E5EAF2] flex flex-col justify-between
        transition-transform duration-200 ease-in-out
        ${isOpenMobile ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
      `}>
        {/* Brand Header */}
        <div className="p-5 border-b border-[#E5EAF2]">
          <div className="flex items-center gap-3 cursor-pointer" onClick={() => onSelectView('overview')}>
            {/* Logo Shield with circuit */}
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-700 via-blue-600 to-indigo-600 flex items-center justify-center text-white shadow-md shadow-blue-500/20">
              <div className="relative">
                <ShieldAlert className="w-6 h-6 text-white" />
                <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-teal-400 ring-2 ring-white"></span>
              </div>
            </div>
            <div>
              <h1 className="font-bold text-[17px] text-[#172033] tracking-tight flex items-center gap-1.5">
                CyberRakshak <span className="text-blue-600">AI</span>
              </h1>
              <p className="text-[11px] font-medium text-[#667085]">
                Detect. Understand. Protect.
              </p>
            </div>
          </div>
        </div>

        {/* Navigation Items */}
        <div className="flex-1 py-4 px-3 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentView === item.id;
            return (
              <button
                key={item.id}
                onClick={() => {
                  onSelectView(item.id as ViewMode);
                  onCloseMobile();
                }}
                className={`
                  w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors
                  ${isActive 
                    ? 'bg-[#EFF6FF] text-[#2563EB] font-semibold shadow-xs' 
                    : 'text-[#475467] hover:bg-[#F8FAFC] hover:text-[#172033]'}
                `}
              >
                <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-[#2563EB]' : 'text-[#667085]'}`} />
                <span className="truncate">{item.label}</span>
                {item.id === 'copilot' && (
                  <span className="ml-auto text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.5 rounded bg-purple-100 text-purple-700">
                    AI
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* User Profile & Interactive Workspace Switcher Footer */}
        <div className="p-3 border-t border-[#E5EAF2] space-y-2 relative">
          {/* Workspace Switcher Popover */}
          {showWorkspaceMenu && (
            <div className="absolute bottom-20 left-3 right-3 bg-white border border-[#E5EAF2] rounded-xl shadow-xl p-2 z-50 space-y-1 animate-in fade-in slide-in-from-bottom-2">
              <div className="px-2 py-1.5 text-[10px] font-bold text-gray-400 uppercase tracking-wider">
                Switch Workspace
              </div>

              <button
                onClick={() => {
                  if (onSwitchWorkspace) onSwitchWorkspace('ws-personal');
                  setShowWorkspaceMenu(false);
                }}
                className={`w-full flex items-center justify-between p-2 rounded-lg text-left text-xs transition-colors ${
                  isPersonal ? 'bg-blue-50 text-blue-800 font-semibold' : 'hover:bg-slate-50 text-slate-700'
                }`}
              >
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 rounded-md bg-indigo-600 text-white flex items-center justify-center text-[10px] font-bold">
                    A
                  </div>
                  <div>
                    <div className="leading-tight">Personal Workspace</div>
                    <div className="text-[10px] text-gray-400 font-normal">Akash Sharma</div>
                  </div>
                </div>
                {isPersonal && <Check className="w-3.5 h-3.5 text-blue-600" />}
              </button>

              <button
                onClick={() => {
                  if (onSwitchWorkspace) onSwitchWorkspace('ws-business');
                  setShowWorkspaceMenu(false);
                }}
                className={`w-full flex items-center justify-between p-2 rounded-lg text-left text-xs transition-colors ${
                  !isPersonal ? 'bg-blue-50 text-blue-800 font-semibold' : 'hover:bg-slate-50 text-slate-700'
                }`}
              >
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 rounded-md bg-blue-600 text-white flex items-center justify-center text-[10px] font-bold">
                    E
                  </div>
                  <div>
                    <div className="leading-tight">Business Perimeter</div>
                    <div className="text-[10px] text-gray-400 font-normal">Acme / Example Inc.</div>
                  </div>
                </div>
                {!isPersonal && <Check className="w-3.5 h-3.5 text-blue-600" />}
              </button>
            </div>
          )}

          {/* Profile Card Trigger */}
          <div 
            onClick={() => setShowWorkspaceMenu(!showWorkspaceMenu)}
            className="flex items-center justify-between p-2 rounded-lg hover:bg-[#F8FAFC] transition-colors cursor-pointer group"
          >
            <div className="flex items-center gap-2.5 min-w-0">
              <div className={`w-8 h-8 rounded-full text-white font-semibold text-xs flex items-center justify-center shrink-0 shadow-xs ${
                isPersonal ? 'bg-indigo-600' : 'bg-blue-700'
              }`}>
                {isPersonal ? 'A' : 'E'}
              </div>
              <div className="min-w-0 text-left">
                <p className="text-xs font-semibold text-[#172033] truncate">
                  {isPersonal ? 'Akash Sharma' : 'Acme / Example Inc.'}
                </p>
                <p className="text-[11px] text-[#667085] truncate">
                  {isPersonal ? 'Personal Account' : 'Business Workspace'}
                </p>
              </div>
            </div>
            <ChevronDown className="w-4 h-4 text-[#98A2B3] group-hover:text-[#475467] shrink-0" />
          </div>

          <button 
            onClick={() => {
              if (onSignOut) {
                onSignOut();
              } else {
                onSelectView('overview');
              }
            }}
            className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium text-[#667085] hover:text-red-600 hover:bg-red-50/50 transition-colors"
          >
            <LogOut className="w-4 h-4" />
            <span>Sign Out</span>
          </button>
        </div>
      </aside>
    </>
  );
};
