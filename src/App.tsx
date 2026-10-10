/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { ViewMode, Finding, ScanResult, BusinessAssessment, RemediationTask, NotificationItem, OverviewData, WorkspaceUser } from './types';
import { 
  INITIAL_FINDINGS, 
  INITIAL_PRIORITY_ACTIONS, 
  INITIAL_SCAN_RESULT, 
  INITIAL_ASSESSMENT 
} from './mock/initialData';
import { Sidebar } from './components/layout/Sidebar';
import { Header } from './components/layout/Header';
import { OverviewView } from './components/overview/OverviewView';
import { PersonalProtectionView } from './components/personal/PersonalProtectionView';
import { BusinessSecurityView } from './components/business/BusinessSecurityView';
import { CyberRiskGraphView } from './components/graph/CyberRiskGraphView';
import { CopilotView } from './components/copilot/CopilotView';
import { ThreatIntelligenceView } from './components/threat/ThreatIntelligenceView';
import { RemediationCenterView } from './components/remediation/RemediationCenterView';
import { SecurityReportsView } from './components/reports/SecurityReportsView';
import { CommunityView } from './components/community/CommunityView';
import { SettingsView } from './components/settings/SettingsView';
import { NotificationModal } from './components/common/NotificationModal';
import { 
  getAuthToken, 
  clearAuthSession, 
  initDemoSession 
} from './utils/api';

export default function App() {
  const [currentView, setCurrentView] = useState<ViewMode>('overview');
  const [currentWorkspaceId, setCurrentWorkspaceId] = useState<'ws-personal' | 'ws-business'>('ws-personal');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [notificationOpen, setNotificationOpen] = useState(false);
  const [notificationCount, setNotificationCount] = useState(0);
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  const [toastMessage, setToastMessage] = useState<{ type: 'success' | 'error' | 'info'; text: string } | null>(null);
  const [currentUser, setCurrentUser] = useState<WorkspaceUser>({
    id: 'usr-akash',
    name: 'Akash Sharma',
    email: 'akash.sharma@example.com',
    role: 'Owner',
    currentWorkspaceId: 'ws-personal'
  });

  // Core application state
  const [overviewData, setOverviewData] = useState<OverviewData | null>(null);
  const [findings, setFindings] = useState<Finding[]>(INITIAL_FINDINGS);
  const [priorityActions, setPriorityActions] = useState<RemediationTask[]>(INITIAL_PRIORITY_ACTIONS);
  const [scanResult, setScanResult] = useState<ScanResult>(INITIAL_SCAN_RESULT);
  const [assessment, setAssessment] = useState<BusinessAssessment>(INITIAL_ASSESSMENT);
  const [copilotContext, setCopilotContext] = useState<any>(null);
  const [isLoadingWorkspace, setIsLoadingWorkspace] = useState(false);

  // Auto-dismiss toast
  useEffect(() => {
    if (toastMessage) {
      const timer = setTimeout(() => setToastMessage(null), 4500);
      return () => clearTimeout(timer);
    }
  }, [toastMessage]);

  const loadWorkspaceData = async (wsId: string) => {
    setIsLoadingWorkspace(true);
    try {
      // 1. Fetch overview
      const ovRes = await fetch('/api/overview', {
        headers: { 'x-workspace-id': wsId }
      });
      if (ovRes.status === 401) {
        clearAuthSession();
        initDemoSession('Owner').then(() => loadWorkspaceData(wsId)).catch(() => {});
        return;
      }
      if (ovRes.ok) {
        const ovData: OverviewData = await ovRes.json();
        setOverviewData(ovData);
        if (Array.isArray(ovData.recentFindings) && ovData.recentFindings.length > 0) {
          setFindings(ovData.recentFindings);
        }
      }

      // 2. Fetch remediation tasks
      const remRes = await fetch('/api/remediation', {
        headers: { 'x-workspace-id': wsId }
      });
      if (remRes.ok) {
        const remData = await remRes.json();
        if (Array.isArray(remData) && remData.length > 0) {
          setPriorityActions(remData);
        }
      }

      // 3. Fetch latest scan
      const scanRes = await fetch('/api/scans', {
        headers: { 'x-workspace-id': wsId }
      });
      if (scanRes.ok) {
        const scanData = await scanRes.json();
        if (Array.isArray(scanData) && scanData.length > 0) {
          setScanResult(scanData[0]);
        }
      }

      // 4. Fetch latest assessment
      const assRes = await fetch('/api/assessments', {
        headers: { 'x-workspace-id': wsId }
      });
      if (assRes.ok) {
        const assData = await assRes.json();
        if (Array.isArray(assData) && assData.length > 0) {
          setAssessment(assData[0]);
        }
      }

      // 5. Notifications
      const notifRes = await fetch('/api/notifications', {
        headers: { 'x-workspace-id': wsId }
      });
      if (notifRes.ok) {
        const notifData: NotificationItem[] = await notifRes.json();
        if (Array.isArray(notifData)) {
          setNotifications(notifData);
          setNotificationCount(notifData.length);
        }
      }

      // 6. Workspaces & User Profile
      const wsRes = await fetch('/api/workspaces', {
        headers: { 'x-workspace-id': wsId }
      });
      if (wsRes.ok) {
        const wsJson = await wsRes.json();
        if (wsJson.user) {
          setCurrentUser(wsJson.user);
        }
      }
    } catch (err) {
      console.warn('Data load error:', err);
    } finally {
      setIsLoadingWorkspace(false);
    }
  };

  // Ensure active session on startup without presenting any login page
  useEffect(() => {
    const existingToken = getAuthToken();
    if (!existingToken) {
      initDemoSession('Owner')
        .then(result => {
          if (result.user) setCurrentUser(result.user);
          loadWorkspaceData(currentWorkspaceId);
        })
        .catch(() => {
          loadWorkspaceData(currentWorkspaceId);
        });
    } else {
      loadWorkspaceData(currentWorkspaceId);
    }
  }, [currentWorkspaceId]);

  const handleSignOut = async () => {
    clearAuthSession();
    try {
      const res = await initDemoSession('Owner');
      if (res.user) setCurrentUser(res.user);
      setToastMessage({ type: 'info', text: 'Workspace session refreshed as Owner.' });
      loadWorkspaceData(currentWorkspaceId);
    } catch {
      setToastMessage({ type: 'info', text: 'Workspace session reset.' });
    }
  };

  // Global search handler
  const handleSearch = (query: string) => {
    if (!query.trim()) return;
    const lower = query.toLowerCase();

    // Check if query matches a finding title
    const matchedFinding = findings.find(f => f.title.toLowerCase().includes(lower) || f.category?.toLowerCase().includes(lower));
    if (matchedFinding) {
      setCopilotContext(matchedFinding);
      setCurrentView('personal');
      return;
    }

    if (lower.includes('scan') || lower.includes('phish') || lower.includes('sms') || lower.includes('url') || lower.includes('job') || lower.includes('message')) {
      setCurrentView('personal');
    } else if (lower.includes('business') || lower.includes('website') || lower.includes('domain') || lower.includes('ssl') || lower.includes('tls') || lower.includes('cert')) {
      setCurrentView('business');
    } else if (lower.includes('graph') || lower.includes('node') || lower.includes('relation') || lower.includes('cluster')) {
      setCurrentView('graph');
    } else if (lower.includes('copilot') || lower.includes('ai') || lower.includes('ask') || lower.includes('chat') || lower.includes('help')) {
      setCurrentView('copilot');
    } else if (lower.includes('remediat') || lower.includes('fix') || lower.includes('task') || lower.includes('action')) {
      setCurrentView('remediation');
    } else if (lower.includes('report') || lower.includes('pdf') || lower.includes('csv') || lower.includes('audit')) {
      setCurrentView('reports');
    } else if (lower.includes('threat') || lower.includes('intel') || lower.includes('feed') || lower.includes('cert-in')) {
      setCurrentView('threat');
    } else if (lower.includes('community') || lower.includes('crowd') || lower.includes('share')) {
      setCurrentView('community');
    } else if (lower.includes('setting') || lower.includes('config') || lower.includes('preference') || lower.includes('reset')) {
      setCurrentView('settings');
    }
  };

  const handleFixAction = (taskId: string) => {
    setCurrentView('remediation');
  };

  const handleSwitchWorkspace = async (wsId: string) => {
    setCurrentWorkspaceId(wsId as any);
    try {
      await fetch('/api/workspaces/switch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ workspaceId: wsId })
      });
    } catch {}

    // Switch view to match selected context
    if (wsId === 'ws-business') {
      setCurrentView('business');
    } else {
      setCurrentView('personal');
    }
  };

  const handleUpdateTaskStatus = async (taskId: string, newStatus: RemediationTask['status']) => {
    const previousActions = [...priorityActions];
    // Optimistic UI update
    setPriorityActions(prev => prev.map(t => t.id === taskId ? { ...t, status: newStatus } : t));

    try {
      const res = await fetch(`/api/remediation/${taskId}`, {
        method: 'PATCH',
        headers: { 
          'Content-Type': 'application/json',
          'x-workspace-id': currentWorkspaceId
        },
        body: JSON.stringify({ status: newStatus })
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error || `Server responded with HTTP ${res.status}`);
      }

      const updated = await res.json();
      setPriorityActions(prev => prev.map(t => t.id === taskId ? { ...t, ...updated } : t));
      setToastMessage({ type: 'success', text: `Task updated to "${newStatus}" and persisted to database.` });

      // Refresh overview posture and notifications
      loadWorkspaceData(currentWorkspaceId);
    } catch (e: any) {
      // Revert optimistic update
      setPriorityActions(previousActions);
      setToastMessage({ type: 'error', text: `Failed to save task status: ${e.message || 'Operation failed'}. Changes were not saved.` });
    }
  };

  const handleResetDemoData = async () => {
    try {
      await fetch('/api/settings/reset', { method: 'POST' });
      await loadWorkspaceData(currentWorkspaceId);
      setToastMessage({ type: 'info', text: 'Database reset to initial factory demonstration state.' });
    } catch {
      setFindings(INITIAL_FINDINGS);
      setPriorityActions(INITIAL_PRIORITY_ACTIONS);
      setScanResult(INITIAL_SCAN_RESULT);
      setAssessment(INITIAL_ASSESSMENT);
      setNotificationCount(3);
    }
  };

  return (
    <div className="min-h-screen bg-[#F7F9FC] text-[#172033] flex">
      {/* Persistent Left Sidebar */}
      <Sidebar
        currentView={currentView}
        onSelectView={(view) => setCurrentView(view)}
        isOpenMobile={mobileMenuOpen}
        onCloseMobile={() => setMobileMenuOpen(false)}
        currentWorkspaceId={currentWorkspaceId}
        onSwitchWorkspace={handleSwitchWorkspace}
        onSignOut={handleSignOut}
      />

      {/* Main Content Area */}
      <div className="flex-1 lg:pl-64 flex flex-col min-w-0 min-h-screen">
        {/* Sticky Top Header */}
        <Header
          onOpenMobileMenu={() => setMobileMenuOpen(true)}
          onSearch={handleSearch}
          onOpenNotifications={() => setNotificationOpen(true)}
          notificationCount={notificationCount}
        />

        {/* View Container */}
        <main className="flex-1 p-4 sm:p-6 lg:p-8 overflow-y-auto">
          {currentView === 'overview' && (
            <OverviewView
              onNavigate={(view) => setCurrentView(view)}
              findings={findings}
              priorityActions={priorityActions}
              overviewData={overviewData}
              userName={currentUser.name.split(' ')[0]}
              isLoading={isLoadingWorkspace}
              onFixAction={handleFixAction}
              onSelectFinding={(fId) => {
                const found = findings.find(f => f.id === fId);
                if (found) setCopilotContext(found);
              }}
            />
          )}

          {currentView === 'personal' && (
            <PersonalProtectionView
              scanResult={scanResult}
              workspaceId={currentWorkspaceId}
              onNewScanResult={(res) => {
                setScanResult(res);
                loadWorkspaceData(currentWorkspaceId);
              }}
              onNavigate={(view) => setCurrentView(view)}
              onOpenCopilotWithContext={(ctx) => setCopilotContext(ctx)}
            />
          )}

          {currentView === 'business' && (
            <BusinessSecurityView
              assessment={assessment}
              workspaceId={currentWorkspaceId}
              onNewAssessment={(ass) => {
                setAssessment(ass);
                loadWorkspaceData(currentWorkspaceId);
              }}
              onNavigate={(view) => setCurrentView(view)}
              onOpenCopilotWithContext={(ctx) => setCopilotContext(ctx)}
            />
          )}

          {currentView === 'graph' && (
            <CyberRiskGraphView
              workspaceId={currentWorkspaceId}
              onAskCopilot={(node) => {
                setCopilotContext(node);
                setCurrentView('copilot');
              }}
              onNavigate={(view) => setCurrentView(view)}
            />
          )}

          {currentView === 'copilot' && (
            <CopilotView
              initialContext={copilotContext}
              workspaceId={currentWorkspaceId}
            />
          )}

          {currentView === 'threat' && (
            <ThreatIntelligenceView />
          )}

          {currentView === 'remediation' && (
            <RemediationCenterView
              tasks={priorityActions}
              onUpdateStatus={handleUpdateTaskStatus}
              workspaceId={currentWorkspaceId}
              onRefreshTasks={() => loadWorkspaceData(currentWorkspaceId)}
              onAskCopilot={(task) => {
                setCopilotContext(task);
                setCurrentView('copilot');
              }}
            />
          )}

          {currentView === 'reports' && (
            <SecurityReportsView
              findings={findings}
              remediationTasks={priorityActions}
              userName={currentUser.name}
              workspaceName={currentWorkspaceId === 'ws-personal' ? 'Personal Account' : 'Acme / Example Inc.'}
            />
          )}

          {currentView === 'community' && (
            <CommunityView />
          )}

          {currentView === 'settings' && (
            <SettingsView onResetDemoData={handleResetDemoData} />
          )}
        </main>
      </div>

      {/* Floating Status / Error Toast Banner */}
      {toastMessage && (
        <div className="fixed bottom-5 right-5 z-50 max-w-md animate-fade-in">
          <div className={`p-4 rounded-xl shadow-lg border text-xs font-semibold flex items-center gap-3 ${
            toastMessage.type === 'error'
              ? 'bg-red-50 text-red-800 border-red-200'
              : toastMessage.type === 'success'
              ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
              : 'bg-blue-50 text-blue-800 border-blue-200'
          }`}>
            <span>{toastMessage.text}</span>
            <button
              onClick={() => setToastMessage(null)}
              className="ml-auto text-xs text-gray-400 hover:text-gray-700 font-bold"
            >
              ✕
            </button>
          </div>
        </div>
      )}

      {/* Notification Drawer Modal */}
      <NotificationModal
        isOpen={notificationOpen}
        notifications={notifications}
        onClose={() => setNotificationOpen(false)}
        onMarkAllRead={() => {
          fetch('/api/notifications/clear', { 
            method: 'POST',
            headers: { 'x-workspace-id': currentWorkspaceId }
          })
            .then(() => {
              setNotifications([]);
              setNotificationCount(0);
            })
            .catch(() => {
              setNotifications([]);
              setNotificationCount(0);
            });
        }}
      />
    </div>
  );
}

