import React, { useState } from 'react';
import { 
  Wrench, 
  CheckCircle2, 
  Clock, 
  AlertTriangle, 
  Check, 
  ShieldCheck, 
  RotateCcw,
  Sparkles,
  User,
  Calendar,
  Layers,
  ArrowRight
} from 'lucide-react';
import { RemediationTask } from '../../types';

interface RemediationCenterViewProps {
  tasks: RemediationTask[];
  onUpdateStatus: (taskId: string, newStatus: RemediationTask['status']) => void;
  workspaceId?: string;
  onRefreshTasks?: () => void;
  onAskCopilot?: (context: any) => void;
}

export const RemediationCenterView: React.FC<RemediationCenterViewProps> = ({
  tasks,
  onUpdateStatus,
  workspaceId = 'ws-personal',
  onRefreshTasks,
  onAskCopilot
}) => {
  const [filterStatus, setFilterStatus] = useState<string>('All');
  const [selectedTaskId, setSelectedTaskId] = useState<string | null>(tasks[0]?.id || null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [verificationFeedback, setVerificationFeedback] = useState<{ id: string; success: boolean; msg: string } | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [assigneeInput, setAssigneeInput] = useState('');

  const filteredTasks = tasks.filter(t => {
    if (filterStatus === 'All') return true;
    return t.status === filterStatus;
  });

  const activeTask = filteredTasks.find(t => t.id === selectedTaskId) || filteredTasks[0] || null;

  const getStatusBadge = (status: RemediationTask['status']) => {
    switch (status) {
      case 'Resolved':
        return 'bg-emerald-50 text-emerald-700 border-emerald-200';
      case 'In Progress':
        return 'bg-blue-50 text-blue-700 border-blue-200';
      case 'Awaiting Verification':
        return 'bg-purple-50 text-purple-700 border-purple-200';
      default:
        return 'bg-amber-50 text-amber-700 border-amber-200';
    }
  };

  const getVerificationBadge = (task: RemediationTask) => {
    const vStatus = task.verificationStatus;
    if (vStatus === 'independently-verified') {
      return (
        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-300 flex items-center gap-1">
          <ShieldCheck className="w-3 h-3" />
          <span>Independently Verified ✓</span>
        </span>
      );
    }
    if (vStatus === 'user-reported') {
      return (
        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-purple-50 text-purple-700 border border-purple-200 flex items-center gap-1">
          <Check className="w-3 h-3" />
          <span>User-Reported Fix</span>
        </span>
      );
    }
    if (vStatus === 'verification-failed') {
      return (
        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-rose-50 text-rose-700 border border-rose-200 flex items-center gap-1">
          <AlertTriangle className="w-3 h-3" />
          <span>Verification Failed</span>
        </span>
      );
    }
    return (
      <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-slate-100 text-slate-600 border border-slate-200">
        Pending Verification
      </span>
    );
  };

  // Safe passive re-probe to independently verify fix
  const handleRerunVerification = async (taskId: string) => {
    setIsVerifying(true);
    setVerificationFeedback(null);
    try {
      const res = await fetch(`/api/remediation/${taskId}/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-workspace-id': workspaceId
        }
      });
      const data = await res.json();
      if (res.ok) {
        const isSuccess = data.verificationStatus === 'independently-verified';
        setVerificationFeedback({
          id: taskId,
          success: isSuccess,
          msg: data.verificationDetails || (isSuccess ? 'Verification re-probe passed successfully.' : 'Verification re-probe completed.')
        });
        if (onRefreshTasks) onRefreshTasks();
      } else {
        setVerificationFeedback({
          id: taskId,
          success: false,
          msg: data.error || 'Automated verification failed.'
        });
      }
    } catch (err: any) {
      setVerificationFeedback({
        id: taskId,
        success: false,
        msg: err.message || 'Verification connection failed.'
      });
    } finally {
      setIsVerifying(false);
    }
  };

  // Generate remediation tasks from real workspace findings
  const handleGenerateFromFindings = async () => {
    setIsGenerating(true);
    try {
      const res = await fetch('/api/remediation/generate-from-findings', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-workspace-id': workspaceId
        }
      });
      if (res.ok) {
        if (onRefreshTasks) onRefreshTasks();
      }
    } catch {
      // Handled cleanly
    } finally {
      setIsGenerating(false);
    }
  };

  // Save assignee
  const handleSaveAssignee = async (taskId: string) => {
    if (!assigneeInput.trim()) return;
    try {
      await fetch(`/api/remediation/${taskId}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'x-workspace-id': workspaceId
        },
        body: JSON.stringify({ assignee: assigneeInput.trim() })
      });
      setAssigneeInput('');
      if (onRefreshTasks) onRefreshTasks();
    } catch {}
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto pb-12">
      {/* Top Header & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-xl sm:text-2xl font-bold text-[#172033] tracking-tight flex items-center gap-2">
            <Wrench className="w-6 h-6 text-blue-600" />
            <span>Remediation Center</span>
          </h2>
          <p className="text-xs text-[#667085] mt-0.5">
            Systematic tracking and independent verification of perimeter remediations and posture tasks.
          </p>
        </div>

        <button
          onClick={handleGenerateFromFindings}
          disabled={isGenerating}
          className="px-3.5 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-xl text-xs font-bold flex items-center gap-1.5 shadow-xs transition-colors self-start sm:self-auto"
        >
          <Layers className="w-3.5 h-3.5" />
          <span>{isGenerating ? 'Generating Tasks...' : 'Sync Tasks from Findings'}</span>
        </button>
      </div>

      {/* Status Filter Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-white p-3 rounded-2xl border border-[#E5EAF2]">
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
          {['All', 'Open', 'In Progress', 'Awaiting Verification', 'Resolved'].map((st) => (
            <button
              key={st}
              onClick={() => setFilterStatus(st)}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-colors ${
                filterStatus === st 
                  ? 'bg-blue-600 text-white shadow-xs' 
                  : 'text-gray-600 hover:bg-gray-100'
              }`}
            >
              {st}
            </button>
          ))}
        </div>

        <span className="text-xs text-gray-500 font-medium">
          Showing {filteredTasks.length} of {tasks.length} tasks
        </span>
      </div>

      {/* Two Column Layout: Task List + Active Task Details Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Task Cards Column */}
        <div className="lg:col-span-7 space-y-3">
          {filteredTasks.length === 0 ? (
            <div className="p-12 text-center bg-white border border-[#E5EAF2] rounded-2xl space-y-2">
              <CheckCircle2 className="w-8 h-8 text-teal-600 mx-auto" />
              <h3 className="font-bold text-sm text-[#172033]">No tasks in this category</h3>
              <p className="text-xs text-gray-500">
                {filterStatus === 'All' 
                  ? 'All tasks have been addressed or none are registered in this workspace.'
                  : `No tasks currently have the status "${filterStatus}".`}
              </p>
            </div>
          ) : (
            filteredTasks.map((task) => {
              const isSelected = activeTask?.id === task.id;
              return (
                <div
                  key={task.id}
                  onClick={() => setSelectedTaskId(task.id)}
                  className={`p-4 rounded-2xl border transition-all cursor-pointer ${
                    isSelected 
                      ? 'bg-white border-blue-500 ring-2 ring-blue-500/10 shadow-xs' 
                      : 'bg-white border-[#E5EAF2] hover:border-slate-300'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="space-y-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-slate-100 text-slate-700">
                          {task.category}
                        </span>
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${getStatusBadge(task.status)}`}>
                          {task.status}
                        </span>
                        {getVerificationBadge(task)}
                        {task.isDemo ? (
                          <span className="text-[9px] font-bold px-2 py-0.5 rounded-full bg-purple-50 text-purple-700 border border-purple-200">
                            Demo
                          </span>
                        ) : (
                          <span className="text-[9px] font-bold px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-800 border border-emerald-200">
                            Live
                          </span>
                        )}
                      </div>
                      <h3 className="font-bold text-sm text-[#172033] leading-snug">
                        {task.title}
                      </h3>
                      <p className="text-xs text-[#667085] line-clamp-1">
                        {task.description}
                      </p>
                    </div>

                    <span className="text-[11px] font-semibold text-gray-500 shrink-0">
                      {task.effort} Effort
                    </span>
                  </div>

                  <div className="mt-3 pt-3 border-t border-[#F1F5F9] flex flex-wrap items-center justify-between text-xs text-[#667085] gap-2">
                    <span>Target: <strong className="text-slate-700">{task.target}</strong></span>
                    <div className="flex items-center gap-3">
                      {task.assignee && (
                        <span>Assigned: <strong className="text-blue-600">{task.assignee}</strong></span>
                      )}
                      <span>Due: <strong className="text-slate-700">{task.dueDate}</strong></span>
                    </div>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Task Detail Panel */}
        <div className="lg:col-span-5 bg-white border border-[#E5EAF2] rounded-2xl p-5 shadow-xs h-fit space-y-4">
          {activeTask ? (
            <>
              <div>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full border ${getStatusBadge(activeTask.status)}`}>
                    Status: {activeTask.status}
                  </span>
                  {getVerificationBadge(activeTask)}
                </div>
                <h3 className="text-base font-bold text-[#172033] mt-2 leading-snug">
                  {activeTask.title}
                </h3>
                <p className="text-xs text-[#667085] mt-1">
                  {activeTask.description}
                </p>
              </div>

              {/* Task Metadata */}
              <div className="space-y-2 p-3.5 bg-[#F8FAFC] rounded-xl border border-[#E5EAF2] text-xs">
                <div className="flex justify-between">
                  <span className="text-gray-500">Effort Required:</span>
                  <span className="font-bold text-[#172033]">{activeTask.effort}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Affected Asset:</span>
                  <span className="font-bold text-[#172033]">{activeTask.target}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Risk Priority:</span>
                  <span className="font-bold text-red-600">{activeTask.priority}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Due Date:</span>
                  <span className="font-semibold text-slate-700">{activeTask.dueDate}</span>
                </div>
                {activeTask.completedAt && (
                  <div className="flex justify-between">
                    <span className="text-gray-500">Resolved Date:</span>
                    <span className="font-semibold text-emerald-700">
                      {new Date(activeTask.completedAt).toLocaleDateString()}
                    </span>
                  </div>
                )}
                {activeTask.assignee && (
                  <div className="flex justify-between">
                    <span className="text-gray-500">Current Assignee:</span>
                    <span className="font-semibold text-blue-700">{activeTask.assignee}</span>
                  </div>
                )}
              </div>

              {/* Verification Feedback Notice if present */}
              {verificationFeedback && verificationFeedback.id === activeTask.id && (
                <div className={`p-3 rounded-xl border text-xs leading-relaxed ${
                  verificationFeedback.success 
                    ? 'bg-emerald-50 border-emerald-200 text-emerald-800' 
                    : 'bg-amber-50 border-amber-200 text-amber-800'
                }`}>
                  <strong>{verificationFeedback.success ? 'Verification Confirmed:' : 'Verification Advisory:'}</strong>{' '}
                  {verificationFeedback.msg}
                </div>
              )}

              {/* Optional Assignee Control */}
              <div className="space-y-1.5 pt-1">
                <label className="text-xs font-bold text-[#172033] flex items-center gap-1.5">
                  <User className="w-3.5 h-3.5 text-slate-500" />
                  <span>Assign Task to Owner/Analyst:</span>
                </label>
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    value={assigneeInput}
                    onChange={(e) => setAssigneeInput(e.target.value)}
                    placeholder={activeTask.assignee || 'e.g. akash.sharma@example.com'}
                    className="flex-1 px-3 py-1.5 bg-slate-50 border border-slate-200 rounded-lg text-xs text-[#172033] focus:outline-none focus:ring-1 focus:ring-blue-500"
                  />
                  <button
                    onClick={() => handleSaveAssignee(activeTask.id)}
                    className="px-3 py-1.5 bg-slate-800 hover:bg-slate-900 text-white rounded-lg text-xs font-semibold shrink-0"
                  >
                    Save
                  </button>
                </div>
              </div>

              {/* Status Update Control */}
              <div className="pt-2 border-t border-[#E5EAF2] space-y-2">
                <label className="text-xs font-bold text-[#172033] block">
                  Change Task Status:
                </label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    onClick={() => onUpdateStatus(activeTask.id, 'Open')}
                    className={`px-3 py-2 rounded-lg text-xs font-bold transition-colors ${
                      activeTask.status === 'Open' ? 'bg-amber-100 text-amber-900 border border-amber-300' : 'bg-gray-100 hover:bg-gray-200 text-gray-700'
                    }`}
                  >
                    Open
                  </button>
                  <button
                    onClick={() => onUpdateStatus(activeTask.id, 'In Progress')}
                    className={`px-3 py-2 rounded-lg text-xs font-bold transition-colors ${
                      activeTask.status === 'In Progress' ? 'bg-blue-100 text-blue-900 border border-blue-300' : 'bg-blue-50 hover:bg-blue-100 text-blue-700'
                    }`}
                  >
                    In Progress
                  </button>
                  <button
                    onClick={() => onUpdateStatus(activeTask.id, 'Awaiting Verification')}
                    className={`px-3 py-2 rounded-lg text-xs font-bold transition-colors ${
                      activeTask.status === 'Awaiting Verification' ? 'bg-purple-100 text-purple-900 border border-purple-300' : 'bg-purple-50 hover:bg-purple-100 text-purple-700'
                    }`}
                  >
                    Awaiting Verify
                  </button>
                  <button
                    onClick={() => onUpdateStatus(activeTask.id, 'Resolved')}
                    className="px-3 py-2 bg-emerald-600 hover:bg-emerald-700 text-white font-bold rounded-lg text-xs transition-colors shadow-2xs"
                  >
                    Mark Resolved (User)
                  </button>
                </div>
              </div>

              {/* Rerun Safe Verification & Ask Copilot Actions */}
              <div className="pt-2 border-t border-[#E5EAF2] space-y-2">
                <button
                  onClick={() => handleRerunVerification(activeTask.id)}
                  disabled={isVerifying}
                  className="w-full py-2 bg-blue-50 hover:bg-blue-100 border border-blue-200 text-blue-800 font-bold rounded-xl text-xs flex items-center justify-center gap-1.5 transition-colors disabled:opacity-50"
                >
                  <RotateCcw className={`w-3.5 h-3.5 ${isVerifying ? 'animate-spin' : ''}`} />
                  <span>{isVerifying ? 'Executing Safe Re-Probe...' : 'Rerun Safe Passive Verification'}</span>
                </button>

                {onAskCopilot && (
                  <button
                    onClick={() => onAskCopilot(activeTask)}
                    className="w-full py-2 bg-purple-50 hover:bg-purple-100 border border-purple-200 text-purple-800 font-bold rounded-xl text-xs flex items-center justify-center gap-1.5 transition-colors"
                  >
                    <Sparkles className="w-3.5 h-3.5" />
                    <span>Ask Security Copilot How to Fix</span>
                  </button>
                )}
              </div>
            </>
          ) : (
            <div className="text-center py-12 text-xs text-gray-400">
              Select a task to review remediation instructions and independent verification status.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
