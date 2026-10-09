import React, { useEffect } from 'react';
import { Bell, X, AlertTriangle, CheckCircle2, ShieldAlert, Clock, Inbox } from 'lucide-react';
import { NotificationItem } from '../../types';

interface NotificationModalProps {
  isOpen: boolean;
  notifications: NotificationItem[];
  onClose: () => void;
  onMarkAllRead: () => void;
}

export const NotificationModal: React.FC<NotificationModalProps> = ({
  isOpen,
  notifications,
  onClose,
  onMarkAllRead
}) => {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div 
      className="fixed inset-0 z-50 bg-slate-900/40 backdrop-blur-xs flex justify-end" 
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Security Notifications Drawer"
    >
      <div 
        className="w-full max-w-sm bg-white h-full shadow-2xl border-l border-[#E5EAF2] flex flex-col justify-between p-5"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-[#E5EAF2]">
            <div className="flex items-center gap-2">
              <Bell className="w-5 h-5 text-blue-600" />
              <h3 className="font-bold text-sm text-[#172033]">
                Notifications ({notifications.length})
              </h3>
            </div>
            <button 
              onClick={onClose} 
              aria-label="Close notification drawer"
              className="p-1 rounded-lg text-gray-400 hover:text-gray-700 hover:bg-gray-100"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          <div className="space-y-3 overflow-y-auto max-h-[calc(100vh-140px)]">
            {notifications.length === 0 ? (
              <div className="py-12 px-4 text-center space-y-2">
                <div className="w-10 h-10 rounded-full bg-slate-100 text-slate-400 flex items-center justify-center mx-auto">
                  <Inbox className="w-5 h-5" />
                </div>
                <p className="text-xs font-semibold text-slate-700">No unread notifications</p>
                <p className="text-[11px] text-slate-400">
                  New security alerts, scam analyses, and domain assessments will appear here.
                </p>
              </div>
            ) : (
              notifications.map((n) => (
                <div 
                  key={n.id} 
                  className="p-3.5 rounded-xl border border-[#E5EAF2] bg-[#F8FAFC] space-y-1 text-xs"
                >
                  <div className="flex items-center justify-between">
                    <span className={`font-bold ${n.type === 'danger' ? 'text-red-600' : n.type === 'warning' ? 'text-amber-600' : 'text-blue-600'}`}>
                      {n.title}
                    </span>
                    <span className="text-[10px] text-gray-400">{n.time}</span>
                  </div>
                  <p className="text-gray-600 text-[11px] leading-relaxed">
                    {n.detail}
                  </p>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="pt-3 border-t border-[#E5EAF2]">
          <button
            onClick={() => {
              onMarkAllRead();
              onClose();
            }}
            disabled={notifications.length === 0}
            className="w-full py-2 bg-gray-100 hover:bg-gray-200 disabled:opacity-50 text-gray-700 font-bold text-xs rounded-lg transition-colors"
          >
            Mark all as read
          </button>
        </div>
      </div>
    </div>
  );
};

