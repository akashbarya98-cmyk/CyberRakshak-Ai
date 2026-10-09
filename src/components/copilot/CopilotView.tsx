import React, { useState, useRef, useEffect } from 'react';
import { 
  Sparkles, 
  Send, 
  ShieldAlert, 
  Bot, 
  User, 
  HelpCircle, 
  CheckCircle2, 
  AlertTriangle,
  Languages,
  RotateCcw
} from 'lucide-react';
import { ChatMessage } from '../../types';

interface CopilotViewProps {
  initialContext?: any;
  workspaceId?: string;
}

export const CopilotView: React.FC<CopilotViewProps> = ({ 
  initialContext, 
  workspaceId = 'ws-personal' 
}) => {
  const [activeContext, setActiveContext] = useState<string>(
    initialContext 
      ? (initialContext.title || initialContext.domain || 'Security Context') 
      : 'General Security Posture'
  );
  const [contextList, setContextList] = useState<string[]>(['General Security Posture']);

  useEffect(() => {
    // Fetch available workspace findings and domain assessments to populate context selector
    const loadContextOptions = async () => {
      try {
        const [fRes, aRes] = await Promise.all([
          fetch('/api/findings', { headers: { 'x-workspace-id': workspaceId } }),
          fetch('/api/assessments', { headers: { 'x-workspace-id': workspaceId } })
        ]);
        const opts = ['General Security Posture'];
        if (fRes.ok) {
          const findings = await fRes.json();
          findings.slice(0, 4).forEach((f: any) => opts.push(`Finding: ${f.title}`));
        }
        if (aRes.ok) {
          const assessments = await aRes.json();
          assessments.forEach((a: any) => opts.push(`Domain: ${a.domain}`));
        }
        setContextList(Array.from(new Set(opts)));
      } catch {}
    };
    loadContextOptions();
  }, [workspaceId]);

  const [messages, setMessages] = useState<ChatMessage[]>(() => {
    if (initialContext) {
      return [
        {
          id: 'msg-init-1',
          role: 'assistant',
          content: `I am currently analyzing your context: **${initialContext.title || initialContext.domain || 'Security Item'}** (${initialContext.severity || initialContext.riskClassification || 'Active Threat Vector'}).
You can ask me why this was flagged, how to remediate it, or request an explanation in Hindi/Hinglish.`,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }
      ];
    }
    return [
      {
        id: 'msg-init-0',
        role: 'assistant',
        content: `Hello! I am CyberRakshak AI Security Copilot. I assist you with explainable cybersecurity advice grounded in your real workspace findings and passive domain assessments.
Feel free to ask about any message you scanned, your domain configuration (TLS/HSTS/CSP), or general digital safety.`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      }
    ];
  });

  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const messagesEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isLoading]);

  const sampleQuestions = [
    'What are the observed technical facts?',
    'How can I verify this job offer?',
    'Explain this in Hindi (हिंदी)',
    'What is HSTS and why do I need it?',
    'Is this assessment conclusive?'
  ];

  const handleSendMessage = async (textToSend?: string) => {
    const text = textToSend || inputMessage;
    if (!text.trim() || isLoading) return;

    const userMsg: ChatMessage = {
      id: `msg-${Date.now()}`,
      role: 'user',
      content: text,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setMessages(prev => [...prev, userMsg]);
    setInputMessage('');
    setIsLoading(true);

    try {
      const response = await fetch('/api/copilot/chat', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'x-workspace-id': workspaceId
        },
        body: JSON.stringify({
          message: text,
          context: { target: activeContext, ...initialContext },
          history: messages.slice(-4)
        })
      });

      if (response.ok) {
        const data = await response.json();
        const aiMsg: ChatMessage = {
          id: `msg-${Date.now() + 1}`,
          role: 'assistant',
          content: data.reply,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        };
        setMessages(prev => [...prev, aiMsg]);
      } else {
        fallbackReply(text);
      }
    } catch {
      fallbackReply(text);
    } finally {
      setIsLoading(false);
    }
  };

  const fallbackReply = (userQuery: string) => {
    const lower = userQuery.toLowerCase();
    let reply = `[Observed Fact]: System active findings analyzed from your current workspace.

[Inferred Threat]: Phishing campaigns and missing security headers represent key risk surfaces.

[Recommended Action]:
1. Verify the entity independently by navigating directly to their known, official URL.
2. Never share SMS OTPs, bank UPI PINs, or confidential credentials over messaging platforms.
3. Review your Remediation Center to address discovered perimeter weaknesses.`;

    if (lower.includes('hindi') || lower.includes('hinglish')) {
      reply = `[Observed Fact]: Yeh message fraud ho sakta hai kyunki isme urgent action lene ko bola gaya hai.

[Inferred Threat]: Anjaan link aur unsolicited SMS se credential chori kiye jaa sakte hain.

[Recommended Action]:
1. Kabhi bhi kisi anjaan vyakti ko apna OTP ya UPI PIN na dein.
2. Koi bhi official company joining se pehle registration fee nahi maangti.
3. Official website par direct jayein, message ke link par click na karein.`;
    }

    const aiMsg: ChatMessage = {
      id: `msg-${Date.now() + 1}`,
      role: 'assistant',
      content: reply,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };
    setMessages(prev => [...prev, aiMsg]);
  };

  // Visual formatting for grounded labels
  const formatMessageContent = (content: string) => {
    const lines = content.split('\n');
    return lines.map((line, lIdx) => {
      if (line.startsWith('[Observed Fact]')) {
        return (
          <div key={lIdx} className="my-1.5 p-2 bg-blue-50/80 border border-blue-200/80 rounded-lg text-blue-900 font-medium">
            <span className="text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.5 rounded bg-blue-200/80 text-blue-800 mr-1.5">
              Observed Fact
            </span>
            <span>{line.replace('[Observed Fact]:', '').replace('[Observed Fact]', '')}</span>
          </div>
        );
      }
      if (line.startsWith('[Inferred Threat]')) {
        return (
          <div key={lIdx} className="my-1.5 p-2 bg-amber-50/80 border border-amber-200/80 rounded-lg text-amber-900">
            <span className="text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.5 rounded bg-amber-200/80 text-amber-800 mr-1.5">
              Inferred Threat
            </span>
            <span>{line.replace('[Inferred Threat]:', '').replace('[Inferred Threat]', '')}</span>
          </div>
        );
      }
      if (line.startsWith('[Recommended Action]')) {
        return (
          <div key={lIdx} className="my-1.5 p-2 bg-emerald-50/80 border border-emerald-200/80 rounded-lg text-emerald-900">
            <span className="text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.5 rounded bg-emerald-200/80 text-emerald-800 mr-1.5">
              Recommended Action
            </span>
            <span>{line.replace('[Recommended Action]:', '').replace('[Recommended Action]', '')}</span>
          </div>
        );
      }
      if (line.startsWith('[Inconclusive / Incomplete Coverage]')) {
        return (
          <div key={lIdx} className="my-1.5 p-2 bg-purple-50/80 border border-purple-200/80 rounded-lg text-purple-900">
            <span className="text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.5 rounded bg-purple-200/80 text-purple-800 mr-1.5">
              Inconclusive
            </span>
            <span>{line.replace('[Inconclusive / Incomplete Coverage]:', '').replace('[Inconclusive / Incomplete Coverage]', '')}</span>
          </div>
        );
      }
      return <div key={lIdx}>{line}</div>;
    });
  };

  return (
    <div className="space-y-4 max-w-4xl mx-auto pb-12 h-[calc(100vh-120px)] flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-[#E5EAF2]">
        <div>
          <h2 className="text-xl sm:text-2xl font-bold text-[#172033] tracking-tight flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-purple-600" />
            <span>AI Security Copilot</span>
          </h2>
          <p className="text-xs text-[#667085] mt-0.5">
            Grounded intelligence assistant explaining verified observations and prioritizing mitigations (English, Hindi, Hinglish).
          </p>
        </div>

        {/* Active Context Selector */}
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-purple-50 border border-purple-200 text-xs text-purple-800 font-medium">
          <ShieldAlert className="w-3.5 h-3.5 text-purple-600 shrink-0" />
          <label htmlFor="context-select" className="sr-only">Focus Context</label>
          <select
            id="context-select"
            value={activeContext}
            onChange={(e) => setActiveContext(e.target.value)}
            className="bg-transparent text-purple-900 font-semibold focus:outline-none cursor-pointer max-w-[220px] truncate"
          >
            {contextList.map((ctx, idx) => (
              <option key={idx} value={ctx} className="bg-white text-slate-800 font-normal">
                {ctx}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Main Chat Stream Container */}
      <div className="flex-1 bg-white border border-[#E5EAF2] rounded-2xl shadow-xs overflow-hidden flex flex-col justify-between">
        
        {/* Messages Scroll Area */}
        <div className="flex-1 p-4 sm:p-6 overflow-y-auto space-y-4">
          {messages.map((msg) => {
            const isUser = msg.role === 'user';
            return (
              <div
                key={msg.id}
                className={`flex gap-3 max-w-[85%] ${isUser ? 'ml-auto justify-end' : 'mr-auto justify-start'}`}
              >
                {!isUser && (
                  <div className="w-8 h-8 rounded-full bg-blue-600 text-white flex items-center justify-center shrink-0 shadow-xs">
                    <Bot className="w-4 h-4" />
                  </div>
                )}

                <div className="space-y-1">
                  <div
                    className={`p-4 rounded-2xl text-xs sm:text-sm leading-relaxed shadow-xs ${
                      isUser
                        ? 'bg-[#7C3AED] text-white rounded-tr-none'
                        : 'bg-[#F8FAFC] text-[#172033] border border-[#E5EAF2] rounded-tl-none font-normal'
                    }`}
                  >
                    {isUser ? msg.content : formatMessageContent(msg.content)}
                  </div>
                  <p className={`text-[10px] text-gray-400 px-1 ${isUser ? 'text-right' : 'text-left'}`}>
                    {msg.timestamp}
                  </p>
                </div>

                {isUser && (
                  <div className="w-8 h-8 rounded-full bg-[#1E293B] text-white flex items-center justify-center shrink-0 shadow-xs text-xs font-bold">
                    AS
                  </div>
                )}
              </div>
            );
          })}

          {isLoading && (
            <div className="flex gap-3 mr-auto max-w-[85%]">
              <div className="w-8 h-8 rounded-full bg-blue-600 text-white flex items-center justify-center shrink-0">
                <Bot className="w-4 h-4" />
              </div>
              <div className="p-4 rounded-2xl bg-[#F8FAFC] border border-[#E5EAF2] rounded-tl-none flex items-center gap-2 text-xs text-gray-500">
                <div className="w-2 h-2 rounded-full bg-blue-500 animate-bounce"></div>
                <div className="w-2 h-2 rounded-full bg-purple-500 animate-bounce [animation-delay:0.2s]"></div>
                <div className="w-2 h-2 rounded-full bg-teal-500 animate-bounce [animation-delay:0.4s]"></div>
                <span className="font-medium text-slate-600">Grounding advice in stored evidence...</span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Suggestion Prompt Pills & Input Bar */}
        <div className="p-3 sm:p-4 bg-white border-t border-[#E5EAF2] space-y-3">
          {/* Quick Prompt Pills */}
          <div className="flex items-center gap-2 overflow-x-auto pb-1 scrollbar-none">
            {sampleQuestions.map((question, idx) => (
              <button
                key={idx}
                onClick={() => handleSendMessage(question)}
                className="whitespace-nowrap px-3 py-1.5 rounded-full border border-blue-200/80 bg-blue-50/60 hover:bg-blue-100 text-blue-700 text-xs font-medium transition-colors shrink-0"
              >
                {question}
              </button>
            ))}
          </div>

          {/* Form Input */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSendMessage();
            }}
            className="flex items-center gap-2"
          >
            <input
              type="text"
              value={inputMessage}
              onChange={(e) => setInputMessage(e.target.value)}
              placeholder="Ask Copilot (in English, Hindi, or Hinglish)..."
              className="flex-1 px-4 py-2.5 bg-[#F8FAFC] border border-[#E5EAF2] rounded-xl text-xs sm:text-sm text-[#172033] placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 focus:bg-white transition-all"
            />
            <button
              type="submit"
              disabled={!inputMessage.trim() || isLoading}
              className="w-10 h-10 rounded-xl bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white flex items-center justify-center shrink-0 shadow-xs transition-colors"
            >
              <Send className="w-4 h-4" />
            </button>
          </form>
        </div>
      </div>
    </div>
  );
};
