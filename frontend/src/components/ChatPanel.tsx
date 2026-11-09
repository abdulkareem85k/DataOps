import React, { useState } from 'react';
import { sendAgentChat } from '../api';
import { ChatMessage } from '../types';

interface ChatPanelProps {
  assessmentId: string;
  onPlanProposed?: (planSteps: any[]) => void;
}

export const ChatPanel: React.FC<ChatPanelProps> = ({ assessmentId, onPlanProposed }) => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'msg-welcome',
      role: 'assistant',
      content:
        'Hello Analyst. I am the AI VAPT Orchestrator. What targets would you like to evaluate in the authorized lab scope?',
      timestamp: 'Ready',
    },
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);

  const quickPrompts = [
    'Discover active hosts and open ports',
    'Assess web application vulnerabilities',
    'Propose comprehensive testing plan',
  ];

  const handleSend = async (textToSend?: string) => {
    const text = textToSend || input;
    if (!text.trim() || !assessmentId) return;

    const userMsg: ChatMessage = {
      id: `msg-${Date.now()}`,
      role: 'user',
      content: text,
      timestamp: new Date().toLocaleTimeString(),
    };
    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setLoading(true);

    try {
      const res = await sendAgentChat(assessmentId, text);
      const assistantMsg: ChatMessage = {
        id: `msg-${Date.now()}-ai`,
        role: 'assistant',
        content: res.text,
        tool_calls: res.tool_calls,
        timestamp: new Date().toLocaleTimeString(),
      };
      setMessages((prev) => [...prev, assistantMsg]);

      if (res.tool_calls && onPlanProposed) {
        for (const call of res.tool_calls) {
          if (call.name === 'propose_plan' && call.arguments?.steps) {
            onPlanProposed(call.arguments.steps);
          }
        }
      }
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        {
          id: `msg-${Date.now()}-err`,
          role: 'system',
          content: `Error: ${err.message || 'Agent request failed'}`,
          timestamp: new Date().toLocaleTimeString(),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-full bg-white border-r border-slate-200">
      <div className="p-3 border-b border-slate-200 flex justify-between items-center bg-slate-50">
        <span className="font-bold text-xs uppercase tracking-wider text-slate-700">
          Agent Reasoning Console
        </span>
        <span className="text-[10px] font-mono text-emerald-600 font-semibold bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
          ● LLM CONNECTED
        </span>
      </div>

      {/* Message List */}
      <div className="flex-1 overflow-y-auto p-3 space-y-3">
        {messages.map((m) => (
          <div
            key={m.id}
            className={`flex flex-col ${
              m.role === 'user' ? 'items-end' : 'items-start'
            }`}
          >
            <div
              className={`max-w-[85%] rounded p-2.5 text-xs ${
                m.role === 'user'
                  ? 'bg-blue-600 text-white shadow-sm'
                  : m.role === 'system'
                  ? 'bg-red-50 text-red-700 border border-red-200'
                  : 'bg-slate-100 text-slate-800 border border-slate-200'
              }`}
            >
              <p className="whitespace-pre-wrap leading-relaxed">{m.content}</p>

              {m.tool_calls && m.tool_calls.length > 0 && (
                <div className="mt-2 pt-2 border-t border-slate-200/50">
                  <span className="text-[10px] font-mono font-bold text-slate-500 uppercase block mb-1">
                    Agent Action Executed:
                  </span>
                  {m.tool_calls.map((t, idx) => (
                    <span
                      key={idx}
                      className="inline-block bg-slate-200 text-slate-800 font-mono text-[9px] px-1.5 py-0.5 rounded mr-1"
                    >
                      {t.name}
                    </span>
                  ))}
                </div>
              )}
            </div>
            <span className="text-[9px] text-slate-400 mt-1 px-1 font-mono">
              {m.timestamp}
            </span>
          </div>
        ))}
        {loading && (
          <div className="text-slate-400 text-xs italic flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-blue-500 animate-ping" />
            Agent reasoning and evaluating scope...
          </div>
        )}
      </div>

      {/* Quick Prompts */}
      <div className="px-3 py-2 bg-slate-50 border-t border-slate-200 flex flex-wrap gap-1.5">
        {quickPrompts.map((p, idx) => (
          <button
            key={idx}
            type="button"
            onClick={() => handleSend(p)}
            className="text-[10px] bg-white border border-slate-300 hover:bg-slate-100 text-slate-700 px-2 py-1 rounded transition-colors"
          >
            {p}
          </button>
        ))}
      </div>

      {/* Input box */}
      <div className="p-3 border-t border-slate-200 bg-white">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          className="flex gap-2"
        >
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Instruct the agent (e.g. 'Scan 172.30.0.10 for open ports')..."
            className="flex-1 text-xs px-3 py-2 border border-slate-300 rounded focus:ring-1 focus:ring-blue-500 outline-none"
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="px-3 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs font-semibold rounded shadow-sm"
          >
            Send
          </button>
        </form>
      </div>
    </div>
  );
};
