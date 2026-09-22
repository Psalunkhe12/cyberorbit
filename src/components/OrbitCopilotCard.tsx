import React, { useState, useRef, useEffect } from 'react';
import { ChatMessage } from '../types';
import { Sparkles, Send, Loader2, Bot, HelpCircle } from 'lucide-react';

interface OrbitCopilotCardProps {
  messages: ChatMessage[];
  onSendMessage: (text: string) => void;
  isLoading: boolean;
}

export const OrbitCopilotCard: React.FC<OrbitCopilotCardProps> = ({
  messages,
  onSendMessage,
  isLoading,
}) => {
  const [inputText, setInputText] = useState('');
  const chatLogRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (chatLogRef.current) {
      chatLogRef.current.scrollTop = chatLogRef.current.scrollHeight;
    }
  }, [messages, isLoading]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputText.trim() || isLoading) return;
    onSendMessage(inputText.trim());
    setInputText('');
  };

  const quickPrompts = [
    'What is the priority item?',
    'Analyze gateway-01 SYN anomaly',
    'Generate WAF rule for HTTP Flood',
  ];

  return (
    <div className="bg-white rounded-[32px] p-6 border border-[#d4deda] shadow-sm flex flex-col justify-between h-full min-h-[360px]">
      <div>
        <div className="flex justify-between items-center mb-4">
          <div>
            <div className="font-display text-base font-extrabold text-[#253835] flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-[#d49b28]" />
              <span>Orbit AI Copilot</span>
            </div>
            <div className="text-xs text-[#6c8582] mt-0.5">
              Security Assistant & Telemetry Correlator
            </div>
          </div>
          <span className="text-[11px] font-bold px-3 py-1 rounded-full bg-[#dce3e0] text-[#253835] flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#2d9d78]" />
            <span>ONLINE</span>
          </span>
        </div>

        {/* Chat Logs */}
        <div
          ref={chatLogRef}
          id="chatlog"
          className="flex flex-col gap-2.5 max-h-[220px] overflow-y-auto mb-3.5 pr-1"
        >
          {messages.map((msg) => (
            <div
              key={msg.id}
              className={`p-3 rounded-2xl text-[12.5px] leading-relaxed max-w-[90%] ${
                msg.sender === 'user'
                  ? 'bg-[#334d4a] text-white self-end rounded-br-none'
                  : 'bg-[#f0f5f3] text-[#253835] border border-[#d4deda] self-start rounded-bl-none'
              }`}
            >
              <small
                className={`block text-[10px] font-bold mb-1 ${
                  msg.sender === 'user' ? 'text-white/60' : 'text-[#6c8582]'
                }`}
              >
                {msg.sender === 'user' ? 'YOU' : 'ORBIT AI'}
              </small>
              <span>{msg.text}</span>
            </div>
          ))}

          {isLoading && (
            <div className="bg-[#f0f5f3] text-[#253835] border border-[#d4deda] p-3 rounded-2xl rounded-bl-none self-start text-[12.5px] flex items-center gap-2">
              <Loader2 className="w-3.5 h-3.5 text-[#d49b28] animate-spin" />
              <span className="text-xs font-semibold text-[#6c8582]">
                Correlating telemetry logs with Gemini...
              </span>
            </div>
          )}
        </div>
      </div>

      <div>
        {/* Quick Prompts */}
        <div className="flex gap-1.5 overflow-x-auto pb-2 mb-2 no-scrollbar">
          {quickPrompts.map((prompt, idx) => (
            <button
              key={idx}
              onClick={() => onSendMessage(prompt)}
              className="bg-[#f0f5f3] hover:bg-[#dce3e0] text-[#334d4a] text-[11px] font-bold px-3 py-1 rounded-full whitespace-nowrap border border-[#d4deda] cursor-pointer transition-colors shrink-0"
            >
              {prompt}
            </button>
          ))}
        </div>

        {/* Form Input */}
        <form id="chatForm" onSubmit={handleSubmit} className="flex gap-2">
          <input
            id="chatInput"
            type="text"
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
            placeholder="Ask Orbit a question..."
            className="flex-1 border border-[#d4deda] bg-[#e3e9e6]/40 px-4 py-2.5 rounded-full text-[12.5px] outline-none text-[#253835] placeholder-[#9cb1ae] focus:border-[#d49b28]"
          />
          <button
            type="submit"
            disabled={isLoading || !inputText.trim()}
            className="bg-[#d49b28] hover:bg-[#b8821a] text-white border-none py-2.5 px-5 rounded-full font-bold text-xs cursor-pointer transition-colors disabled:opacity-50 flex items-center justify-center"
          >
            <Send className="w-3.5 h-3.5" />
          </button>
        </form>
      </div>
    </div>
  );
};
