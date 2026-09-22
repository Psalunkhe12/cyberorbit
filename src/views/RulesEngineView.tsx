import React, { useState } from 'react';
import { SecurityRule } from '../types';
import { SlidersHorizontal, Plus, Power, Terminal, Play, CheckCircle2, Shield } from 'lucide-react';

interface RulesEngineViewProps {
  rules: SecurityRule[];
  onToggleRule: (id: string) => void;
  onAddRule: (rule: SecurityRule) => void;
}

export const RulesEngineView: React.FC<RulesEngineViewProps> = ({
  rules,
  onToggleRule,
  onAddRule,
}) => {
  const [testPayload, setTestPayload] = useState("GET /search?q=1' OR '1'='1 HTTP/1.1");
  const [testPattern, setTestPattern] = useState("(?i)(union\\s+select|select\\s+.*\\s+from|\\\'\\s*or\\s*\\\'1\\\'=\\\'1\\\')");
  const [testResult, setTestResult] = useState<{ matched: boolean; matchText?: string } | null>(null);

  // Add rule modal state
  const [isAddOpen, setIsAddOpen] = useState(false);
  const [newRuleName, setNewRuleName] = useState('');
  const [newRulePattern, setNewRulePattern] = useState('');
  const [newRuleAction, setNewRuleAction] = useState<SecurityRule['action']>('BLOCK');
  const [newRuleCategory, setNewRuleCategory] = useState('Application Layer');

  const handleTestRegex = () => {
    try {
      const regex = new RegExp(testPattern, 'i');
      const match = testPayload.match(regex);
      if (match) {
        setTestResult({ matched: true, matchText: match[0] });
      } else {
        setTestResult({ matched: false });
      }
    } catch {
      setTestResult({ matched: false, matchText: 'Invalid Regex Expression Syntax' });
    }
  };

  const handleCreateRule = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRuleName.trim() || !newRulePattern.trim()) return;

    const rule: SecurityRule = {
      id: `rule-${Date.now()}`,
      name: newRuleName.trim(),
      pattern: newRulePattern.trim(),
      action: newRuleAction,
      status: 'ACTIVE',
      matchesCount: 0,
      priority: rules.length + 1,
      category: newRuleCategory,
      lastTriggered: 'Just created',
    };

    onAddRule(rule);
    setIsAddOpen(false);
    setNewRuleName('');
    setNewRulePattern('');
  };

  return (
    <div className="flex flex-col gap-5">
      {/* Top Banner */}
      <div className="bg-white rounded-[32px] p-6 border border-[#d4deda] shadow-sm flex flex-wrap justify-between items-center gap-4">
        <div>
          <h2 className="font-display text-lg font-extrabold text-[#253835] flex items-center gap-2 m-0">
            <SlidersHorizontal className="w-5 h-5 text-[#d49b28]" />
            <span>WAF & Edge Rule Configuration Engine</span>
          </h2>
          <p className="text-xs text-[#6c8582] mt-0.5 m-0">
            Deploy dynamic pattern-matching filters, TCP flags, and bot-mitigation policies.
          </p>
        </div>

        <button
          onClick={() => setIsAddOpen(true)}
          className="bg-[#d49b28] hover:bg-[#b8821a] text-white px-5 py-2.5 rounded-full font-bold text-xs border-none cursor-pointer flex items-center gap-2 transition-colors shadow-md"
        >
          <Plus className="w-4 h-4" />
          <span>Deploy New Rule</span>
        </button>
      </div>

      {/* Regex Pattern Tester Console */}
      <div className="bg-[#334d4a] text-white rounded-[32px] p-6 border border-white/10 shadow-xl">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Terminal className="w-5 h-5 text-[#d49b28]" />
            <h3 className="font-display text-base font-bold text-white m-0">
              Interactive Rule Regex Tester
            </h3>
          </div>
          <span className="text-[10px] font-mono-code bg-white/10 text-[#d49b28] px-2.5 py-1 rounded">
            PCRE2 ENGINE ACTIVE
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
          <div>
            <label className="text-[11px] font-bold text-white/70 block mb-1">
              REGULAR EXPRESSION PATTERN
            </label>
            <input
              type="text"
              value={testPattern}
              onChange={(e) => setTestPattern(e.target.value)}
              className="w-full bg-white/10 border border-white/20 px-3.5 py-2 rounded-xl text-xs font-mono-code text-[#d49b28] outline-none"
            />
          </div>

          <div>
            <label className="text-[11px] font-bold text-white/70 block mb-1">
              TEST PACKET / HTTP PAYLOAD
            </label>
            <input
              type="text"
              value={testPayload}
              onChange={(e) => setTestPayload(e.target.value)}
              className="w-full bg-white/10 border border-white/20 px-3.5 py-2 rounded-xl text-xs font-mono-code text-white outline-none"
            />
          </div>
        </div>

        <div className="flex items-center justify-between">
          <button
            onClick={handleTestRegex}
            className="bg-[#d49b28] hover:bg-[#b8821a] text-white font-bold py-2 px-5 rounded-full text-xs border-none cursor-pointer flex items-center gap-1.5"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Test Pattern Match</span>
          </button>

          {testResult && (
            <div
              className={`text-xs font-bold px-4 py-1.5 rounded-full flex items-center gap-2 ${
                testResult.matched
                  ? 'bg-[#d94b4b] text-white'
                  : 'bg-[#2d9d78] text-white'
              }`}
            >
              <span>
                {testResult.matched
                  ? `MATCH DETECTED: "${testResult.matchText}"`
                  : 'NO MATCH - PAYLOAD CLEARED'}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Rules Table */}
      <div className="bg-white rounded-[32px] p-6 border border-[#d4deda] shadow-sm">
        <div className="font-display text-base font-extrabold text-[#253835] mb-4">
          Active Security Rules ({rules.length})
        </div>

        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-xs">
            <thead>
              <tr className="border-b border-[#d4deda]">
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                  RULE NAME
                </th>
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                  PATTERN / REGEX
                </th>
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                  ACTION
                </th>
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                  MATCHES
                </th>
                <th className="text-right py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                  STATUS
                </th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.id} className="border-b border-[#edf2f0] hover:bg-[#f0f5f3]">
                  <td className="py-3.5 px-3">
                    <b className="block text-[#253835] font-bold">{rule.name}</b>
                    <small className="text-[#6c8582] text-[10px] block">{rule.category}</small>
                  </td>
                  <td className="py-3.5 px-3 font-mono-code text-[11px] text-[#334d4a]">
                    {rule.pattern}
                  </td>
                  <td className="py-3.5 px-3 font-bold">
                    <span
                      className={`px-2.5 py-1 rounded-full text-[10px] ${
                        rule.action === 'BLOCK'
                          ? 'bg-[#fde8e8] text-[#d94b4b]'
                          : rule.action === 'RATE_LIMIT'
                          ? 'bg-[#fdf3e1] text-[#b8821a]'
                          : 'bg-[#e3f2fd] text-[#1976d2]'
                      }`}
                    >
                      {rule.action}
                    </span>
                  </td>
                  <td className="py-3.5 px-3 font-mono-code font-semibold text-[#253835]">
                    {rule.matchesCount.toLocaleString()}
                  </td>
                  <td className="py-3.5 px-3 text-right">
                    <button
                      onClick={() => onToggleRule(rule.id)}
                      className={`px-3 py-1 rounded-full text-[11px] font-bold border-none cursor-pointer flex items-center gap-1.5 ml-auto transition-all ${
                        rule.status === 'ACTIVE'
                          ? 'bg-[#2d9d78] text-white'
                          : 'bg-[#dce3e0] text-[#6c8582]'
                      }`}
                    >
                      <Power className="w-3 h-3" />
                      <span>{rule.status}</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Rule Modal */}
      {isAddOpen && (
        <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-xs grid place-items-center p-4">
          <form
            onSubmit={handleCreateRule}
            className="bg-white rounded-2xl max-w-lg w-full p-6 shadow-2xl border border-[#d4deda] relative"
          >
            <h3 className="font-display text-lg font-bold text-[#253835] mb-4">
              Deploy New WAF Security Rule
            </h3>

            <div className="flex flex-col gap-3 mb-5">
              <div>
                <label className="text-xs font-bold text-[#6c8582] block mb-1">
                  Rule Name
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Zero-Day Exploit Filter"
                  value={newRuleName}
                  onChange={(e) => setNewRuleName(e.target.value)}
                  className="w-full border border-[#d4deda] p-2.5 rounded-xl text-xs outline-none"
                />
              </div>

              <div>
                <label className="text-xs font-bold text-[#6c8582] block mb-1">
                  Regex Pattern
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. (?i)(eval\(|base64_decode)"
                  value={newRulePattern}
                  onChange={(e) => setNewRulePattern(e.target.value)}
                  className="w-full border border-[#d4deda] p-2.5 rounded-xl text-xs font-mono-code outline-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-bold text-[#6c8582] block mb-1">
                    Enforcement Action
                  </label>
                  <select
                    value={newRuleAction}
                    onChange={(e) => setNewRuleAction(e.target.value as any)}
                    className="w-full border border-[#d4deda] p-2.5 rounded-xl text-xs outline-none"
                  >
                    <option value="BLOCK">BLOCK</option>
                    <option value="RATE_LIMIT">RATE_LIMIT</option>
                    <option value="CHALLENGE">CHALLENGE</option>
                    <option value="LOG">LOG ONLY</option>
                  </select>
                </div>

                <div>
                  <label className="text-xs font-bold text-[#6c8582] block mb-1">
                    Category
                  </label>
                  <select
                    value={newRuleCategory}
                    onChange={(e) => setNewRuleCategory(e.target.value)}
                    className="w-full border border-[#d4deda] p-2.5 rounded-xl text-xs outline-none"
                  >
                    <option value="Application Layer">Application Layer</option>
                    <option value="Network Transport">Network Transport</option>
                    <option value="Bot Mitigation">Bot Mitigation</option>
                    <option value="Geofencing">Geofencing</option>
                  </select>
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-3">
              <button
                type="button"
                onClick={() => setIsAddOpen(false)}
                className="bg-[#dce3e0] text-[#253835] font-bold px-4 py-2 rounded-full text-xs border-none cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="bg-[#d49b28] hover:bg-[#b8821a] text-white font-bold px-5 py-2 rounded-full text-xs border-none cursor-pointer"
              >
                Deploy Rule
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
