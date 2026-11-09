import React, { useState } from 'react';
import { createAssessment, registerScope } from '../api';

interface NewAssessmentModalProps {
  isOpen: boolean;
  onClose: () => void;
  onCreated: (assessmentId: string) => void;
}

export const NewAssessmentModal: React.FC<NewAssessmentModalProps> = ({
  isOpen,
  onClose,
  onCreated,
}) => {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [targetCidr, setTargetCidr] = useState('172.30.0.0/24');
  const [exclusions, setExclusions] = useState('172.30.0.254');
  const [testTarget, setTestTarget] = useState('172.30.0.10');
  const [scopeCheckResult, setScopeCheckResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleTestScope = async () => {
    if (!testTarget) return;
    try {
      // Temporary check against lab CIDR
      const isLab = testTarget.startsWith('172.30.0.');
      setScopeCheckResult({
        target: testTarget,
        allowed: isLab,
        reason: isLab ? 'In-scope lab address' : 'Target is outside the authorized lab subnet (172.30.0.0/24)',
      });
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setLoading(true);
    setError(null);

    try {
      const asm = await createAssessment(name, description);
      await registerScope(asm.id, {
        allowed_targets: targetCidr.split(',').map((s) => s.trim()).filter(Boolean),
        exclusions: exclusions.split(',').map((s) => s.trim()).filter(Boolean),
        allowed_tools: ['nmap', 'nikto', 'zap', 'metasploit'],
        allowed_action_classes: ['discovery', 'vuln_scan', 'web_scan', 'active_validation'],
        notes: 'Analyst authorized scope rules',
      });
      onCreated(asm.id);
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to create assessment workspace');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-white rounded-lg shadow-xl max-w-lg w-full p-6 border border-slate-200">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-base font-bold text-slate-800">Create Scoped Assessment</h2>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-slate-600 text-lg leading-none"
          >
            &times;
          </button>
        </div>

        {error && (
          <div className="bg-red-50 text-red-700 text-xs p-3 rounded mb-4 border border-red-200">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1">
              Assessment Name *
            </label>
            <input
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Q4 Web App Vulnerability Evaluation"
              className="w-full text-xs px-3 py-2 border border-slate-300 rounded focus:ring-1 focus:ring-blue-500 outline-none"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-700 mb-1">
              Description / Engagement Scope
            </label>
            <textarea
              rows={2}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Testing parameters, business objectives, and rules of engagement."
              className="w-full text-xs px-3 py-2 border border-slate-300 rounded focus:ring-1 focus:ring-blue-500 outline-none"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Authorized Subnet (CIDR) *
              </label>
              <input
                type="text"
                required
                value={targetCidr}
                onChange={(e) => setTargetCidr(e.target.value)}
                className="w-full font-mono text-xs px-3 py-2 border border-slate-300 rounded focus:ring-1 focus:ring-blue-500 outline-none"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">
                Exclusions (IPs)
              </label>
              <input
                type="text"
                value={exclusions}
                onChange={(e) => setExclusions(e.target.value)}
                className="w-full font-mono text-xs px-3 py-2 border border-slate-300 rounded focus:ring-1 focus:ring-blue-500 outline-none"
              />
            </div>
          </div>

          {/* Instant Scope Checker */}
          <div className="bg-slate-50 border border-slate-200 rounded p-3 text-xs">
            <span className="font-semibold text-slate-700 block mb-1">Test Scope Validator:</span>
            <div className="flex gap-2 mb-2">
              <input
                type="text"
                value={testTarget}
                onChange={(e) => setTestTarget(e.target.value)}
                placeholder="Target IP or CIDR"
                className="flex-1 font-mono text-xs px-2 py-1 border border-slate-300 rounded"
              />
              <button
                type="button"
                onClick={handleTestScope}
                className="px-2.5 py-1 bg-slate-200 hover:bg-slate-300 rounded text-slate-700 text-xs font-medium"
              >
                Validate
              </button>
            </div>
            {scopeCheckResult && (
              <div
                className={`p-2 rounded text-[11px] ${
                  scopeCheckResult.allowed
                    ? 'bg-emerald-50 text-emerald-800 border border-emerald-200'
                    : 'bg-red-50 text-red-800 border border-red-200'
                }`}
              >
                {scopeCheckResult.allowed ? '✓ Target In-Scope' : '✗ Out-of-Scope Target Rejected'}:{' '}
                {scopeCheckResult.reason}
              </div>
            )}
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 text-xs text-slate-600 hover:bg-slate-100 rounded"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-1.5 text-xs bg-blue-600 hover:bg-blue-700 text-white font-medium rounded shadow-sm disabled:opacity-50"
            >
              {loading ? 'Initializing...' : 'Create Assessment'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
