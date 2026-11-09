import React, { useState } from 'react';
import { decideApproval } from '../api';
import { Approval } from '../types';

interface ApprovalQueueProps {
  approvals: Approval[];
  onRefresh: () => void;
}

export const ApprovalQueue: React.FC<ApprovalQueueProps> = ({ approvals, onRefresh }) => {
  const [selectedApproval, setSelectedApproval] = useState<Approval | null>(null);
  const [decision, setDecision] = useState<'approve' | 'reject'>('approve');
  const [reason, setReason] = useState('');
  const [approver, setApprover] = useState('lead_analyst');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tokenResult, setTokenResult] = useState<string | null>(null);

  const pending = approvals.filter((a) => a.status === 'pending');
  const decided = approvals.filter((a) => a.status !== 'pending');

  const handleDecisionSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedApproval || !reason.trim()) return;

    setSubmitting(true);
    setError(null);
    try {
      const res = await decideApproval(selectedApproval.id, decision, reason, approver);
      if (res.approval_token) {
        setTokenResult(res.approval_token);
      }
      setSelectedApproval(null);
      setReason('');
      onRefresh();
    } catch (err: any) {
      setError(err.message || 'Failed to submit approval decision');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      <div className="flex justify-between items-center border-b border-slate-200 pb-4">
        <div>
          <h1 className="text-xl font-bold text-slate-900">Human-in-the-Loop Approval Gate</h1>
          <p className="text-xs text-slate-500 mt-1">
            Offensive verification, check modules, and intrusive tests require explicit, recorded human approval.
          </p>
        </div>
        <button
          type="button"
          onClick={onRefresh}
          className="text-xs font-medium px-3 py-1.5 bg-slate-100 hover:bg-slate-200 rounded border border-slate-300"
        >
          Refresh Queue
        </button>
      </div>

      {tokenResult && (
        <div className="bg-emerald-50 border border-emerald-300 rounded p-4 text-xs text-emerald-900 space-y-1">
          <strong className="block font-bold">✓ Single-Use Approval Token Issued:</strong>
          <code className="font-mono bg-white p-2 block rounded border border-emerald-200 break-all select-all">
            {tokenResult}
          </code>
          <p className="text-[11px] text-emerald-700">
            Valid for 15 minutes. Any alteration to tool or target immediately invalidates this token.
          </p>
        </div>
      )}

      {/* Pending Approvals Section */}
      <section className="space-y-3">
        <h2 className="text-xs font-bold text-slate-800 uppercase tracking-wider flex items-center gap-2">
          <span>Pending Authorization Requests ({pending.length})</span>
          {pending.length > 0 && (
            <span className="w-2 h-2 rounded-full bg-amber-500 animate-ping" />
          )}
        </h2>

        {pending.length === 0 ? (
          <div className="bg-white border border-slate-200 rounded p-6 text-center text-slate-400 text-xs">
            No active validation requests pending approval.
          </div>
        ) : (
          pending.map((appr) => {
            const detail = appr.action_detail || {};
            return (
              <div
                key={appr.id}
                className="bg-white border-2 border-amber-300 rounded-lg p-5 shadow-sm space-y-3"
              >
                <div className="flex justify-between items-start">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-mono text-xs font-bold text-slate-500">{appr.id}</span>
                      <span className="bg-amber-100 text-amber-900 font-bold text-[10px] px-2 py-0.5 rounded border border-amber-300">
                        PENDING HUMAN SIGN-OFF
                      </span>
                    </div>
                    <h3 className="text-sm font-bold text-slate-900">
                      Offensive Check Verification: {detail.tool || 'Metasploit'} against{' '}
                      <code>{detail.target || 'target'}</code>
                    </h3>
                  </div>
                  <span className="font-mono text-[10px] bg-red-100 text-red-800 px-2.5 py-1 rounded font-bold">
                    TTL: 15 MIN
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-3 bg-amber-50/50 p-3 rounded border border-amber-200 text-xs text-slate-700">
                  <div>
                    <strong>Target:</strong> <code>{detail.target || '172.30.0.10'}</code>
                  </div>
                  <div>
                    <strong>Action Module:</strong>{' '}
                    <code>{detail.params?.module || 'auxiliary/scanner/check'}</code>
                  </div>
                  <div className="col-span-2">
                    <strong>Justification:</strong> {detail.justification || 'Verify vulnerability without exploit payload.'}
                  </div>
                </div>

                <div className="flex justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedApproval(appr);
                      setDecision('reject');
                    }}
                    className="px-3.5 py-1.5 text-xs text-red-700 hover:bg-red-50 border border-red-300 rounded font-medium"
                  >
                    Reject Action
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedApproval(appr);
                      setDecision('approve');
                    }}
                    className="px-4 py-1.5 text-xs bg-emerald-600 hover:bg-emerald-700 text-white font-medium rounded shadow-xs"
                  >
                    Approve Verification
                  </button>
                </div>
              </div>
            );
          })
        )}
      </section>

      {/* Decision Dialog Modal */}
      {selectedApproval && (
        <div className="fixed inset-0 z-50 bg-slate-900/50 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white rounded-lg p-6 max-w-md w-full shadow-2xl border border-slate-200 space-y-4">
            <h3 className="text-sm font-bold text-slate-800">
              {decision === 'approve' ? 'Authorize Validation Step' : 'Reject Validation Request'}
            </h3>

            {error && (
              <div className="text-red-700 bg-red-50 p-2 rounded text-xs border border-red-200">
                {error}
              </div>
            )}

            <form onSubmit={handleDecisionSubmit} className="space-y-3">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Approver Identity *
                </label>
                <input
                  type="text"
                  required
                  value={approver}
                  onChange={(e) => setApprover(e.target.value)}
                  className="w-full text-xs px-2.5 py-1.5 border border-slate-300 rounded"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Technical Decision Rationale *
                </label>
                <textarea
                  rows={3}
                  required
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder="Provide recorded reason for this authorization or rejection (audit logged)..."
                  className="w-full text-xs p-2 border border-slate-300 rounded"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setSelectedApproval(null)}
                  className="px-3 py-1.5 text-xs text-slate-600 hover:bg-slate-100 rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting || !reason.trim()}
                  className={`px-4 py-1.5 text-xs font-medium rounded text-white shadow-xs ${
                    decision === 'approve'
                      ? 'bg-emerald-600 hover:bg-emerald-700'
                      : 'bg-red-600 hover:bg-red-700'
                  }`}
                >
                  {submitting ? 'Recording...' : `Confirm ${decision.toUpperCase()}`}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Historical Approvals */}
      <section className="space-y-3 pt-4 border-t border-slate-200">
        <h2 className="text-xs font-bold text-slate-700 uppercase tracking-wider">
          Recorded Approvals History ({decided.length})
        </h2>
        <div className="bg-white border border-slate-200 rounded divide-y divide-slate-100">
          {decided.length === 0 ? (
            <div className="p-4 text-center text-slate-400 text-xs">No decided approvals.</div>
          ) : (
            decided.map((item) => (
              <div key={item.id} className="p-3 text-xs flex justify-between items-center">
                <div>
                  <span className="font-mono text-slate-400 mr-2">{item.id}</span>
                  <span
                    className={`font-bold uppercase text-[9px] px-1.5 py-0.5 rounded mr-2 ${
                      item.status === 'approved'
                        ? 'bg-emerald-100 text-emerald-800'
                        : 'bg-red-100 text-red-800'
                    }`}
                  >
                    {item.status}
                  </span>
                  <span className="text-slate-600">{item.reason || 'No reason specified'}</span>
                </div>
                <span className="text-[10px] text-slate-400 font-mono">
                  {item.requested_by || 'analyst'}
                </span>
              </div>
            ))
          )}
        </div>
      </section>
    </div>
  );
};
