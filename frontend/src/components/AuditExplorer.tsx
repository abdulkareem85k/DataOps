import React, { useState } from 'react';
import { verifyAuditChain } from '../api';
import { AuditEvent } from '../types';

interface AuditExplorerProps {
  assessmentId: string;
  auditEvents: AuditEvent[];
  onRefresh: () => void;
}

export const AuditExplorer: React.FC<AuditExplorerProps> = ({
  assessmentId,
  auditEvents,
  onRefresh,
}) => {
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<{
    verified: boolean;
    event_count: number;
    message: string;
  } | null>(null);

  const handleVerify = async () => {
    if (!assessmentId) return;
    setVerifying(true);
    try {
      const res = await verifyAuditChain(assessmentId);
      setVerifyResult(res);
    } catch (err: any) {
      setVerifyResult({
        verified: false,
        event_count: auditEvents.length,
        message: err.message || 'Verification check failed',
      });
    } finally {
      setVerifying(false);
    }
  };

  const exportUrl = (format: string) =>
    `/assessments/${assessmentId}/audit/export?format=${format}`;

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      <div className="flex justify-between items-center border-b border-slate-200 pb-4">
        <div>
          <h1 className="text-xl font-bold text-slate-900">
            Append-Only Cryptographic Audit Trail
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            Every planning step, scope check, scan invocation, and human approval is chained sequentially with SHA-256 hashes.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onRefresh}
            className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium text-xs rounded border border-slate-300"
          >
            ↻ Refresh Log
          </button>
          <button
            type="button"
            onClick={handleVerify}
            disabled={verifying || !assessmentId}
            className="px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white font-medium text-xs rounded shadow-xs transition-colors flex items-center gap-2"
          >
            {verifying ? 'Verifying Hashes...' : '🔒 Verify Cryptographic Chain'}
          </button>
          <a
            href={exportUrl('json')}
            download={`audit_${assessmentId}.json`}
            className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium text-xs rounded border border-slate-300"
          >
            Export JSON
          </a>
          <a
            href={exportUrl('csv')}
            download={`audit_${assessmentId}.csv`}
            className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 font-medium text-xs rounded border border-slate-300"
          >
            Export CSV
          </a>
        </div>
      </div>

      {/* Verification Status Banner */}
      {verifyResult && (
        <div
          className={`p-4 rounded-lg border text-xs flex items-center justify-between ${
            verifyResult.verified
              ? 'bg-emerald-50 border-emerald-300 text-emerald-900'
              : 'bg-red-50 border-red-300 text-red-900'
          }`}
        >
          <div className="flex items-center gap-2">
            <span className="text-lg">
              {verifyResult.verified ? '✓' : '⚠️'}
            </span>
            <div>
              <strong className="block font-bold">
                {verifyResult.verified
                  ? 'Cryptographic SHA-256 Chain Integrity: VERIFIED INTACT'
                  : 'Tamper Detected in Audit Chain!'}
              </strong>
              <span>{verifyResult.message}</span>
            </div>
          </div>
          <span className="font-mono text-[10px]">
            {verifyResult.event_count} events verified from genesis
          </span>
        </div>
      )}

      {/* Events Table */}
      <div className="bg-white border border-slate-200 rounded-lg shadow-xs overflow-hidden">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 font-mono text-[10px] uppercase">
              <th className="py-2.5 px-3">Seq</th>
              <th className="py-2.5 px-3">Timestamp (UTC)</th>
              <th className="py-2.5 px-3">Actor</th>
              <th className="py-2.5 px-3">Event Type</th>
              <th className="py-2.5 px-3">Outcome</th>
              <th className="py-2.5 px-3">SHA-256 Hash</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {auditEvents.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-8 text-center text-slate-400">
                  No audit events recorded for this assessment yet.
                </td>
              </tr>
            ) : (
              auditEvents.map((evt) => (
                <tr key={evt.id} className="hover:bg-slate-50 font-mono text-[11px]">
                  <td className="py-2.5 px-3 font-bold text-slate-600">{evt.seq}</td>
                  <td className="py-2.5 px-3 text-slate-500">
                    {new Date(evt.timestamp).toISOString().replace('T', ' ').slice(0, 19)}
                  </td>
                  <td className="py-2.5 px-3">
                    <span className="bg-slate-100 px-1.5 py-0.5 rounded text-slate-700">
                      {evt.actor}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-900 font-semibold">{evt.event_type}</td>
                  <td className="py-2.5 px-3">
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${
                        evt.outcome === 'success'
                          ? 'bg-emerald-100 text-emerald-800'
                          : 'bg-red-100 text-red-800'
                      }`}
                    >
                      {evt.outcome}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-slate-400 select-all" title={evt.hash}>
                    {evt.hash.slice(0, 16)}...
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
