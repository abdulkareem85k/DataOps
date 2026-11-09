import React from 'react';
import { Finding } from '../types';

interface FindingDetailDrawerProps {
  finding: Finding | null;
  onClose: () => void;
  onRequestValidation: (finding: Finding) => void;
}

export const FindingDetailDrawer: React.FC<FindingDetailDrawerProps> = ({
  finding,
  onClose,
  onRequestValidation,
}) => {
  if (!finding) return null;

  const observedItems = finding.evidence?.filter((e) => e.type === 'observed') || [];
  const inferenceItems = finding.evidence?.filter((e) => e.type === 'inference') || [];

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-slate-900/40 backdrop-blur-xs flex justify-end">
      <div className="w-full max-w-2xl bg-white shadow-2xl h-full flex flex-col border-l border-slate-200">
        {/* Drawer Header */}
        <div className="p-4 border-b border-slate-200 flex justify-between items-start bg-slate-50">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="font-mono text-xs font-bold text-slate-500">{finding.id}</span>
              <span
                className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded ${
                  finding.tool_severity === 'critical'
                    ? 'bg-red-100 text-red-700 border border-red-200'
                    : finding.tool_severity === 'high'
                    ? 'bg-orange-100 text-orange-700 border border-orange-200'
                    : finding.tool_severity === 'medium'
                    ? 'bg-amber-100 text-amber-700 border border-amber-200'
                    : 'bg-emerald-100 text-emerald-700 border border-emerald-200'
                }`}
              >
                {finding.tool_severity || finding.severity || 'UNKNOWN'}
              </span>
              <span className="text-[10px] bg-slate-800 text-white font-mono px-2 py-0.5 rounded">
                Risk: {finding.risk_score || 0}/100 ({finding.risk_band || 'P3'})
              </span>
            </div>
            <h2 className="text-sm font-bold text-slate-900">{finding.title}</h2>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-slate-600 text-xl font-bold p-1"
          >
            &times;
          </button>
        </div>

        {/* Drawer Content */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5 text-xs">
          {/* Metadata Grid */}
          <div className="grid grid-cols-2 gap-2 bg-slate-50 p-3 rounded border border-slate-200 text-slate-700">
            <div>
              <span className="font-semibold text-slate-500">Target Asset: </span>
              <code className="bg-white px-1.5 py-0.5 rounded border border-slate-200">
                {finding.target_asset || finding.asset_id}
              </code>
            </div>
            <div>
              <span className="font-semibold text-slate-500">Port / Protocol: </span>
              <span>
                {finding.port || 'N/A'}/{finding.protocol || 'tcp'}
              </span>
            </div>
            <div>
              <span className="font-semibold text-slate-500">Contributing Tool: </span>
              <span className="capitalize">{finding.source_tools?.join(', ') || 'Scanner'}</span>
            </div>
            <div>
              <span className="font-semibold text-slate-500">CVSS Base: </span>
              <span>
                {finding.cvss_score !== null && finding.cvss_score !== undefined
                  ? `${finding.cvss_score} (${finding.cvss_vector || 'vector stored'})`
                  : 'Not scored by source'}
              </span>
            </div>
          </div>

          {/* Description */}
          <div>
            <h3 className="font-bold text-slate-800 mb-1 text-xs uppercase tracking-wider">
              Vulnerability Description
            </h3>
            <p className="text-slate-600 leading-relaxed bg-white border border-slate-200 p-3 rounded">
              {finding.description}
            </p>
          </div>

          {/* CRITICAL EVIDENCE CONTAINER (Observed vs Inference) */}
          <div className="space-y-3">
            <h3 className="font-bold text-slate-800 text-xs uppercase tracking-wider flex items-center justify-between">
              <span>Evidence Traceability (Observed vs. Inference)</span>
              <span className="text-[10px] text-blue-600 font-mono">STRICT SEPARATION</span>
            </h3>

            {/* OBSERVED EVIDENCE BLOCK */}
            <div className="border border-blue-200 bg-blue-50/40 rounded overflow-hidden">
              <div className="bg-blue-100/70 border-b border-blue-200 px-3 py-1.5 flex justify-between items-center">
                <span className="font-bold text-[10px] tracking-wider text-blue-800 uppercase flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-blue-600" />
                  OBSERVED EVIDENCE (Raw Scanner Bytes)
                </span>
                <span className="text-[9px] text-slate-500 font-mono">IMMUTABLE ON-WRITE</span>
              </div>
              <div className="p-3">
                {observedItems.length > 0 ? (
                  observedItems.map((obs, idx) => (
                    <div key={idx} className="space-y-2">
                      <pre className="bg-slate-900 text-slate-100 p-2.5 rounded font-mono text-[11px] overflow-x-auto whitespace-pre-wrap leading-tight">
                        <code>{obs.content}</code>
                      </pre>
                      {obs.raw_ref && (
                        <div className="text-[10px] text-slate-500 font-mono flex gap-3">
                          <span>ToolRun: {obs.raw_ref.tool_run_id || 'TRN-001'}</span>
                          <span>Locator: {obs.raw_ref.locator || 'xpath / line'}</span>
                        </div>
                      )}
                    </div>
                  ))
                ) : (
                  <p className="text-slate-500 italic">No inline raw byte snippet captured for this record.</p>
                )}
              </div>
            </div>

            {/* AI INFERENCE BLOCK */}
            <div className="border border-purple-200 bg-purple-50/40 rounded overflow-hidden">
              <div className="bg-purple-100/70 border-b border-purple-200 px-3 py-1.5 flex justify-between items-center">
                <span className="font-bold text-[10px] tracking-wider text-purple-800 uppercase flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full bg-purple-600" />
                  AI INFERENCE (Reasoning &amp; Impact Posture)
                </span>
                <span className="text-[9px] text-slate-500 font-mono">GROUNDED ENGINE</span>
              </div>
              <div className="p-3 text-slate-700 leading-relaxed text-xs">
                {inferenceItems.length > 0 ? (
                  inferenceItems.map((inf, idx) => <p key={idx}>{inf.content}</p>)
                ) : (
                  <p>{finding.risk_rationale || 'Prioritized based on exposure factor and scanner confidence.'}</p>
                )}
              </div>
            </div>
          </div>

          {/* Actionable Remediation */}
          <div>
            <h3 className="font-bold text-slate-800 mb-1 text-xs uppercase tracking-wider">
              Actionable Remediation Guidance
            </h3>
            <div className="bg-emerald-50 border border-emerald-200 text-emerald-900 p-3 rounded leading-relaxed">
              Upgrade the component to the latest vendor release. Enforce strict input sanitization
              and restrict access to authorized management subnets only.
            </div>
          </div>
        </div>

        {/* Drawer Footer Actions */}
        <div className="p-4 border-t border-slate-200 bg-slate-50 flex items-center justify-between">
          <div className="text-[11px] text-slate-500">
            Status: <strong className="uppercase">{finding.status}</strong>
          </div>
          <button
            type="button"
            onClick={() => onRequestValidation(finding)}
            className="px-3.5 py-1.5 bg-amber-600 hover:bg-amber-700 text-white font-medium rounded text-xs shadow-sm flex items-center gap-1.5 transition-colors"
          >
            <span>Request Active Validation Gate</span>
          </button>
        </div>
      </div>
    </div>
  );
};

