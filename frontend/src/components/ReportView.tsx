import React, { useState } from 'react';
import { generateReport } from '../api';

interface ReportViewProps {
  assessmentId: string;
}

export const ReportView: React.FC<ReportViewProps> = ({ assessmentId }) => {
  const [generating, setGenerating] = useState(false);
  const [reportMeta, setReportMeta] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const handleGenerate = async () => {
    if (!assessmentId) return;
    setGenerating(true);
    setError(null);
    try {
      const res = await generateReport(assessmentId);
      setReportMeta(res);
    } catch (err: any) {
      setError(err.message || 'Report generation failed');
    } finally {
      setGenerating(false);
    }
  };

  const previewUrl = `/assessments/${assessmentId}/report/preview`;
  const downloadPdfUrl = `/assessments/${assessmentId}/report.pdf`;

  return (
    <div className="flex flex-col h-full bg-slate-100">
      {/* Top Controls Bar */}
      <div className="p-4 bg-white border-b border-slate-200 flex justify-between items-center shadow-xs">
        <div>
          <h1 className="text-base font-bold text-slate-800">
            VAPT Client Report Generator
          </h1>
          <p className="text-xs text-slate-500">
            Client-ready VAPT report with mandatory sections, raw evidence traceability, and standards mapping.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={handleGenerate}
            disabled={generating || !assessmentId}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-semibold text-xs rounded shadow-xs transition-colors flex items-center gap-2"
          >
            {generating ? (
              <>
                <span className="w-2 h-2 rounded-full bg-white animate-spin" />
                Compiling Report...
              </>
            ) : (
              '⚡ Generate Final Report'
            )}
          </button>

          <a
            href={downloadPdfUrl}
            download={`VAPT_Report_${assessmentId}.pdf`}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-900 text-white font-semibold text-xs rounded shadow-xs transition-colors flex items-center gap-2"
          >
            📥 Download PDF
          </a>
        </div>
      </div>

      {error && (
        <div className="m-4 bg-red-50 text-red-700 text-xs p-3 rounded border border-red-200">
          {error}
        </div>
      )}

      {reportMeta && (
        <div className="mx-4 mt-4 bg-emerald-50 border border-emerald-300 text-emerald-900 text-xs p-3 rounded flex justify-between items-center">
          <span>
            ✓ Report successfully compiled. Total findings: <strong>{reportMeta.total_findings}</strong> | Risk Posture: <strong>{reportMeta.risk_posture}</strong>
          </span>
          <span className="font-mono text-[10px]">
            Audit Chain: {reportMeta.audit_chain_verified ? 'VERIFIED' : 'UNVERIFIED'}
          </span>
        </div>
      )}

      {/* Embedded Live HTML Preview */}
      <div className="flex-1 p-4 overflow-hidden flex flex-col">
        <div className="flex-1 bg-white border border-slate-300 rounded-lg shadow-sm overflow-hidden">
          {assessmentId ? (
            <iframe
              src={previewUrl}
              title="VAPT Report Live Preview"
              className="w-full h-full border-none"
            />
          ) : (
            <div className="flex items-center justify-center h-full text-slate-400 text-xs">
              Select or create an assessment to view the report preview.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
