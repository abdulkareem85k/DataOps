import React from 'react';
import { HealthState } from '../types';

interface TopBarProps {
  currentTab: string;
  health: HealthState;
  activeAssessmentId: string;
  assessments: { id: string; name: string }[];
  onSelectAssessment: (id: string) => void;
  onNewAssessment: () => void;
  onEmergencyStop: () => void;
  isStopping: boolean;
}

export const TopBar: React.FC<TopBarProps> = ({
  currentTab,
  health,
  activeAssessmentId,
  assessments,
  onSelectAssessment,
  onNewAssessment,
  onEmergencyStop,
  isStopping,
}) => {
  return (
    <header className="topbar">
      <div className="breadcrumb flex items-center gap-2">
        <span className="font-mono text-[9px] uppercase tracking-wider text-slate-500">
          WORKSPACE
        </span>
        <span className="breadcrumb-slash text-slate-400">/</span>

        {assessments.length > 0 ? (
          <select
            value={activeAssessmentId}
            onChange={(e) => onSelectAssessment(e.target.value)}
            className="text-xs font-semibold text-slate-800 bg-white border border-slate-300 rounded px-2 py-1 max-w-[280px]"
          >
            {assessments.map((a) => (
              <option key={a.id} value={a.id}>
                {a.id} — {a.name}
              </option>
            ))}
          </select>
        ) : (
          <span className="font-semibold text-slate-800 text-xs">
            {activeAssessmentId || 'No Active Workspace'}
          </span>
        )}

        <span className="breadcrumb-slash text-slate-400">/</span>
        <span className="font-mono text-[10px] uppercase text-blue-600">
          {currentTab}
        </span>
      </div>

      <div className="topbar-right flex items-center gap-3">
        <button
          type="button"
          onClick={onNewAssessment}
          className="text-[11px] font-medium bg-slate-100 hover:bg-slate-200 text-slate-800 px-2.5 py-1 rounded border border-slate-300 transition-colors"
        >
          + New Assessment
        </button>

        <span className="topbar-divider" />

        <div className="health-indicator flex items-center gap-1.5 font-mono text-[10px]">
          <span className={`health-dot health-${health}`} />
          <span className="text-slate-600">API {health.toUpperCase()}</span>
        </div>

        <span className="topbar-divider" />

        {/* Global Emergency STOP ALL Button */}
        <button
          type="button"
          onClick={onEmergencyStop}
          disabled={!activeAssessmentId || isStopping}
          className="bg-red-600 hover:bg-red-700 active:bg-red-800 disabled:opacity-40 text-white font-mono text-[10px] font-bold px-3 py-1.5 rounded shadow-sm flex items-center gap-1.5 transition-all"
          title="Immediately abort active scans and background runner processes"
        >
          <span className="inline-block w-2 h-2 rounded-full bg-white animate-pulse" />
          {isStopping ? 'ABORTING...' : 'STOP ALL SCANS'}
        </button>
      </div>
    </header>
  );
};
