import React from 'react';
import { PlanStep } from '../types';

interface PlanTimelineProps {
  steps: PlanStep[];
  avoidedRepeats: number;
  onApproveStep?: (index: number) => void;
  onSkipStep?: (index: number) => void;
}

export const PlanTimeline: React.FC<PlanTimelineProps> = ({
  steps,
  avoidedRepeats,
  onApproveStep,
  onSkipStep,
}) => {
  return (
    <div className="flex flex-col h-full bg-slate-50 border-r border-slate-200">
      <div className="p-3 border-b border-slate-200 flex justify-between items-center bg-white">
        <span className="font-bold text-xs uppercase tracking-wider text-slate-700">
          Execution Plan &amp; Timeline
        </span>
        <div className="flex items-center gap-2">
          <span className="text-[10px] font-mono bg-blue-50 text-blue-800 border border-blue-200 px-2 py-0.5 rounded font-semibold">
            Avoided Repeats: {avoidedRepeats}
          </span>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-3">
        {steps.length === 0 ? (
          <div className="text-center py-12 text-slate-400 text-xs">
            <p className="font-semibold text-slate-600 mb-1">No Active Plan Proposed</p>
            <p>Prompt the agent in the chat console to generate an assessment plan.</p>
          </div>
        ) : (
          steps.map((step, idx) => (
            <div
              key={idx}
              className="bg-white border border-slate-200 rounded p-3 shadow-xs space-y-2"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-slate-400">0{idx + 1}</span>
                  <span className="font-mono text-xs font-bold uppercase bg-slate-100 text-slate-800 px-2 py-0.5 rounded border border-slate-200">
                    {step.action}
                  </span>
                  <code className="text-[11px] text-blue-700">{step.target}</code>
                </div>
                <span
                  className={`text-[9px] font-bold uppercase px-2 py-0.5 rounded ${
                    step.status === 'completed'
                      ? 'bg-emerald-100 text-emerald-800'
                      : step.status === 'running'
                      ? 'bg-blue-100 text-blue-800 animate-pulse'
                      : step.status === 'skipped'
                      ? 'bg-slate-200 text-slate-600'
                      : 'bg-amber-100 text-amber-800'
                  }`}
                >
                  {step.status || 'PROPOSED'}
                </span>
              </div>

              <p className="text-xs text-slate-600 leading-normal pl-6">
                <strong>Rationale:</strong> {step.rationale}
              </p>

              {(!step.status || step.status === 'proposed') && (
                <div className="flex justify-end gap-2 pt-2 border-t border-slate-100 pl-6">
                  {onSkipStep && (
                    <button
                      type="button"
                      onClick={() => onSkipStep(idx)}
                      className="px-2.5 py-1 text-[11px] text-slate-500 hover:bg-slate-100 rounded"
                    >
                      Skip
                    </button>
                  )}
                  {onApproveStep && (
                    <button
                      type="button"
                      onClick={() => onApproveStep(idx)}
                      className="px-3 py-1 text-[11px] bg-blue-600 hover:bg-blue-700 text-white font-medium rounded shadow-xs"
                    >
                      Execute Step
                    </button>
                  )}
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
};
