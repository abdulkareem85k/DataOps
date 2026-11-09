import React, { useState } from 'react';
import { Finding, PlanStep } from '../types';
import { ChatPanel } from './ChatPanel';
import { FindingDetailDrawer } from './FindingDetailDrawer';
import { FindingsTable } from './FindingsTable';
import { PlanTimeline } from './PlanTimeline';

interface WorkspaceProps {
  assessmentId: string;
  findings: Finding[];
  onRequestValidation: (finding: Finding) => void;
}

export const Workspace: React.FC<WorkspaceProps> = ({
  assessmentId,
  findings,
  onRequestValidation,
}) => {
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [planSteps, setPlanSteps] = useState<PlanStep[]>([
    {
      action: 'nmap',
      target: '172.30.0.10',
      rationale: 'Active host discovery and service port enumeration on lab subnet.',
      status: 'completed',
    },
    {
      action: 'zap',
      target: 'http://172.30.0.10:3000',
      rationale: 'Web DAST baseline vulnerability crawl on detected HTTP service.',
      status: 'proposed',
    },
  ]);
  const [avoidedRepeats] = useState(1);

  const handlePlanProposed = (newSteps: any[]) => {
    const formatted: PlanStep[] = newSteps.map((s) => ({
      action: s.action || s.tool,
      target: s.target,
      rationale: s.rationale,
      status: 'proposed',
    }));
    setPlanSteps(formatted);
  };

  const handleApproveStep = (idx: number) => {
    setPlanSteps((prev) =>
      prev.map((s, i) => (i === idx ? { ...s, status: 'completed' } : s))
    );
  };

  const handleSkipStep = (idx: number) => {
    setPlanSteps((prev) =>
      prev.map((s, i) => (i === idx ? { ...s, status: 'skipped' } : s))
    );
  };

  return (
    <div className="flex-1 flex overflow-hidden relative h-[calc(100vh-65px)]">
      {/* 3-Panel Console */}
      <div className="w-1/3 min-w-[320px] max-w-[420px] h-full flex flex-col">
        <ChatPanel
          assessmentId={assessmentId}
          onPlanProposed={handlePlanProposed}
        />
      </div>

      <div className="w-1/3 min-w-[320px] max-w-[440px] h-full flex flex-col">
        <PlanTimeline
          steps={planSteps}
          avoidedRepeats={avoidedRepeats}
          onApproveStep={handleApproveStep}
          onSkipStep={handleSkipStep}
        />
      </div>

      <div className="flex-1 min-w-[360px] h-full flex flex-col">
        <FindingsTable
          findings={findings}
          onSelectFinding={(f) => setSelectedFinding(f)}
        />
      </div>

      {/* Slide-over Finding Detail Drawer */}
      <FindingDetailDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
        onRequestValidation={(f) => {
          setSelectedFinding(null);
          onRequestValidation(f);
        }}
      />
    </div>
  );
};
