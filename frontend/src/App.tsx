import { useEffect, useState } from 'react';
import {
  abortAssessment,
  fetchApprovals,
  fetchAuditEvents,
  fetchFindings,
  fetchHealth,
} from './api';
import { ApprovalQueue } from './components/ApprovalQueue';
import { AuditExplorer } from './components/AuditExplorer';
import { IntegrationsMatrix } from './components/IntegrationsMatrix';
import { NewAssessmentModal } from './components/NewAssessmentModal';
import { ReportView } from './components/ReportView';
import { Sidebar } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { Workspace } from './components/Workspace';
import { Approval, AuditEvent, Finding, HealthState } from './types';

export default function App() {
  const [currentTab, setCurrentTab] = useState('workspace');
  const [health, setHealth] = useState<HealthState>('checking');
  const [activeAssessmentId, setActiveAssessmentId] = useState<string>('ASM-DEMO-001');
  const [findings, setFindings] = useState<Finding[]>([]);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isStopping, setIsStopping] = useState(false);
  const [bannerNotice, setBannerNotice] = useState<string | null>(null);

  // Poll health and assessment data
  useEffect(() => {
    fetchHealth().then((ok) => setHealth(ok ? 'online' : 'offline'));
  }, []);

  const refreshData = async (asmId: string) => {
    if (!asmId) return;
    try {
      const [fnds, apprs, audits] = await Promise.all([
        fetchFindings(asmId).catch(() => []),
        fetchApprovals(asmId).catch(() => []),
        fetchAuditEvents(asmId).catch(() => []),
      ]);
      setFindings(fnds);
      setApprovals(apprs);
      setAuditEvents(audits);
    } catch {}
  };

  useEffect(() => {
    refreshData(activeAssessmentId);
  }, [activeAssessmentId]);

  // Emergency Stop Handler
  const handleEmergencyStop = async () => {
    if (!activeAssessmentId || isStopping) return;
    setIsStopping(true);
    try {
      const res = await abortAssessment(activeAssessmentId);
      setBannerNotice(res.message);
      refreshData(activeAssessmentId);
    } catch (err: any) {
      setBannerNotice(`Emergency abort: ${err.message || 'Signal dispatched'}`);
    } finally {
      setIsStopping(false);
    }
  };

  const handleRequestValidation = (finding: Finding) => {
    // Add pending validation request and switch to approvals tab
    const newApproval: Approval = {
      id: `APR-${Date.now().toString().slice(-4)}`,
      assessment_id: activeAssessmentId,
      action: JSON.stringify({
        finding_id: finding.id,
        tool: 'metasploit',
        target: finding.target_asset || finding.asset_id,
        params: { module: 'exploit/multi/http/apache_normalize_path_rce' },
        justification: `Verify exploitability of ${finding.title} safely.`,
        risk: 'high',
      }),
      action_detail: {
        finding_id: finding.id,
        tool: 'metasploit',
        target: finding.target_asset || finding.asset_id,
        params: { module: 'exploit/multi/http/apache_normalize_path_rce' },
        justification: `Verify exploitability of ${finding.title} safely.`,
        risk: 'high',
      },
      status: 'pending',
    };
    setApprovals((prev) => [newApproval, ...prev]);
    setCurrentTab('approvals');
  };

  const pendingApprovalsCount = approvals.filter((a) => a.status === 'pending').length;

  return (
    <div className="app-shell min-h-screen bg-slate-100 flex text-slate-800">
      {/* Sidebar */}
      <Sidebar
        currentTab={currentTab}
        onSelectTab={(tab) => setCurrentTab(tab)}
        pendingApprovalsCount={pendingApprovalsCount}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        <TopBar
          currentTab={currentTab}
          health={health}
          activeAssessmentId={activeAssessmentId}
          onNewAssessment={() => setIsModalOpen(true)}
          onEmergencyStop={handleEmergencyStop}
          isStopping={isStopping}
        />

        {bannerNotice && (
          <div className="bg-red-600 text-white text-xs px-4 py-2 flex justify-between items-center font-mono">
            <span>🚨 {bannerNotice}</span>
            <button
              type="button"
              onClick={() => setBannerNotice(null)}
              className="text-white hover:text-slate-200 font-bold"
            >
              &times;
            </button>
          </div>
        )}

        <div className="flex-1 overflow-auto">
          {currentTab === 'overview' && (
            <div className="p-8 max-w-5xl mx-auto space-y-6">
              <div className="page-heading">
                <div>
                  <p className="eyebrow">AUTHORIZED ASSESSMENT · CONTROL PLANE</p>
                  <h1>Lab Overview &amp; Security Posture</h1>
                  <p className="heading-copy">
                    A scoped workspace for evidence-led, deterministic security testing.
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-4">
                <div className="bg-white p-5 rounded-lg border border-slate-200 shadow-xs">
                  <div className="text-[10px] font-mono font-bold text-slate-400 uppercase">
                    ACTIVE ASSESSMENT
                  </div>
                  <div className="text-sm font-bold text-slate-800 mt-1">
                    {activeAssessmentId}
                  </div>
                  <div className="text-xs text-slate-500 mt-1">
                    Target CIDR: 172.30.0.0/24
                  </div>
                </div>

                <div className="bg-white p-5 rounded-lg border border-slate-200 shadow-xs">
                  <div className="text-[10px] font-mono font-bold text-slate-400 uppercase">
                    CORRELATED FINDINGS
                  </div>
                  <div className="text-xl font-bold text-blue-600 mt-1">
                    {findings.length}
                  </div>
                  <div className="text-xs text-slate-500 mt-1">
                    Prioritized mathematically
                  </div>
                </div>

                <div className="bg-white p-5 rounded-lg border border-slate-200 shadow-xs">
                  <div className="text-[10px] font-mono font-bold text-slate-400 uppercase">
                    APPROVAL GATE
                  </div>
                  <div className="text-xl font-bold text-amber-600 mt-1">
                    {pendingApprovalsCount} Pending
                  </div>
                  <div className="text-xs text-slate-500 mt-1">
                    Offensive check modules
                  </div>
                </div>
              </div>

              <div className="p-4 bg-emerald-50 border border-emerald-300 rounded text-xs text-emerald-900">
                <strong>✓ Fail-Closed Defensive Scoping Active:</strong> Target execution is
                restricted strictly to registered private subnets. Out-of-scope targets are rejected
                automatically by the deterministic scope engine.
              </div>
            </div>
          )}

          {currentTab === 'workspace' && (
            <Workspace
              assessmentId={activeAssessmentId}
              findings={findings}
              onRequestValidation={handleRequestValidation}
            />
          )}

          {currentTab === 'approvals' && (
            <ApprovalQueue
              approvals={approvals}
              onRefresh={() => refreshData(activeAssessmentId)}
            />
          )}

          {currentTab === 'reports' && (
            <ReportView assessmentId={activeAssessmentId} />
          )}

          {currentTab === 'audit' && (
            <AuditExplorer
              assessmentId={activeAssessmentId}
              auditEvents={auditEvents}
              onRefresh={() => refreshData(activeAssessmentId)}
            />
          )}

          {currentTab === 'integrations' && <IntegrationsMatrix />}
        </div>
      </div>

      {/* New Assessment Modal */}
      <NewAssessmentModal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        onCreated={(id) => {
          setActiveAssessmentId(id);
          refreshData(id);
          setCurrentTab('workspace');
        }}
      />
    </div>
  );
}
