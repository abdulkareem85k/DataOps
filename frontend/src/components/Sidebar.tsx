import React from 'react';

interface SidebarProps {
  currentTab: string;
  onSelectTab: (tab: string) => void;
  pendingApprovalsCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  pendingApprovalsCount,
}) => {
  const tabs = [
    { id: 'overview', index: '01', label: 'Overview' },
    { id: 'workspace', index: '02', label: 'Assessment Console' },
    { id: 'approvals', index: '03', label: 'Human Approvals', badge: pendingApprovalsCount },
    { id: 'reports', index: '04', label: 'PDF Report & Preview' },
    { id: 'audit', index: '05', label: 'Audit Trail & Integrity' },
    { id: 'integrations', index: '06', label: 'Integration Matrix' },
  ];

  return (
    <aside className="sidebar select-none">
      <div className="brand-lockup">
        <div className="brand-mark" aria-hidden="true">
          <span />
          <span />
          <span />
        </div>
        <div>
          <p className="brand-name">VAPT / AGENT</p>
          <p className="brand-caption">AI OFFENSIVE AUDIT CORE</p>
        </div>
      </div>

      <div className="workspace-label">WORKSPACES</div>
      <nav aria-label="Primary navigation">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            type="button"
            className={`nav-link text-left w-full border-none cursor-pointer transition-colors ${
              currentTab === tab.id ? 'nav-link-active font-semibold' : 'text-[#aab5c1] hover:bg-white/5'
            }`}
            onClick={() => onSelectTab(tab.id)}
          >
            <span className="nav-index">{tab.index}</span>
            <span className="flex-1 truncate">{tab.label}</span>
            {tab.badge !== undefined && tab.badge > 0 && (
              <span className="ml-auto bg-amber-500 text-black text-[9px] font-bold px-1.5 py-0.5 rounded-full">
                {tab.badge}
              </span>
            )}
          </button>
        ))}
      </nav>

      <div className="sidebar-bottom">
        <div className="scope-mini-label">SAFETY BOUNDARY</div>
        <div className="scope-mini-value">
          <span className="scope-dot" /> INTERNAL LAB ONLY
        </div>
        <p className="text-[10px] text-[#91a0b0] leading-snug mt-2">
          Public destinations (WAN) are blocked by default via deterministic scope checking.
        </p>
        <div className="sidebar-version text-[9px] text-[#6f8095]">PLATFORM / v0.2.0</div>
      </div>
    </aside>
  );
};
