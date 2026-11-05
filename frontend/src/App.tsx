import { useEffect, useState } from 'react';

type HealthState = 'checking' | 'online' | 'offline';

type ServiceStatus = {
  name: string;
  detail: string;
  state: 'Live' | 'Planned' | 'Disabled';
  mark: string;
};

const services: ServiceStatus[] = [
  {
    name: 'Backend API',
    detail: 'Health endpoint responds from the application service.',
    state: 'Live',
    mark: 'API',
  },
  {
    name: 'Scanner runner',
    detail: 'Nmap/Nikto endpoints are lab-scoped and bearer-protected.',
    state: 'Planned',
    mark: 'RUN',
  },
  {
    name: 'ZAP daemon',
    detail: 'Compose service is pinned; active scanning stays disabled.',
    state: 'Planned',
    mark: 'ZAP',
  },
];

function StatePill({ state }: { state: string }) {
  return <span className={`state-pill state-${state.toLowerCase()}`}>{state}</span>;
}

export default function App() {
  const [health, setHealth] = useState<HealthState>('checking');

  useEffect(() => {
    let active = true;
    fetch('/health', { headers: { Accept: 'text/plain' } })
      .then((response) => {
        if (!response.ok) throw new Error('Health check failed');
        return response.text();
      })
      .then((body) => {
        if (active) setHealth(body.trim() === 'OK' ? 'online' : 'offline');
      })
      .catch(() => {
        if (active) setHealth('offline');
      });
    return () => {
      active = false;
    };
  }, []);

  return (
    <div className="app-shell min-h-screen">
      <aside className="sidebar">
        <div className="brand-lockup">
          <div className="brand-mark" aria-hidden="true">
            <span />
            <span />
            <span />
          </div>
          <div>
            <p className="brand-name">VAPT / AGENT</p>
            <p className="brand-caption">ASSESSMENT WORKSPACE</p>
          </div>
        </div>

        <div className="workspace-label">WORKSPACE</div>
        <nav aria-label="Primary navigation">
          <a className="nav-link nav-link-active" href="#overview" aria-current="page">
            <span className="nav-index">01</span> Overview
          </a>
          <span className="nav-link nav-link-muted" aria-disabled="true">
            <span className="nav-index">02</span> Assessments <span className="soon-mark">NEXT</span>
          </span>
          <span className="nav-link nav-link-muted" aria-disabled="true">
            <span className="nav-index">03</span> Findings <span className="soon-mark">NEXT</span>
          </span>
          <span className="nav-link nav-link-muted" aria-disabled="true">
            <span className="nav-index">04</span> Audit trail <span className="soon-mark">NEXT</span>
          </span>
        </nav>

        <div className="sidebar-bottom">
          <div className="scope-mini-label">SCOPE MODE</div>
          <div className="scope-mini-value"><span className="scope-dot" /> INTERNAL LAB ONLY</div>
          <p>Public destinations are blocked by default.</p>
          <div className="sidebar-version">FOUNDATION / 0.1</div>
        </div>
      </aside>

      <main className="main-content" id="overview">
        <header className="topbar">
          <div className="breadcrumb"><span>WORKSPACE</span><span className="breadcrumb-slash">/</span> Overview</div>
          <div className="topbar-right">
            <span className="milestone-label">MILESTONE A</span>
            <span className="topbar-divider" />
            <span className="health-indicator"><i className={`health-dot health-${health}`} /> API {health.toUpperCase()}</span>
          </div>
        </header>

        <section className="page-heading">
          <div>
            <p className="eyebrow">AUTHORIZED ASSESSMENT · CONTROL PLANE</p>
            <h1>Lab overview</h1>
            <p className="heading-copy">A scoped workspace for evidence-led security testing.</p>
          </div>
          <div className="heading-stamp">
            <span className="stamp-top">CURRENT PHASE</span>
            <strong>FOUNDATION</strong>
            <span className="stamp-bottom">PROMPT 1 / 14</span>
          </div>
        </section>

        <section className="notice-panel" aria-label="Safety boundary">
          <div className="notice-symbol" aria-hidden="true">S</div>
          <div className="notice-copy">
            <strong>Scope boundary is enforced in code.</strong>
            <p>Targets must be literal IPv4 addresses inside the configured private lab CIDR. Approval never expands scope.</p>
          </div>
          <StatePill state="Live" />
        </section>

        <section className="section-block">
          <div className="section-heading">
            <div>
              <p className="eyebrow">SERVICE POSTURE</p>
              <h2>Foundation services</h2>
            </div>
            <span className="section-note">STATUS IS VERIFIED OR CLEARLY MARKED</span>
          </div>
          <div className="service-list">
            {services.map((service, index) => (
              <article className="service-row" key={service.name}>
                <div className="service-number">0{index + 1}</div>
                <div className="service-mark">{service.mark}</div>
                <div className="service-copy">
                  <h3>{service.name}</h3>
                  <p>{service.detail}</p>
                </div>
                <StatePill state={service.name === 'Backend API' && health === 'offline' ? 'Disabled' : service.state} />
                <span className="service-chevron" aria-hidden="true">›</span>
              </article>
            ))}
          </div>
        </section>

        <section className="section-block lower-grid">
          <article className="quiet-card">
            <div className="card-topline"><span className="eyebrow">EVIDENCE REGISTER</span><span className="card-code">EV / 00</span></div>
            <h2>No findings ingested</h2>
            <p>Scanner output will appear only after a scoped, approved run or a validated import. No sample findings are included.</p>
            <div className="empty-state-line"><span /> WAITING FOR APPROVED INPUT</div>
          </article>
          <article className="quiet-card approval-card">
            <div className="card-topline"><span className="eyebrow">HUMAN CONTROL</span><span className="card-code">AP / 00</span></div>
            <h2>Active validation disabled</h2>
            <p>Intrusive web scans and offensive validation require a recorded human approval. No scan action is exposed in this foundation UI.</p>
            <div className="approval-lock"><span aria-hidden="true">▣</span> APPROVAL GATE REQUIRED</div>
          </article>
        </section>

        <footer className="page-footer">
          <span>AI UNIFIED VAPT AGENT</span>
          <span>LAB-ONLY · NO PUBLIC TARGETS · NO AUTONOMOUS EXPLOITATION</span>
        </footer>
      </main>
    </div>
  );
}
