import React, { useState } from 'react';
import { Finding } from '../types';

interface FindingsTableProps {
  findings: Finding[];
  onSelectFinding: (finding: Finding) => void;
}

export const FindingsTable: React.FC<FindingsTableProps> = ({
  findings,
  onSelectFinding,
}) => {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');

  const filtered = findings.filter((f) => {
    const matchesSearch =
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      (f.target_asset || f.asset_id || '').toLowerCase().includes(search.toLowerCase()) ||
      f.id.toLowerCase().includes(search.toLowerCase());
    const matchesSev =
      severityFilter === 'all' ||
      (f.tool_severity || f.severity || '').toLowerCase() === severityFilter.toLowerCase();
    return matchesSearch && matchesSev;
  });

  return (
    <div className="flex flex-col h-full bg-white">
      <div className="p-3 border-b border-slate-200 bg-white space-y-2">
        <div className="flex justify-between items-center">
          <span className="font-bold text-xs uppercase tracking-wider text-slate-700">
            Correlated Findings ({findings.length})
          </span>
          <span className="text-[10px] text-slate-500 font-mono">DETERMINISTIC RANKING</span>
        </div>

        <div className="flex gap-2">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search findings or targets..."
            className="flex-1 text-xs px-2.5 py-1.5 border border-slate-300 rounded focus:ring-1 focus:ring-blue-500 outline-none"
          />
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="text-xs px-2 py-1.5 border border-slate-300 rounded bg-white text-slate-700"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto divide-y divide-slate-100">
        {filtered.length === 0 ? (
          <div className="text-center py-12 text-slate-400 text-xs">
            No security findings matching the criteria.
          </div>
        ) : (
          filtered.map((f) => (
            <div
              key={f.id}
              onClick={() => onSelectFinding(f)}
              className="p-3 hover:bg-slate-50 cursor-pointer transition-colors space-y-1.5"
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[10px] font-bold text-slate-400">{f.id}</span>
                  <span
                    className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${
                      (f.tool_severity || f.severity) === 'critical'
                        ? 'bg-red-100 text-red-700'
                        : (f.tool_severity || f.severity) === 'high'
                        ? 'bg-orange-100 text-orange-700'
                        : (f.tool_severity || f.severity) === 'medium'
                        ? 'bg-amber-100 text-amber-700'
                        : 'bg-emerald-100 text-emerald-700'
                    }`}
                  >
                    {f.tool_severity || f.severity}
                  </span>
                </div>
                <span className="font-mono text-[10px] font-bold bg-slate-900 text-white px-2 py-0.5 rounded">
                  {f.risk_score ? `${Math.round(f.risk_score)}/100` : 'P3'}
                </span>
              </div>

              <h4 className="text-xs font-semibold text-slate-900 leading-snug line-clamp-2">
                {f.title}
              </h4>

              <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono">
                <span className="truncate max-w-[180px]">
                  {f.target_asset || f.asset_id}:{f.port || 'all'}
                </span>
                <span className="bg-slate-100 px-1 rounded text-slate-600">
                  {f.source_tools?.join(', ') || 'nmap'}
                </span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
