import React, { useEffect, useState } from 'react';
import { fetchIntegrations } from '../api';
import { IntegrationTool } from '../types';

export const IntegrationsMatrix: React.FC = () => {
  const [tools, setTools] = useState<IntegrationTool[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchIntegrations()
      .then((data) => setTools(data))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      <div className="border-b border-slate-200 pb-4">
        <h1 className="text-xl font-bold text-slate-900">Truthful Integration Status Matrix</h1>
        <p className="text-xs text-slate-500 mt-1">
          In accordance with the hackathon transparency invariant, all 7 scanner integrations are truthfully categorized by operational execution mode.
        </p>
      </div>

      <div className="bg-white border border-slate-200 rounded-lg shadow-xs overflow-hidden">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 font-mono text-[10px] uppercase">
              <th className="py-3 px-4">Tool</th>
              <th className="py-3 px-4">Execution Mode</th>
              <th className="py-3 px-4">Operational Status</th>
              <th className="py-3 px-4">Engine / Version</th>
              <th className="py-3 px-4">Capabilities &amp; Scope Limits</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {loading ? (
              <tr>
                <td colSpan={5} className="py-8 text-center text-slate-400">
                  Querying tool health and availability...
                </td>
              </tr>
            ) : (
              tools.map((tool) => (
                <tr key={tool.name} className="hover:bg-slate-50">
                  <td className="py-3 px-4 font-bold text-slate-900 flex items-center gap-2">
                    <span
                      className={`w-2 h-2 rounded-full ${
                        tool.mode === 'Live'
                          ? 'bg-emerald-500'
                          : tool.mode === 'Import-only'
                          ? 'bg-blue-500'
                          : 'bg-amber-500'
                      }`}
                    />
                    {tool.name}
                  </td>
                  <td className="py-3 px-4">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase font-mono ${
                        tool.mode === 'Live'
                          ? 'bg-emerald-100 text-emerald-800'
                          : tool.mode === 'Import-only'
                          ? 'bg-blue-100 text-blue-800'
                          : 'bg-amber-100 text-amber-800'
                      }`}
                    >
                      {tool.mode}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-slate-700 font-medium">{tool.status}</td>
                  <td className="py-3 px-4 font-mono text-[11px] text-slate-500">
                    {tool.version || 'Adapter Engine'}
                  </td>
                  <td className="py-3 px-4 text-slate-600">
                    <div className="font-medium text-slate-800">{tool.capabilities}</div>
                    <div className="text-[10px] text-slate-400 mt-0.5 italic">{tool.limitations}</div>
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

