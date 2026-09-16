import { useState, type ReactNode } from 'react';
import { Link, NavLink, useNavigate } from 'react-router-dom';

import { BackendStatus } from '@/components/BackendStatus';
import { Icon, type IconName } from '@/components/Icon';
import { downloadCbom } from '@/services/api';

interface AppShellProps {
  children: ReactNode;
}

interface NavItem {
  to: string;
  label: string;
  icon: IconName;
  badge?: string;
}

const NAV_ITEMS: NavItem[] = [
  { to: '/dashboard', label: 'Overview', icon: 'activity' },
  { to: '/scan', label: 'Scanner', icon: 'search', badge: 'Live AST' },
  { to: '/tls', label: 'TLS / Certificates', icon: 'lock', badge: 'Live' },
  { to: '/findings', label: 'Findings', icon: 'alert-triangle' },
  { to: '/cbom', label: 'CBOM Inventory', icon: 'file-json', badge: 'CycloneDX' },
  { to: '/roadmap', label: 'Migration Roadmap', icon: 'target', badge: 'Plan' },
  { to: '/compliance', label: 'Compliance Sensitivity', icon: 'shield', badge: 'Mosca' },
  { to: '/reports', label: 'Migration Report', icon: 'barchart' },
  { to: '/projects', label: 'Projects', icon: 'layers' },
];

export function AppShell({ children }: AppShellProps) {
  const navigate = useNavigate();
  const [sidebarOpen, setSidebarOpen] = useState(true);

  return (
    <div className="min-h-screen flex bg-[#080B0F] text-slate-100 font-sans antialiased">
      {/* Sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 z-40 border-r border-[#222B35] bg-[#0C1117] transition-all duration-300 ${
          sidebarOpen ? 'w-64' : 'w-20'
        } flex flex-col`}
      >
        {/* Brand Header */}
        <div className="flex h-16 items-center justify-between border-b border-[#222B35] px-4">
          <Link to="/" className="flex items-center gap-3 overflow-hidden">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-[#7DB7E8]/30 bg-[#11171E] text-[#7DB7E8]">
              <Icon name="shield" size={20} />
            </div>
            {sidebarOpen ? (
              <div className="flex flex-col">
                <span className="font-mono text-base font-bold tracking-wider text-slate-100">
                  BLINDSPOT
                </span>
                <span className="font-mono text-[10px] font-semibold tracking-widest text-[#7DB7E8] -mt-1">
                  ECDAT
                </span>
              </div>
            ) : null}
          </Link>

          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="rounded p-1 text-slate-400 hover:bg-[#151C24] hover:text-white"
            title={sidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'}
          >
            <Icon name={sidebarOpen ? 'chevron-right' : 'menu'} size={18} />
          </button>
        </div>

        {/* Sidebar Nav */}
        <div className="flex-1 overflow-y-auto px-3 py-6 space-y-1">
          <div className="mb-2 px-3 text-[11px] font-mono font-semibold uppercase tracking-wider text-slate-500">
            {sidebarOpen ? 'Navigation' : '•••'}
          </div>

          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-lg px-3 py-2.5 text-xs font-medium transition-colors ${
                  isActive
                    ? 'border border-[#7DB7E8]/40 bg-[#7DB7E8]/10 text-[#7DB7E8]'
                    : 'text-slate-400 hover:bg-[#151C24] hover:text-slate-200'
                }`
              }
            >
              <Icon name={item.icon} size={18} className="shrink-0" />
              {sidebarOpen ? (
                <div className="flex flex-1 items-center justify-between">
                  <span>{item.label}</span>
                  {item.badge ? (
                    <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
                      {item.badge}
                    </span>
                  ) : null}
                </div>
              ) : null}
            </NavLink>
          ))}
        </div>

        {/* Sidebar Footer / Return to Landing */}
        <div className="border-t border-[#222B35] p-3">
          <Link
            to="/"
            className="flex items-center gap-3 rounded-lg px-3 py-2 text-xs text-slate-400 transition-colors hover:bg-[#151C24] hover:text-white"
          >
            <Icon name="external-link" size={16} />
            {sidebarOpen ? <span>Landing Page</span> : null}
          </Link>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className={`flex flex-1 flex-col transition-all duration-300 ${sidebarOpen ? 'pl-64' : 'pl-20'}`}>
        {/* Top Header */}
        <header className="sticky top-0 z-30 flex h-16 items-center justify-between border-b border-[#222B35] bg-[#080B0F]/90 px-6 backdrop-blur-md">
          {/* Project Breadcrumb */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 rounded-lg border border-[#222B35] bg-[#11171E] px-3 py-1.5 font-mono text-xs text-slate-300">
              <Icon name="layers" size={14} className="text-[#7DB7E8]" />
              <span className="text-slate-400">Project:</span>
              <span className="font-semibold text-slate-100">demo-repo</span>
            </div>
          </div>

          {/* Topbar Actions */}
          <div className="flex items-center gap-4">
            <BackendStatus />

            <button
              type="button"
              onClick={() => void downloadCbom()}
              className="flex items-center gap-1.5 rounded-lg border border-[#7DB7E8]/40 bg-[#7DB7E8]/10 px-3 py-1.5 font-mono text-xs font-semibold text-[#7DB7E8] transition-colors hover:bg-[#7DB7E8]/20"
            >
              <Icon name="download" size={14} />
              <span>Export CBOM</span>
            </button>

            <button
              onClick={() => navigate('/login')}
              className="flex items-center gap-2 rounded-lg border border-[#222B35] bg-[#11171E] px-3 py-1.5 text-xs text-slate-300 transition-colors hover:border-slate-700 hover:text-white"
            >
              <Icon name="logout" size={14} />
              <span>Session</span>
            </button>
          </div>
        </header>

        {/* Page Content Body */}
        <main className="flex-1 p-6 lg:p-8 max-w-7xl mx-auto w-full">{children}</main>

        {/* Application Footer */}
        <footer className="border-t border-[#222B35] bg-[#0C1117] px-6 py-4 text-xs text-slate-400">
          <div className="flex flex-wrap items-center justify-between gap-2 max-w-7xl mx-auto">
            <span>Blindspot ECDAT v1.0.0 — Enterprise Cryptographic Discovery & Analysis Tool</span>
            <span className="font-mono text-[11px] text-slate-400">
              "You cannot migrate cryptography you cannot find."
            </span>
          </div>
        </footer>
      </div>
    </div>
  );
}
