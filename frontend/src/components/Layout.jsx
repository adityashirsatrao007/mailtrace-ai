import { NavLink, Outlet } from 'react-router-dom'
import { LayoutDashboard, ScanLine, Globe, GitCompare, Clock, Settings } from 'lucide-react'

const NAV = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/analyze', icon: ScanLine, label: 'Analyze' },
  { to: '/map', icon: Globe, label: 'Threat Map' },
  { to: '/compare', icon: GitCompare, label: 'Compare' },
  { to: '/history', icon: Clock, label: 'History' },
]

export default function Layout() {
  return (
    <div className="flex h-screen overflow-hidden">
      <aside className="w-[220px] flex-shrink-0 flex flex-col border-r" style={{ borderColor: 'var(--color-border)' }}>
        <div className="px-6 pt-8 pb-6">
          <div className="text-lg font-bold tracking-tight">MailTrace</div>
          <div className="text-[10px] font-medium uppercase tracking-[0.15em] mt-0.5" style={{ color: 'var(--color-text-muted)' }}>Forensics</div>
        </div>

        <nav className="flex-1 px-3 space-y-0.5">
          {NAV.map(({ to, icon: Icon, label }) => (
            <NavLink key={to} to={to} end={to === '/'} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
              <Icon size={16} strokeWidth={1.8} />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="px-3 pb-3">
          <NavLink to="/settings" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <Settings size={16} strokeWidth={1.8} />
            Settings
          </NavLink>
        </div>

        <div className="px-6 py-4 border-t text-[10px] font-mono" style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-muted)' }}>
          v2.0 · SIH 2026
        </div>
      </aside>

      <main className="flex-1 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  )
}
