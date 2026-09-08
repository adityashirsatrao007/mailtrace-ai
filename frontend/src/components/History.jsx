import { useState, useEffect } from 'react'
import { Search, Download, Filter } from 'lucide-react'

const LC = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' }

export default function History() {
  const [stats, setStats] = useState(null)
  const [search, setSearch] = useState('')
  useEffect(() => { fetch('/api/v1/dashboard').then(r => r.json()).then(setStats).catch(() => {}) }, [])
  const scans = (stats?.recent_scans || []).filter(s => !search || s.subject?.toLowerCase().includes(search.toLowerCase()) || s.from?.toLowerCase().includes(search.toLowerCase()))

  return (
    <div className="max-w-[1080px] mx-auto px-10 py-12">
      <div className="mb-10"><h1 className="font-bold tracking-tight" style={{ fontSize: 'var(--text-4xl)' }}>History</h1><p className="mt-2" style={{ color: 'var(--color-text-muted)', fontSize: 'var(--text-sm)' }}>{stats?.total_scans || 0} scans recorded</p></div>

      <div className="flex items-center gap-3 mb-6">
        <div className="relative flex-1"><Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: 'var(--color-text-muted)' }} /><input type="text" placeholder="Search by subject or sender..." value={search} onChange={(e) => setSearch(e.target.value)} className="input input-with-icon" /></div>
        <button className="btn"><Filter size={12} /> Filter</button>
        <button className="btn"><Download size={12} /> Export</button>
      </div>

      <div className="table-wrap">
        <table className="table">
          <thead><tr><th>Subject</th><th>From</th><th>Classification</th><th>Level</th><th className="text-right">Score</th></tr></thead>
          <tbody>{scans.map((s, i) => <tr key={i} className="data-row"><td className="max-w-[240px] truncate font-medium" style={{ color: 'var(--color-text)' }}>{s.subject}</td><td className="max-w-[180px] truncate font-mono text-xs">{s.from}</td><td className="text-xs capitalize">{(s.class || '').replace(/_/g, ' ')}</td><td><span className={`level-badge ${LC[s.threat_level]}`}><span className={`level-dot ${LC[s.threat_level]}`} />{s.threat_level}</span></td><td className="text-right font-mono text-xs">{s.score?.toFixed(0)}%</td></tr>)}
          {scans.length === 0 && <tr><td colSpan={5} className="text-center py-12 text-xs" style={{ color: 'var(--color-text-muted)' }}>No scans found</td></tr>}</tbody>
        </table>
      </div>
    </div>
  )
}
