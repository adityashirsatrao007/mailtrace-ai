import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { Upload, FileText, AlertTriangle, Shield, Globe, ArrowRight } from 'lucide-react'

const LC = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' }

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [dragActive, setDragActive] = useState(false)
  const [uploading, setUploading] = useState(false)
  const fileRef = useRef(null)
  const navigate = useNavigate()

  useEffect(() => { fetch('/api/v1/dashboard').then(r => r.json()).then(setStats).catch(() => {}) }, [])

  const handleUpload = async (file) => {
    if (!file) return
    setUploading(true)
    try {
      const fd = new FormData(); fd.append('file', file)
      const data = await fetch('/api/v1/analyze', { method: 'POST', body: fd }).then(r => r.json())
      sessionStorage.setItem('lastAnalysis', JSON.stringify(data))
      navigate('/analyze')
    } catch { alert('Analysis failed.') }
    setUploading(false)
  }

  const handleQuick = async (name) => {
    setUploading(true)
    try {
      const sample = await fetch(`/api/v1/sample/${name}`).then(r => r.json())
      const fd = new FormData()
      fd.append('file', new Blob([sample.raw_email], { type: 'message/rfc822' }), name)
      const data = await fetch('/api/v1/analyze', { method: 'POST', body: fd }).then(r => r.json())
      sessionStorage.setItem('lastAnalysis', JSON.stringify(data))
      navigate('/analyze')
    } catch { alert('Quick analysis failed.') }
    setUploading(false)
  }

  return (
    <div className="max-w-[1080px] mx-auto px-10 py-12">
      {/* Header — Swiss: large type, generous whitespace */}
      <div className="flex items-end justify-between mb-12">
        <div>
          <h1 className="font-bold tracking-tight" style={{ fontSize: 'var(--text-4xl)' }}>Dashboard</h1>
          <p className="mt-2" style={{ color: 'var(--color-text-muted)', fontSize: 'var(--text-sm)' }}>Email threat monitoring overview</p>
        </div>
        {stats && (
          <div className="flex items-center gap-2 text-xs font-medium" style={{ color: 'var(--color-success)' }}>
            <span className="w-2 h-2 rounded-full" style={{ background: 'var(--color-success)' }} />
            Live
          </div>
        )}
      </div>

      {/* KPI — Swiss: bold numbers, no decoration */}
      <div className="grid grid-cols-4 gap-px mb-12" style={{ background: 'var(--color-border)' }}>
        {stats ? [
          { label: 'Total Scans', value: stats.total_scans, icon: FileText },
          { label: 'Critical', value: stats.critical_threats, icon: AlertTriangle, color: 'var(--color-danger)' },
          { label: 'Phishing', value: stats.phishing_detected, icon: Shield, color: 'var(--color-warning)' },
          { label: 'Domains', value: stats.top_threat_domains?.length || 0, icon: Globe },
        ].map((k, i) => (
          <div key={i} className="kpi" style={{ background: 'var(--color-bg)' }}>
            <div className="flex items-center gap-2 mb-2">
              <k.icon size={13} strokeWidth={2} style={{ color: 'var(--color-text-muted)' }} />
              <span className="kpi-label mb-0">{k.label}</span>
            </div>
            <div className="kpi-value" style={k.color ? { color: k.color } : {}}>{k.value}</div>
          </div>
        )) : Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="kpi" style={{ background: 'var(--color-bg)' }}><div className="skeleton h-3 w-16 mb-3" /><div className="skeleton h-8 w-14" /></div>
        ))}
      </div>

      {/* Upload + Quick — Swiss: clean boxes, no shadows */}
      <div className="grid grid-cols-3 gap-8 mb-12">
        <div className="col-span-2">
          <div
            className="p-12 text-center cursor-pointer transition-colors duration-100"
            style={{
              background: 'var(--color-bg)',
              border: `2px dashed ${dragActive ? 'var(--color-text)' : 'var(--color-border)'}`,
            }}
            onClick={() => fileRef.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDragActive(true) }}
            onDragLeave={() => setDragActive(false)}
            onDrop={(e) => { e.preventDefault(); setDragActive(false); handleUpload(e.dataTransfer.files[0]) }}
          >
            <input ref={fileRef} type="file" className="hidden" accept=".eml,.msg,.txt" onChange={(e) => handleUpload(e.target.files[0])} />
            <Upload size={24} className="mx-auto mb-4" style={{ color: 'var(--color-text-muted)' }} strokeWidth={1.5} />
            <p className="font-semibold mb-1" style={{ fontSize: 'var(--text-base)' }}>
              {uploading ? 'Analyzing...' : 'Drop email file or click to upload'}
            </p>
            <p style={{ color: 'var(--color-text-muted)', fontSize: 'var(--text-sm)' }}>.eml, .msg, or raw email text</p>
          </div>
        </div>

        <div>
          <div className="section-title">Quick Analysis</div>
          <div className="space-y-2">
            {[
              { name: 'phishing_sample.eml', label: 'Phishing Sample', level: 'CRITICAL' },
              { name: 'bec_attack.eml', label: 'BEC Attack', level: 'HIGH' },
              { name: 'legitimate_email.eml', label: 'Legitimate Email', level: 'LOW' },
            ].map((s) => (
              <button key={s.name} onClick={() => handleQuick(s.name)} disabled={uploading}
                className="w-full flex items-center justify-between px-4 py-3 text-left text-sm border transition-opacity disabled:opacity-30"
                style={{ borderColor: 'var(--color-border)', background: 'var(--color-bg)' }}>
                <span className="flex items-center gap-3">
                  <span className={`level-dot ${LC[s.level]}`} />
                  {s.label}
                </span>
                <ArrowRight size={13} style={{ color: 'var(--color-text-muted)' }} />
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Recent + Domains */}
      <div className="grid grid-cols-3 gap-8">
        <div className="col-span-2">
          <div className="section-title">Recent Scans</div>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr><th>Subject</th><th>From</th><th>Level</th><th className="text-right">Score</th></tr>
              </thead>
              <tbody>
                {stats?.recent_scans?.slice(0, 5).map((s, i) => (
                  <tr key={i} className="data-row">
                    <td className="max-w-[200px] truncate font-medium" style={{ color: 'var(--color-text)' }}>{s.subject}</td>
                    <td className="max-w-[150px] truncate font-mono text-xs">{s.from}</td>
                    <td><span className={`level-badge ${LC[s.threat_level]}`}><span className={`level-dot ${LC[s.threat_level]}`} />{s.threat_level}</span></td>
                    <td className="text-right font-mono text-xs">{s.score?.toFixed(0)}%</td>
                  </tr>
                ))}
                {(!stats?.recent_scans || stats.recent_scans.length === 0) && <tr><td colSpan={4} className="text-center py-10 text-xs" style={{ color: 'var(--color-text-muted)' }}>No scans yet</td></tr>}
              </tbody>
            </table>
          </div>
        </div>

        <div>
          <div className="section-title">Top Threat Domains</div>
          <div className="space-y-4">
            {stats?.top_threat_domains?.slice(0, 5).map((d, i) => {
              const max = stats.top_threat_domains[0]?.confidence || 1
              return (
                <div key={i}>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-mono truncate max-w-[130px]" style={{ color: 'var(--color-text-secondary)' }}>{d.domain}</span>
                    <span className="text-[10px] font-mono" style={{ color: 'var(--color-text-muted)' }}>{d.confidence?.toFixed(0)}%</span>
                  </div>
                  <div className="progress"><div className="progress-fill" style={{ width: `${(d.confidence / max) * 100}%` }} /></div>
                </div>
              )
            })}
            {(!stats?.top_threat_domains || stats.top_threat_domains.length === 0) && <p className="text-xs py-4 text-center" style={{ color: 'var(--color-text-muted)' }}>No domain data</p>}
          </div>
        </div>
      </div>
    </div>
  )
}
