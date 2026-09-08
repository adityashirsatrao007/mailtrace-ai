import { useState, useEffect } from 'react'
import { MapContainer, TileLayer, CircleMarker, Popup } from 'react-leaflet'
import 'leaflet/dist/leaflet.css'
import { AlertTriangle, Shield, Globe } from 'lucide-react'

const LC = { CRITICAL: '#dc2626', HIGH: '#ea580c', MEDIUM: '#d97706', LOW: '#16a34a' }

export default function ThreatMap() {
  const [stats, setStats] = useState(null)
  useEffect(() => { fetch('/api/v1/dashboard').then(r => r.json()).then(setStats).catch(() => {}) }, [])
  const t = stats?.recent_scans || []

  return (
    <div className="max-w-[1080px] mx-auto px-10 py-12">
      <div className="flex items-end justify-between mb-10">
        <div><h1 className="font-bold tracking-tight" style={{ fontSize: 'var(--text-4xl)' }}>Threat Map</h1><p className="mt-2" style={{ color: 'var(--color-text-muted)', fontSize: 'var(--text-sm)' }}>Global email threat origins</p></div>
        <div className="flex items-center gap-4 text-[11px] font-medium" style={{ color: 'var(--color-text-muted)' }}>{Object.entries(LC).map(([l, c]) => <div key={l} className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full" style={{ background: c }} />{l[0] + l.slice(1).toLowerCase()}</div>)}</div>
      </div>

      {!stats ? <div className="skeleton" style={{ height: 440 }} /> : (
        <div className="mb-10" style={{ height: 440, border: '1px solid var(--color-border)' }}>
          <MapContainer center={[20, 0]} zoom={2} style={{ height: '100%', width: '100%', background: '#f8f8f8' }}><TileLayer url="https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png" />{t.map((s, i) => <CircleMarker key={i} center={[20 + Math.sin(i * 1.3) * 30, -30 + Math.cos(i * 0.9) * 50]} radius={s.threat_level === 'CRITICAL' ? 7 : s.threat_level === 'HIGH' ? 5 : 3} fillColor={LC[s.threat_level] || LC.LOW} fillOpacity={0.8} color="#fff" weight={1}><Popup><div className="text-xs"><div className="font-medium">{s.from}</div><div style={{ color: 'var(--color-text-muted)' }}>{s.subject}</div></div></Popup></CircleMarker>)}</MapContainer>
        </div>
      )}

      <div className="grid grid-cols-3 gap-px" style={{ background: 'var(--color-border)' }}>
        {[{ l: 'Active Threats', v: stats?.critical_threats || 0, icon: AlertTriangle, c: 'var(--color-danger)' }, { l: 'Blocked', v: stats?.phishing_detected || 0, icon: Shield, c: 'var(--color-success)' }, { l: 'Domains', v: stats?.top_threat_domains?.length || 0, icon: Globe }].map((s, i) => (
          <div key={i} className="kpi" style={{ background: 'var(--color-bg)' }}><div className="flex items-center gap-2 mb-2"><s.icon size={13} strokeWidth={2} style={{ color: 'var(--color-text-muted)' }} /><span className="kpi-label mb-0">{s.l}</span></div><div className="kpi-value" style={s.c ? { color: s.c } : {}}>{s.v}</div></div>
        ))}
      </div>
    </div>
  )
}
