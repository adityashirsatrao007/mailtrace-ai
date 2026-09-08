import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { MapContainer, TileLayer, CircleMarker, Popup } from 'react-leaflet'
import 'leaflet/dist/leaflet.css'
import { PieChart, Pie, Cell, RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis, ResponsiveContainer, Tooltip } from 'recharts'
import { Download, ThumbsUp, ThumbsDown, ArrowLeft, AlertTriangle, Shield, Globe, Link2, Route, MessageSquare, Search } from 'lucide-react'

const LC = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' }
const LCOL = { CRITICAL: '#dc2626', HIGH: '#ea580c', MEDIUM: '#d97706', LOW: '#16a34a' }
const PIE = ['#0a0a0a', '#525252', '#a3a3a3', '#d4d4d4', '#e5e5e5']

function Sec({ title, icon: Icon, children }) {
  return <div className="section">{title && <div className="section-title flex items-center gap-2">{Icon && <Icon size={11} strokeWidth={2.5} />}{title}</div>}{children}</div>
}

function F({ label, value, mono, color }) {
  return <div><div className="text-[10px] font-medium uppercase tracking-[0.1em] mb-1" style={{ color: 'var(--color-text-muted)' }}>{label}</div><div className={`text-sm ${mono ? 'font-mono' : ''}`} style={{ color: color || 'var(--color-text)' }}>{value || '—'}</div></div>
}

function Auth({ label, result }) {
  const ok = result?.toLowerCase() === 'pass'
  return <div className="flex items-center gap-3 text-xs"><span className="font-medium w-14 uppercase tracking-wider text-[10px]" style={{ color: 'var(--color-text-muted)' }}>{label}</span><span style={{ color: ok ? 'var(--color-success)' : 'var(--color-danger)' }}>{result || '—'}</span></div>
}

export default function Analysis() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [fb, setFb] = useState(null)
  const nav = useNavigate()

  useEffect(() => { const s = sessionStorage.getItem('lastAnalysis'); if (s) { setData(JSON.parse(s)); setLoading(false) } else nav('/') }, [nav])

  const feedback = async (v) => { if (!data) return; setFb(v); try { await fetch('/api/v1/feedback', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ report_id: data.report_id, threat_score: data.threat_score, verdict: v }) }) } catch {} }

  const exportPDF = async () => { if (!data) return; try { const r = await fetch('/api/v1/export/pdf', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ report_id: data.report_id, ...data }) }); if (!r.ok) throw 0; const b = await r.blob(); const u = URL.createObjectURL(b); const a = document.createElement('a'); a.href = u; a.download = `MailTrace-${data.report_id}.pdf`; a.click(); URL.revokeObjectURL(u) } catch { alert('Export failed.') } }

  if (loading || !data) return <div className="max-w-[1080px] mx-auto px-10 py-12"><div className="space-y-4"><div className="skeleton h-10 w-48" /><div className="skeleton h-4 w-64" /><div className="grid grid-cols-3 gap-6 mt-12">{Array.from({ length: 6 }).map((_, i) => <div key={i} className="skeleton h-28" />)}</div></div></div>

  const lc = LC[data.threat_level] || 'low'
  const lang = data.language || {}; const orig = data.origin || {}; const dom = data.domain || {}; const au = data.authentication || {}

  const radar = [
    { subject: 'Urgency', A: (lang.urgency_score || 0) * 100 },
    { subject: 'Fear', A: (lang.fear_score || 0) * 100 },
    { subject: 'Greed', A: (lang.greed_score || 0) * 100 },
    { subject: 'Authority', A: (lang.authority_score || 0) * 100 },
    { subject: 'Sentiment', A: Math.abs(lang.sentiment_score || 0) * 100 },
  ]

  const pie = [{ name: 'Headers', value: 30 }, { name: 'Body', value: 40 }, { name: 'Links', value: lang.url_count || 0 }, { name: 'Attachments', value: 10 }, { name: 'Metadata', value: 20 }].filter(d => d.value > 0)

  return (
    <div className="max-w-[1080px] mx-auto px-10 py-12">
      <div className="flex items-center justify-between mb-8">
        <button onClick={() => nav('/')} className="btn btn-ghost text-xs"><ArrowLeft size={13} /> Dashboard</button>
        <button onClick={exportPDF} className="btn text-xs"><Download size={12} /> Export PDF</button>
      </div>

      {/* Threat Header — Swiss: oversized type, asymmetric layout */}
      <div className="mb-12">
        <div className="flex items-start justify-between">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-3 mb-3">
              <span className={`level-badge ${lc}`}>{data.threat_level}</span>
              <span className="text-xs font-mono" style={{ color: 'var(--color-text-muted)' }}>{data.report_id?.slice(0, 8)}</span>
            </div>
            <h1 className="font-bold tracking-tight mb-2 truncate" style={{ fontSize: 'var(--text-2xl)' }}>{data.email?.subject || 'No subject'}</h1>
            <div className="flex items-center gap-4 text-xs" style={{ color: 'var(--color-text-muted)' }}>
              <span>From <span className="font-mono" style={{ color: 'var(--color-text-secondary)' }}>{data.email?.from}</span></span>
              <span>To <span className="font-mono" style={{ color: 'var(--color-text-secondary)' }}>{data.email?.to}</span></span>
            </div>
          </div>
          <div className="text-right ml-10">
            <div className="stat-value" style={{ color: LCOL[data.threat_level] }}>{data.threat_score?.toFixed(0)}%</div>
            <div className="text-[10px] font-semibold uppercase tracking-[0.12em] mt-2" style={{ color: 'var(--color-text-muted)' }}>Threat Score</div>
          </div>
        </div>
      </div>

      {/* AI Narrative — Swiss: clean divider, generous padding */}
      {data.ai_narrative && (
        <div className="mb-12">
          <div className="section-title flex items-center gap-2"><Shield size={11} strokeWidth={2.5} />AI Analysis</div>
          <p className="leading-relaxed max-w-[720px]" style={{ color: 'var(--color-text-secondary)', fontSize: 'var(--text-base)' }}>{data.ai_narrative}</p>
        </div>
      )}

      <hr className="sep mb-0" />

      {/* 2-col — Swiss: grid, generous gap, no cards */}
      <div className="grid grid-cols-3 gap-10">
        <div className="col-span-2 space-y-0">
          <Sec title="Authentication & Origin" icon={Shield}>
            <div className="grid grid-cols-2 gap-8">
              <div className="space-y-2.5"><Auth label="SPF" result={au.spf} /><Auth label="DKIM" result={au.dkim} /><Auth label="DMARC" result={au.dmarc} /></div>
              <div className="space-y-2.5"><F label="Origin IP" value={orig.ip} mono /><F label="Location" value={[orig.city, orig.country].filter(Boolean).join(', ')} /><F label="ISP" value={orig.isp} /><div className="flex gap-2">{orig.is_vpn && <span className="badge">VPN</span>}{orig.is_tor && <span className="badge">TOR</span>}</div></div>
            </div>
          </Sec>

          {data.iocs?.length > 0 && (
            <Sec title="Indicators of Compromise" icon={Search}>
              <div className="table-wrap"><table className="table"><thead><tr><th>Type</th><th>Value</th><th>Context</th><th className="text-right">Confidence</th></tr></thead><tbody>{data.iocs.map((i, k) => <tr key={k} className="data-row"><td><span className="badge">{i.type}</span></td><td className="font-mono text-xs max-w-[220px] truncate">{i.value}</td><td className="text-xs">{i.context}</td><td className="text-right font-mono text-xs">{(i.confidence * 100).toFixed(0)}%</td></tr>)}</tbody></table></div>
            </Sec>
          )}

          {data.relay_path?.length > 0 && (
            <Sec title="Relay Path" icon={Route}>
              <div className="relative pl-6">
                <div className="absolute left-[11px] top-2 bottom-2 w-px" style={{ background: 'var(--color-border)' }} />
                {data.relay_path.map((h, i) => (
                  <div key={i} className="relative flex items-start gap-4 pb-4 last:pb-0">
                    <div className="relative z-10 w-2.5 h-2.5 rounded-full mt-1.5 flex-shrink-0" style={{ background: h.is_vpn ? 'var(--color-warning)' : h.is_tor ? 'var(--color-danger)' : 'var(--color-text)' }} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5"><span className="text-xs font-mono" style={{ color: 'var(--color-text)' }}>{h.ip || '—'}</span>{h.country && <span className="text-[10px]" style={{ color: 'var(--color-text-muted)' }}>{h.country}</span>}{h.is_vpn && <span className="badge text-[9px]">VPN</span>}{h.is_tor && <span className="badge text-[9px]">TOR</span>}</div>
                      <div className="text-[11px]" style={{ color: 'var(--color-text-muted)' }}>{h.from && <span>from {h.from}</span>}{h.asn && <span> · {h.asn}</span>}</div>
                    </div>
                  </div>
                ))}
              </div>
            </Sec>
          )}

          <Sec title="Language Analysis" icon={MessageSquare}>
            <div className="grid grid-cols-2 gap-8">
              <div>
                <div className="text-xs mb-3" style={{ color: 'var(--color-text-muted)' }}>Template: <span className="font-medium capitalize" style={{ color: 'var(--color-text-secondary)' }}>{(lang.template_type || '—').replace(/_/g, ' ')}</span></div>
                <div className="space-y-3">
                  {[{ l: 'Urgency', v: lang.urgency_score }, { l: 'Fear', v: lang.fear_score }, { l: 'Greed', v: lang.greed_score }, { l: 'Authority', v: lang.authority_score }].filter(m => m.v != null).map(m => (
                    <div key={m.l}><div className="flex items-center justify-between mb-1"><span className="text-[11px]" style={{ color: 'var(--color-text-muted)' }}>{m.l}</span><span className="text-[11px] font-mono" style={{ color: 'var(--color-text-muted)' }}>{(m.v * 100).toFixed(0)}%</span></div><div className="progress"><div className="progress-fill" style={{ width: `${m.v * 100}%` }} /></div></div>
                  ))}
                </div>
              </div>
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4"><F label="Sentiment" value={`${lang.sentiment || '—'} (${((lang.sentiment_score || 0) * 100).toFixed(0)}%)`} /><F label="Reading Level" value={lang.reading_level} /><F label="Caps Ratio" value={lang.caps_ratio ? `${(lang.caps_ratio * 100).toFixed(0)}%` : '—'} /><F label="Exclamations" value={lang.exclamation_count ?? '—'} /></div>
                {lang.social_engineering_tactics?.length > 0 && <div><div className="text-[10px] font-semibold uppercase tracking-[0.1em] mb-1.5" style={{ color: 'var(--color-text-muted)' }}>Tactics</div><div className="flex flex-wrap gap-1.5">{lang.social_engineering_tactics.map(t => <span key={t} className="badge text-[10px]">{t}</span>)}</div></div>}
                {lang.red_flag_phrases?.length > 0 && <div><div className="text-[10px] font-semibold uppercase tracking-[0.1em] mb-1.5" style={{ color: 'var(--color-text-muted)' }}>Red Flags</div><div className="flex flex-wrap gap-1.5">{lang.red_flag_phrases.map((p, i) => <span key={i} className="badge text-[10px]" style={{ color: 'var(--color-danger)', borderColor: 'var(--color-danger)' }}>{p}</span>)}</div></div>}
              </div>
            </div>
          </Sec>

          <Sec title="Domain Intelligence" icon={Globe}>
            <div className="grid grid-cols-2 gap-8">
              <div className="space-y-2.5"><F label="Domain Age" value={dom.age_days != null ? `${dom.age_days} days` : '—'} /><F label="Registrar" value={dom.registrar} /><F label="Suspicious" value={dom.is_suspicious ? 'Yes' : 'No'} color={dom.is_suspicious ? 'var(--color-danger)' : 'var(--color-success)'} /></div>
              <div className="space-y-3">
                {data.lookalike?.is_lookalike && <div className="p-4" style={{ background: 'var(--color-surface)' }}><div className="text-xs font-semibold mb-1.5 flex items-center gap-1.5" style={{ color: 'var(--color-danger)' }}><AlertTriangle size={11} /> Lookalike Detected</div><div className="text-[11px] space-y-0.5" style={{ color: 'var(--color-text-secondary)' }}><div>Target: <span className="font-mono">{data.lookalike.target_domain}</span></div><div>Technique: <span className="capitalize">{data.lookalike.technique?.replace(/_/g, ' ')}</span></div><div>Confidence: <span className="font-mono">{(data.lookalike.confidence * 100).toFixed(0)}%</span></div></div></div>}
                {data.display_spoof?.is_spoofed && <div className="p-4" style={{ background: 'var(--color-surface)' }}><div className="text-xs font-semibold mb-1.5 flex items-center gap-1.5" style={{ color: 'var(--color-warning)' }}><AlertTriangle size={11} /> Display Spoofing</div><div className="text-[11px] space-y-0.5" style={{ color: 'var(--color-text-secondary)' }}><div>Display: <span className="font-mono">{data.display_spoof.display_name}</span></div><div>Actual: <span className="font-mono">{data.display_spoof.envelope_sender}</span></div></div></div>}
              </div>
            </div>
          </Sec>

          {data.url_traces?.length > 0 && (
            <Sec title="URL Redirect Tracing" icon={Link2}>
              <div className="space-y-2">{data.url_traces.map((t, i) => <div key={i} className="p-3" style={{ background: t.is_suspicious ? 'var(--color-surface)' : 'var(--color-bg)', border: `1px solid ${t.is_suspicious ? 'var(--color-danger)' : 'var(--color-border)'}` }}><div className="flex items-center gap-2 mb-0.5"><span className="text-xs font-mono truncate max-w-[280px]" style={{ color: 'var(--color-text)' }}>{t.original}</span>{t.is_suspicious && <span className="badge text-[9px]" style={{ color: 'var(--color-danger)', borderColor: 'var(--color-danger)' }}>Suspicious</span>}</div><div className="text-[11px]" style={{ color: 'var(--color-text-muted)' }}>Redirects: <span className="font-mono">{t.redirects}</span>{t.url_shortener && <span className="ml-2 badge text-[9px]">Shortener</span>}</div></div>)}</div>
            </Sec>
          )}
        </div>

        {/* Right column */}
        <div className="space-y-0">
          <Sec title="Model Confidence" icon={Shield}>
            <div className="h-[180px]"><ResponsiveContainer width="100%" height="100%"><RadarChart data={radar} cx="50%" cy="50%" outerRadius="65%"><PolarGrid stroke="var(--color-border)" /><PolarAngleAxis dataKey="subject" tick={{ fontSize: 10, fill: '#a3a3a3' }} /><PolarRadiusAxis tick={false} axisLine={false} domain={[0, 100]} /><Radar name="A" dataKey="A" stroke="#0a0a0a" fill="#0a0a0a" fillOpacity={0.06} strokeWidth={1.5} /></RadarChart></ResponsiveContainer></div>
          </Sec>

          <Sec title="Email Components">
            <div className="h-[160px]"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={pie} cx="50%" cy="50%" innerRadius={38} outerRadius={60} dataKey="value" paddingAngle={2}>{pie.map((_, i) => <Cell key={i} fill={PIE[i % PIE.length]} />)}</Pie><Tooltip contentStyle={{ background: '#fff', border: '1px solid var(--color-border)', fontSize: 11 }} /></PieChart></ResponsiveContainer></div>
            <div className="flex flex-wrap gap-3 mt-2">{pie.map((d, i) => <div key={d.name} className="flex items-center gap-1.5 text-[10px]" style={{ color: 'var(--color-text-muted)' }}><span className="w-2.5 h-2.5" style={{ background: PIE[i % PIE.length] }} />{d.name}</div>)}</div>
          </Sec>

          {orig.latitude != null && orig.latitude !== 0 && (
            <Sec title="Origin" icon={Globe}>
              <div className="overflow-hidden" style={{ height: 170, border: '1px solid var(--color-border)' }}>
                <MapContainer center={[orig.latitude, orig.longitude]} zoom={3} style={{ height: '100%', width: '100%', background: '#f8f8f8' }}><TileLayer url="https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png" /><CircleMarker center={[orig.latitude, orig.longitude]} radius={5} fillColor="#0a0a0a" fillOpacity={0.8} color="#fff" weight={1}><Popup><span className="text-xs">{orig.ip} — {orig.city}, {orig.country}</span></Popup></CircleMarker></MapContainer>
              </div>
            </Sec>
          )}

          {data.graph?.nodes?.length > 0 && <Sec title="Relationship Graph"><div className="space-y-1.5">{data.graph.nodes.map((n, i) => <div key={i} className="flex items-center gap-2 text-xs"><span className={`level-dot ${n.type === 'malicious' ? 'critical' : n.type === 'suspicious' ? 'medium' : 'low'}`} /><span className="font-mono truncate" style={{ color: 'var(--color-text-secondary)' }}>{n.id || n.label}</span><span className="ml-auto" style={{ color: 'var(--color-text-muted)' }}>{n.type}</span></div>)}</div></Sec>}

          {data.anomalies?.length > 0 && <Sec title="Anomalies" icon={AlertTriangle}><div className="space-y-1.5">{data.anomalies.map((a, i) => <div key={i} className="flex items-start gap-2 text-xs"><AlertTriangle size={11} className="mt-0.5 flex-shrink-0" style={{ color: 'var(--color-warning)' }} /><span style={{ color: 'var(--color-text-secondary)' }}>{typeof a === 'string' ? a : a.description || JSON.stringify(a)}</span></div>)}</div></Sec>}

          {data.recommendations?.length > 0 && <Sec title="Recommendations" icon={Shield}><div className="space-y-2">{data.recommendations.map((r, i) => <div key={i} className="text-xs leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>{r}</div>)}</div></Sec>}

          <Sec title="Feedback">
            <div className="flex gap-2.5">
              <button onClick={() => feedback('correct')} disabled={fb !== null} className={`btn text-xs ${fb === 'correct' ? 'btn-primary' : ''}`}><ThumbsUp size={12} /> Correct</button>
              <button onClick={() => feedback('incorrect')} disabled={fb !== null} className={`btn text-xs ${fb === 'incorrect' ? 'btn-danger' : ''}`}><ThumbsDown size={12} /> Incorrect</button>
            </div>
            {fb && <p className="text-[11px] mt-2" style={{ color: 'var(--color-text-muted)' }}>Thank you for your feedback.</p>}
          </Sec>
        </div>
      </div>
    </div>
  )
}
