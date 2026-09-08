import { useState } from 'react'
import { GitCompare, Plus, Trash2, AlertTriangle, Shield } from 'lucide-react'

const LCOL = { CRITICAL: '#dc2626', HIGH: '#ea580c', MEDIUM: '#d97706', LOW: '#16a34a' }

export default function Compare() {
  const [emails, setEmails] = useState(['', ''])
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  const add = () => { if (emails.length < 5) setEmails([...emails, '']) }
  const rm = (i) => { if (emails.length > 2) setEmails(emails.filter((_, idx) => idx !== i)) }
  const upd = (i, v) => { const n = [...emails]; n[i] = v; setEmails(n) }

  const run = async () => { setLoading(true); try { const r = await fetch('/api/v1/compare', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ emails }) }); setResult(await r.json()) } catch { alert('Failed.') } setLoading(false) }

  return (
    <div className="max-w-[1080px] mx-auto px-10 py-12">
      <div className="mb-10"><h1 className="font-bold tracking-tight" style={{ fontSize: 'var(--text-4xl)' }}>Compare</h1><p className="mt-2" style={{ color: 'var(--color-text-muted)', fontSize: 'var(--text-sm)' }}>Compare up to 5 emails for coordinated attacks</p></div>

      <div className="space-y-2 mb-4">{emails.map((em, i) => <div key={i} className="flex gap-2"><input type="text" placeholder={`Email ${i + 1} — paste headers or body...`} value={em} onChange={(e) => upd(i, e.target.value)} className="input flex-1" />{emails.length > 2 && <button onClick={() => rm(i)} className="btn btn-ghost px-2"><Trash2 size={13} /></button>}</div>)}</div>

      <div className="flex items-center gap-3 mb-10">{emails.length < 5 && <button onClick={add} className="btn"><Plus size={12} /> Add Email</button>}<button onClick={run} disabled={loading || emails.some(e => !e.trim())} className="btn-primary">{loading ? <><span className="spinner" /> Analyzing...</> : <><GitCompare size={12} /> Compare</>}</button></div>

      {result && (
        <div className="space-y-8">
          <div>
            <div className="section-title">Summary</div>
            <div className="grid grid-cols-3 gap-8">
              <div><div className="text-[10px] font-semibold uppercase tracking-[0.1em] mb-1.5" style={{ color: 'var(--color-text-muted)' }}>Avg Threat Score</div><div className="stat-value" style={{ color: result.summary.avg_score > 50 ? 'var(--color-danger)' : result.summary.avg_score > 30 ? 'var(--color-warning)' : 'var(--color-success)' }}>{result.summary.avg_score?.toFixed(0)}%</div></div>
              <div><div className="text-[10px] font-semibold uppercase tracking-[0.1em] mb-1.5" style={{ color: 'var(--color-text-muted)' }}>Coordinated</div><div className="flex items-center gap-2 mt-1">{result.summary.is_coordinated ? <AlertTriangle size={15} style={{ color: 'var(--color-danger)' }} /> : <Shield size={15} style={{ color: 'var(--color-success)' }} />}<span className="text-sm font-semibold">{result.summary.is_coordinated ? 'YES' : 'NO'}</span></div></div>
              <div><div className="text-[10px] font-semibold uppercase tracking-[0.1em] mb-1.5" style={{ color: 'var(--color-text-muted)' }}>Common Tactics</div><div className="flex flex-wrap gap-1.5 mt-1">{result.summary.common_tactics?.length > 0 ? result.summary.common_tactics.map(t => <span key={t} className="badge text-[10px]">{t}</span>) : <span className="text-xs" style={{ color: 'var(--color-text-muted)' }}>None</span>}</div></div>
            </div>
            {result.summary.common_ips?.length > 0 && <div className="mt-3 text-xs" style={{ color: 'var(--color-text-muted)' }}>Common IPs: <span className="font-mono" style={{ color: 'var(--color-danger)' }}>{result.summary.common_ips.join(', ')}</span></div>}
          </div>

          <hr className="sep" />

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">{result.individual_results?.map((r, i) => { const tc = LCOL[r.threat_level] || LCOL.LOW; return (
            <div key={i} className="p-5" style={{ border: '1px solid var(--color-border)' }}>
              <div className="flex items-center justify-between mb-3"><span className="text-[11px] font-medium uppercase tracking-wider" style={{ color: 'var(--color-text-muted)' }}>Email #{i + 1}</span><span className="text-xs font-semibold" style={{ color: tc }}>{r.threat_level}</span></div>
              <div className="font-semibold truncate mb-0.5" style={{ fontSize: 'var(--text-base)' }}>{r.email?.subject || 'No subject'}</div>
              <div className="text-xs truncate mb-3" style={{ color: 'var(--color-text-muted)' }}>{r.email?.from}</div>
              <div className="grid grid-cols-3 gap-3 text-xs"><div><div className="text-[10px] uppercase tracking-wider mb-0.5" style={{ color: 'var(--color-text-muted)' }}>Score</div><div className="font-mono" style={{ color: 'var(--color-text-secondary)' }}>{r.threat_score?.toFixed(0)}%</div></div><div><div className="text-[10px] uppercase tracking-wider mb-0.5" style={{ color: 'var(--color-text-muted)' }}>Class</div><div className="font-mono capitalize" style={{ color: 'var(--color-text-secondary)' }}>{(r.classification || '').replace(/_/g, ' ')}</div></div><div><div className="text-[10px] uppercase tracking-wider mb-0.5" style={{ color: 'var(--color-text-muted)' }}>Template</div><div className="font-mono capitalize" style={{ color: 'var(--color-text-secondary)' }}>{(r.language?.template_type || '').replace(/_/g, ' ')}</div></div></div>
              {r.language?.social_engineering_tactics?.length > 0 && <div className="mt-3 flex flex-wrap gap-1">{r.language.social_engineering_tactics.map(t => <span key={t} className="badge text-[9px]">{t}</span>)}</div>}
            </div>
          )})}</div>
        </div>
      )}
    </div>
  )
}
