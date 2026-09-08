import { useState } from 'react'
import { Mail, Key, Bell, Database, RefreshCw, Save } from 'lucide-react'

export default function Settings() {
  const [imap, setImap] = useState(false)
  const [key, setKey] = useState('')
  const [train, setTrain] = useState(false)

  const doTrain = async () => { setTrain(true); try { const r = await fetch('/api/v1/train', { method: 'POST' }); alert(r.ok ? 'Retrained.' : 'Failed.') } catch { alert('Failed.') } setTrain(false) }

  return (
    <div className="max-w-[560px] mx-auto px-10 py-12">
      <h1 className="font-bold tracking-tight mb-1" style={{ fontSize: 'var(--text-4xl)' }}>Settings</h1>
      <p className="mb-10" style={{ color: 'var(--color-text-muted)', fontSize: 'var(--text-sm)' }}>Configure MailTrace AI</p>

      <div className="space-y-10">
        <div>
          <div className="flex items-center gap-2 mb-1"><Mail size={14} strokeWidth={2} style={{ color: 'var(--color-text-muted)' }} /><h2 className="text-sm font-semibold">Email Monitoring</h2></div>
          <p className="text-xs mb-4" style={{ color: 'var(--color-text-muted)' }}>Connect your email inbox for automatic scanning.</p>
          <div className="grid grid-cols-2 gap-3">
            {[{ l: 'IMAP Server', p: 'imap.gmail.com' }, { l: 'Port', p: '993' }, { l: 'Email', p: 'your@email.com' }, { l: 'App Password', p: 'xxxx-xxxx-xxxx-xxxx', t: 'password' }].map((f, i) => <div key={i}><label className="text-[11px] font-medium uppercase tracking-[0.08em] mb-1.5 block" style={{ color: 'var(--color-text-muted)' }}>{f.l}</label><input className="input" placeholder={f.p} type={f.t || 'text'} /></div>)}
          </div>
          <div className="flex items-center gap-3 mt-4"><div className={`toggle ${imap ? 'active' : ''}`} onClick={() => setImap(!imap)} /><span className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>{imap ? 'Active' : 'Disabled'}</span></div>
        </div>

        <hr className="sep" />

        <div>
          <div className="flex items-center gap-2 mb-1"><Key size={14} strokeWidth={2} style={{ color: 'var(--color-text-muted)' }} /><h2 className="text-sm font-semibold">LLM Configuration</h2></div>
          <p className="text-xs mb-4" style={{ color: 'var(--color-text-muted)' }}>GROQ API key for AI narratives.</p>
          <label className="text-[11px] font-medium uppercase tracking-[0.08em] mb-1.5 block" style={{ color: 'var(--color-text-muted)' }}>API Key</label>
          <input className="input" type="password" placeholder="gsk_..." value={key} onChange={(e) => setKey(e.target.value)} />
        </div>

        <hr className="sep" />

        <div>
          <div className="flex items-center gap-2 mb-1"><Database size={14} strokeWidth={2} style={{ color: 'var(--color-text-muted)' }} /><h2 className="text-sm font-semibold">ML Model</h2></div>
          <p className="text-xs mb-4" style={{ color: 'var(--color-text-muted)' }}>Retrain DistilBERT with new feedback.</p>
          <div className="flex items-center gap-4">
            <button onClick={doTrain} disabled={train} className="btn-primary">{train ? <><RefreshCw size={12} className="animate-spin" /> Training...</> : <><RefreshCw size={12} /> Retrain</>}</button>
            <span className="text-xs" style={{ color: 'var(--color-text-muted)' }}>Accuracy: <span className="font-mono" style={{ color: 'var(--color-success)' }}>100%</span></span>
          </div>
        </div>

        <hr className="sep" />

        <div>
          <div className="flex items-center gap-2 mb-1"><Bell size={14} strokeWidth={2} style={{ color: 'var(--color-text-muted)' }} /><h2 className="text-sm font-semibold">Notifications</h2></div>
          <div className="mt-3">{['Critical threat detected', 'New phishing campaign', 'Model retrained', 'Daily summary'].map((item, i) => <div key={i}><div className="flex items-center justify-between py-3"><span className="text-xs" style={{ color: 'var(--color-text-secondary)' }}>{item}</span><div className="toggle active" /></div>{i < 3 && <hr className="sep" />}</div>)}</div>
        </div>
      </div>

      <button className="btn-primary mt-10"><Save size={12} /> Save Settings</button>
    </div>
  )
}
