import { lazy, Suspense } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'

const Dashboard = lazy(() => import('./components/Dashboard'))
const Analysis = lazy(() => import('./components/Analysis'))
const ThreatMap = lazy(() => import('./components/ThreatMap'))
const History = lazy(() => import('./components/History'))
const Settings = lazy(() => import('./components/Settings'))
const Compare = lazy(() => import('./components/Compare'))

function Loader() {
  return <div className="flex items-center justify-center h-64"><div className="spinner" style={{ width: 20, height: 20 }} /></div>
}

function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center h-[60vh] gap-3">
      <div className="font-mono font-bold" style={{ fontSize: '5rem', color: 'var(--color-border)', lineHeight: 1 }}>404</div>
      <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>Page not found</p>
      <a href="/" className="btn btn-primary mt-2 text-xs">Back to Dashboard</a>
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Suspense fallback={<Loader />}><Dashboard /></Suspense>} />
          <Route path="/analyze" element={<Suspense fallback={<Loader />}><Analysis /></Suspense>} />
          <Route path="/map" element={<Suspense fallback={<Loader />}><ThreatMap /></Suspense>} />
          <Route path="/compare" element={<Suspense fallback={<Loader />}><Compare /></Suspense>} />
          <Route path="/history" element={<Suspense fallback={<Loader />}><History /></Suspense>} />
          <Route path="/settings" element={<Suspense fallback={<Loader />}><Settings /></Suspense>} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
