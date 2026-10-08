import { lazy, Suspense } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import Layout from '@/components/Layout';

const Dashboard = lazy(() => import('@/pages/Dashboard'));
const Domains = lazy(() => import('@/pages/Domains'));
const DomainDetail = lazy(() => import('@/pages/DomainDetail'));
const Schedule = lazy(() => import('@/pages/Schedule'));
const Anomalies = lazy(() => import('@/pages/Anomalies'));
const Analytics = lazy(() => import('@/pages/Analytics'));
const Scanning = lazy(() => import('@/pages/Scanning'));
const Alerts = lazy(() => import('@/pages/Alerts'));
const Settings = lazy(() => import('@/pages/Settings'));
const Tranco = lazy(() => import('@/pages/Tranco'));
const CDNPropagation = lazy(() => import('@/pages/CDNPropagation'));

function App() {
  return (
    <Suspense fallback={<div role="status">正在加载页面…</div>}>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="domains" element={<Domains />} />
          <Route path="domains/:domain" element={<DomainDetail />} />
          {/* legacy paths */}
          <Route path="certificates" element={<Navigate to="/domains" replace />} />
          <Route path="certificates/:domain" element={<DomainDetail />} />
          <Route path="schedule" element={<Schedule />} />
          <Route path="anomalies" element={<Anomalies />} />
          <Route path="analytics" element={<Analytics />} />
          <Route path="scanning" element={<Scanning />} />
          <Route path="cdn-propagation" element={<CDNPropagation />} />
          <Route path="tranco" element={<Tranco />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Routes>
    </Suspense>
  );
}

export default App;
