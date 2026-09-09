import { Routes, Route, Navigate } from 'react-router-dom';
import Layout from '@/components/Layout';
import Dashboard from '@/pages/Dashboard';
import Domains from '@/pages/Domains';
import DomainDetail from '@/pages/DomainDetail';
import Schedule from '@/pages/Schedule';
import Anomalies from '@/pages/Anomalies';
import Analytics from '@/pages/Analytics';
import Scanning from '@/pages/Scanning';
import Alerts from '@/pages/Alerts';
import Settings from '@/pages/Settings';
import Tranco from '@/pages/Tranco';

function App() {
  return (
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
        <Route path="tranco" element={<Tranco />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="settings" element={<Settings />} />
      </Route>
    </Routes>
  );
}

export default App;
