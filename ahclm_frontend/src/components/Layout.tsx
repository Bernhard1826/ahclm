import { Outlet, Link, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  Globe,
  CalendarClock,
  AlertTriangle,
  BarChart3,
  Scan,
  Bell,
  Settings,
  ListOrdered,
  Menu,
  X,
  Activity,
} from 'lucide-react';
import { useState } from 'react';

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Domains', href: '/domains', icon: Globe },
  { name: 'Schedule', href: '/schedule', icon: CalendarClock },
  { name: 'Analytics', href: '/analytics', icon: BarChart3 },
  { name: 'Anomalies', href: '/anomalies', icon: AlertTriangle },
  { name: 'Scanning', href: '/scanning', icon: Scan },
  { name: 'Tranco', href: '/tranco', icon: ListOrdered },
  { name: 'Alerts', href: '/alerts', icon: Bell },
  { name: 'Settings', href: '/settings', icon: Settings },
];

export default function Layout() {
  const location = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const isAnomalyRoute = location.pathname === '/anomalies';

  return (
    <div className={`min-h-screen app-shell ${isAnomalyRoute ? 'anomaly-route' : ''}`}>
      {/* Mobile menu button */}
      <div className="lg:hidden fixed top-0 left-0 right-0 z-50 bg-slate-900 border-b border-slate-700 px-4 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Activity className="h-6 w-6 text-primary-500" />
          <span className="font-bold text-lg">AHCLM</span>
        </div>
        <button
          type="button"
          className="p-2 text-slate-400 hover:text-white"
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
        >
          {mobileMenuOpen ? <X className="h-6 w-6" /> : <Menu className="h-6 w-6" />}
        </button>
      </div>

      {/* Mobile menu */}
      {mobileMenuOpen && (
        <div className="lg:hidden fixed inset-0 z-40 bg-slate-900 pt-16">
          <nav className="px-4 py-4 space-y-1">
            {navigation.map((item) => {
              const isActive = location.pathname === item.href || location.pathname.startsWith(item.href + '/');
              const Icon = item.icon;
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                    isActive
                      ? 'bg-primary-600 text-white'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                  onClick={() => setMobileMenuOpen(false)}
                >
                  <Icon className="h-5 w-5" />
                  {item.name}
                </Link>
              );
            })}
          </nav>
        </div>
      )}

      {/* Desktop sidebar. Anomalies collapses to an icon rail so evidence/cause can own the viewport. */}
      <div className={`hidden lg:fixed lg:inset-y-0 lg:flex lg:flex-col ${isAnomalyRoute ? 'lg:w-16' : 'lg:w-64'}`}>
        <div className="flex flex-col flex-1 bg-slate-900 border-r border-slate-700">
          <div className={`flex items-center border-b border-slate-700 ${isAnomalyRoute ? 'justify-center px-2 py-4' : 'gap-3 px-6 py-5'}`}>
            <Activity className={`${isAnomalyRoute ? 'h-7 w-7' : 'h-8 w-8'} text-primary-500`} />
            {!isAnomalyRoute && (
              <div>
                <h1 className="font-bold text-lg">AHCLM</h1>
                <p className="text-xs text-slate-400">Certificate Lifecycle Monitor</p>
              </div>
            )}
          </div>

          <nav className={`flex-1 py-4 space-y-1 ${isAnomalyRoute ? 'px-2' : 'px-4'}`}>
            {navigation.map((item) => {
              const isActive = location.pathname === item.href || location.pathname.startsWith(item.href + '/');
              const Icon = item.icon;
              return (
                <Link
                  key={item.name}
                  to={item.href}
                  title={item.name}
                  aria-label={item.name}
                  className={`flex items-center rounded-lg transition-colors ${
                    isAnomalyRoute ? 'justify-center px-2 py-3' : 'gap-3 px-4 py-3'
                  } ${
                    isActive
                      ? 'bg-primary-600 text-white'
                      : 'text-slate-300 hover:bg-slate-800'
                  }`}
                >
                  <Icon className="h-5 w-5" />
                  {!isAnomalyRoute && item.name}
                </Link>
              );
            })}
          </nav>

          {!isAnomalyRoute && (
            <div className="p-4 border-t border-slate-700">
              <p className="text-xs text-slate-500 text-center">
                Adaptive HTTPS Certificate<br />
                Lifecycle Monitoring System
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Main content */}
      <div className={`${isAnomalyRoute ? 'lg:pl-16' : 'lg:pl-64'} pt-16 lg:pt-0`}>
        <main className={`min-h-screen ${isAnomalyRoute ? 'p-3 lg:p-4' : 'p-4 lg:p-8'}`}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
