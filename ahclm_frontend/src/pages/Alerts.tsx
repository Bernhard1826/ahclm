import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Bell, Plus, Trash2, Edit2, Save, XCircle } from 'lucide-react';
import { getAlerts, createAlert, updateAlert, deleteAlert, getRuntimeConfig } from '@/api';
import type { CertificateAlert } from '@/types';

export default function Alerts() {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState<number | null>(null);
  const [newAlert, setNewAlert] = useState(false);
  const [formData, setFormData] = useState<Partial<CertificateAlert>>({
    name: '',
    interval_days: undefined,
    is_enabled: true,
    email_enabled: false,
    webhook_url: '',
  });

  const { data: alerts, isLoading } = useQuery<CertificateAlert[]>({
    queryKey: ['alerts'],
    queryFn: async () => {
      const res = await getAlerts();
      return res.data as CertificateAlert[];
    },
  });
  const { data: runtimeConfig } = useQuery({
    queryKey: ['runtimeConfig'],
    queryFn: async () => (await getRuntimeConfig()).data,
  });

  const createMutation = useMutation({
    mutationFn: (alert: Omit<CertificateAlert, 'id' | 'created_at' | 'updated_at'>) => createAlert(alert),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      setNewAlert(false);
      setFormData({ name: '', interval_days: undefined, is_enabled: true, email_enabled: false, webhook_url: '' });
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, alert }: { id: number; alert: CertificateAlert }) => updateAlert(id, alert),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      setEditing(null);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => deleteAlert(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
    },
  });

  const handleSave = () => {
    if (!formData.name || !formData.interval_days) return;
    createMutation.mutate(formData as Omit<CertificateAlert, 'id' | 'created_at' | 'updated_at'>);
  };

  const handleUpdate = () => {
    if (!editing || !formData.name) return;
    updateMutation.mutate({
      id: editing,
      alert: { ...formData, id: editing } as CertificateAlert,
    });
  };

  const configuredIntervals = Array.from(new Set([
    ...(runtimeConfig?.scheduler.milestones ?? []),
    ...(runtimeConfig?.scheduler.post_expiry_checks ?? []),
  ])).sort((a, b) => b - a);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Alerts</h1>
          <p className="text-slate-400 mt-1">Configure certificate expiration alerts</p>
        </div>
        <button
          onClick={() => setNewAlert(true)}
          className="btn btn-primary"
          disabled={newAlert}
        >
          <Plus className="h-4 w-4 mr-2" />
          Add Alert
        </button>
      </div>

      {/* Default Intervals */}
      <div className="card">
        <h2 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Bell className="h-5 w-5 text-primary-500" />
          Default Alert Intervals
        </h2>
        <p className="text-sm text-slate-400 mb-4">
          Configure when to rescan certificates based on days until expiration
        </p>
        <div className="flex flex-wrap gap-2">
          {configuredIntervals.map((days) => (
            <div
              key={days}
              className={`px-4 py-2 rounded-lg text-center ${
                alerts?.some(a => a.interval_days === days)
                  ? 'bg-primary-500/20 text-primary-400 border border-primary-500/30'
                  : 'bg-slate-700 text-slate-400'
              }`}
            >
              <p className="font-medium">{days}</p>
              <p className="text-xs">day{days > 1 ? 's' : ''}</p>
            </div>
          ))}
        </div>
      </div>

      {/* New Alert Form */}
      {newAlert && (
        <div className="card border-primary-500/30">
          <h2 className="text-lg font-semibold mb-4">Create New Alert</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-slate-400 mb-1">Alert Name</label>
              <input
                type="text"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                placeholder="Alert name"
                className="input"
              />
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-1">Days Before Expiration</label>
              <select
                value={formData.interval_days}
                onChange={(e) => setFormData({ ...formData, interval_days: parseInt(e.target.value) })}
                className="input"
              >
                {configuredIntervals.map((days) => (
                  <option key={days} value={days}>{days} days</option>
                ))}
              </select>
            </div>
            <div className="md:col-span-2">
              <label className="block text-sm text-slate-400 mb-1">Webhook URL (optional)</label>
              <input
                type="url"
                value={formData.webhook_url || ''}
                onChange={(e) => setFormData({ ...formData, webhook_url: e.target.value })}
                placeholder="Optional HTTPS webhook URL"
                className="input"
              />
            </div>
            <div className="flex gap-4">
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={formData.is_enabled}
                  onChange={(e) => setFormData({ ...formData, is_enabled: e.target.checked })}
                  className="w-4 h-4 rounded border-slate-600 bg-slate-700"
                />
                <span className="text-sm">Enabled</span>
              </label>
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={formData.email_enabled}
                  onChange={(e) => setFormData({ ...formData, email_enabled: e.target.checked })}
                  className="w-4 h-4 rounded border-slate-600 bg-slate-700"
                />
                <span className="text-sm">Email Notification</span>
              </label>
            </div>
          </div>
          <div className="flex gap-2 mt-4">
            <button onClick={handleSave} className="btn btn-primary" disabled={createMutation.isPending}>
              <Save className="h-4 w-4 mr-2" />
              {createMutation.isPending ? 'Saving...' : 'Save Alert'}
            </button>
            <button onClick={() => setNewAlert(false)} className="btn btn-secondary">
              <XCircle className="h-4 w-4 mr-2" />
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Alert List */}
      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Configured Alerts</h2>
        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <div className="spinner" />
          </div>
        ) : !alerts || alerts.length === 0 ? (
          <div className="text-center py-8">
            <Bell className="h-12 w-12 text-slate-600 mx-auto mb-4" />
            <p className="text-slate-400">No alerts configured</p>
            <p className="text-sm text-slate-500 mt-2">Create an alert to get notified when certificates are expiring</p>
          </div>
        ) : (
          <div className="space-y-4">
            {alerts.map((alert) => (
              <div
                key={alert.id}
                className={`p-4 rounded-lg border ${
                  editing === alert.id ? 'border-primary-500/30 bg-slate-700/30' : 'border-slate-700'
                }`}
              >
                {editing === alert.id ? (
                  <div className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm text-slate-400 mb-1">Alert Name</label>
                        <input
                          type="text"
                          value={formData.name}
                          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                          className="input"
                        />
                      </div>
                      <div>
                        <label className="block text-sm text-slate-400 mb-1">Days Before Expiration</label>
                        <select
                          value={formData.interval_days}
                          onChange={(e) => setFormData({ ...formData, interval_days: parseInt(e.target.value) })}
                          className="input"
                        >
                          {configuredIntervals.map((days) => (
                            <option key={days} value={days}>{days} days</option>
                          ))}
                        </select>
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <button onClick={handleUpdate} className="btn btn-primary btn-sm">
                        <Save className="h-4 w-4 mr-1" /> Save
                      </button>
                      <button onClick={() => setEditing(null)} className="btn btn-secondary btn-sm">
                        <XCircle className="h-4 w-4 mr-1" /> Cancel
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      <div className="w-12 h-12 bg-primary-500/20 rounded-lg flex items-center justify-center">
                        <span className="text-lg font-bold text-primary-400">{alert.interval_days}</span>
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <p className="font-medium">{alert.name}</p>
                          <span className={`px-2 py-0.5 rounded-full text-xs ${
                            alert.is_enabled ? 'bg-green-500/20 text-green-400' : 'bg-slate-500/20 text-slate-400'
                          }`}>
                            {alert.is_enabled ? 'Enabled' : 'Disabled'}
                          </span>
                          {alert.email_enabled && (
                            <span className="px-2 py-0.5 rounded-full text-xs bg-blue-500/20 text-blue-400">
                              Email
                            </span>
                          )}
                        </div>
                        <p className="text-sm text-slate-400">
                          Rescan {alert.interval_days} day{alert.interval_days > 1 ? 's' : ''} before expiration
                        </p>
                        {alert.webhook_url && (
                          <p className="text-xs text-slate-500 mt-1">Webhook: {alert.webhook_url}</p>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => {
                          setEditing(alert.id);
                          setFormData(alert);
                        }}
                        className="p-2 text-slate-400 hover:text-white"
                      >
                        <Edit2 className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => deleteMutation.mutate(alert.id)}
                        className="p-2 text-slate-400 hover:text-red-400"
                        disabled={deleteMutation.isPending}
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Alerting Strategy */}
      <div className="card">
        <h2 className="text-lg font-semibold mb-4">Intelligent Alerting Strategy</h2>
        <div className="space-y-4 text-sm">
          <div className="p-4 bg-slate-700/30 rounded-lg">
            <h3 className="font-medium text-yellow-400 mb-2">Critical (1-3 days)</h3>
            <p className="text-slate-400">
              Maximum priority scanning. Certificates expiring within 3 days are flagged immediately.
              Automatic rescans every hour until renewal or expiration.
            </p>
          </div>
          <div className="p-4 bg-slate-700/30 rounded-lg">
            <h3 className="font-medium text-orange-400 mb-2">Warning (7-10 days)</h3>
            <p className="text-slate-400">
              Daily rescan schedule. Focus on certificates approaching renewal window.
              Notify via configured channels.
            </p>
          </div>
          <div className="p-4 bg-slate-700/30 rounded-lg">
            <h3 className="font-medium text-blue-400 mb-2">Notice (30+ days)</h3>
            <p className="text-slate-400">
              Weekly scanning. Maintain baseline monitoring and track any mid-term changes.
              Useful for trend analysis.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
