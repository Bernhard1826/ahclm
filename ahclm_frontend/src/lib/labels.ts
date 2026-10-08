// Display labels only: retain the original API values for queries and CSS.
const STATUS_LABELS: Record<string, string> = {
  active: '活跃', unreachable: '无法访问', dormant: '休眠', healthy: '健康',
  good: '正常', revoked: '已吊销', unknown: '未知', expired: '已过期',
  expiring: '即将到期', valid: '有效', critical: '严重', warning: '警告', info: '提示',
  enabled: '已启用', disabled: '已禁用', paused: '已暂停', running: '运行中',
  pending: '待处理', completed: '已完成', complete: '完整', failed: '失败',
  partial: '部分完整', absent: '缺失', external_only: '仅有外部证据',
  proven: '已证实', inferred: '推测', established: '已确定', unestablished: '未确定',
  deterministic: '确定', speculative: '推测', supported: '最符合', possible: '可能',
  rejected: '已排除', underdetermined: '无法判定', insufficient: '证据不足',
  ambiguous: '尚无法区分', expected: '预期行为', incident: '问题',
  watching: '监测中', changed: '已变更', in_progress: '进行中', mixed: '混合状态',
  regional_lag: '地区滞后', synchronized: '已同步', target: '目标证书',
  previous: '前任证书', baseline: '基线', other: '其他', timeout: '超时',
  origin_via_cdn: 'CDN 回源证书核验', origin_verified: '源站新证书已核验', origin_unverified: 'HTTP 成功，证书未核验', origin_reload: '源站加载事件', request_ok: '源站新证书已核验', request_error: '请求失败',
  incomplete: '不完整', provider_error: '探测服务错误', provider_skipped: '探测服务已跳过',
  canceled: '已取消', cancelled: '已取消', success: '成功', succeeded: '成功', error: '错误',
  ready: '就绪', connected: '已连接', disconnected: '已断开',
  none: '无', not_checked: '未检查', unsupported: '不支持', unavailable: '不可用',
  ok: '正常', deferred: '已延后', accumulating: '积累中', queued: '排队中',
  concordant: '一致', divergent: '存在差异', inconclusive: '无法判定',
  concurrent_leaves: '同一地址多叶并存',
  homogeneous: '一致', heterogeneous: '存在差异', stable: '稳定',
  operator_input: '操作者输入', monitor_observation: '监测观测', monitor_observed: '监测观测',
  ari_or_near_expiry_watch_started: 'ARI 或临近到期监测启动',
  first_observation: '首次观测', watcher_start: '监测启动', watch_start: '监测启动',
  edge: '边缘', origin: '源站', leaf: '叶证书', root: '根证书', intermediate: '中间证书',
  certificate_not_before: '证书 NotBefore', certificate_first_seen: '证书首次入库',
  observation: '生命周期观测', measurement_snapshot: '测量快照',
  endpoint_probe: '端点探测', internal_evidence: '内部证据',
  zip: '压缩列表', fallback: '备用来源',
  resolved: '已解析', nxdomain: '域名不存在', no_answer: '无响应',
  no_public_ip: '无公网 IP', consistent: '一致', diverse: '多样',
  keycompromise: '私钥泄露', cacompromise: 'CA 私钥泄露', superseded: '已被替代',
  cessationofoperation: '停止使用', affiliationchanged: '归属变更',
  certificatehold: '证书暂停', unspecified: '未指明', removefromcrl: '已从 CRL 移除',
  privilegewithdrawn: '权限撤销', aacompromise: '属性颁发机构泄露',
};

export function statusLabel(value?: string | null): string {
  if (!value) return '未知';
  return STATUS_LABELS[value.toLowerCase()] ?? value;
}

export const severityLabel = statusLabel;

const REASON_LABELS: Record<string, string> = {
  initial: '首次观测', initial_scan: '首次扫描', baseline: '基线扫描',
  baseline_rescan: '基线复扫', post_expiry_check: '到期后检查',
  manual: '手动扫描', manual_scan: '手动扫描', batch: '批量扫描',
  manual_batch: '手动批量扫描', tranco: 'Tranco 列表扫描',
  adaptive: '自适应扫描', milestone: '里程碑扫描',
  ari_emergency: 'ARI 紧急续签', ari_window: 'ARI 续签窗口',
  revocation_poll: '吊销状态轮询', revocation_check: '吊销检查',
  retry: '失败重试', rescan: '复扫', near_expiry: '临近到期',
};

export function reasonLabel(value?: string | null): string {
  if (!value) return '—';
  const match = value.match(/^(?:expiry|milestone)_(\d+)d(?:_check)?$/);
  if (match) return `到期前 ${match[1]} 天检查`;
  return REASON_LABELS[value] ?? statusLabel(value);
}

const REGION_LABELS: Record<string, string> = {
  AF: '非洲', AS: '亚洲', EU: '欧洲', NA: '北美洲', OC: '大洋洲', SA: '南美洲',
};

export function regionLabel(value: string): string {
  return REGION_LABELS[value] ?? value;
}

export function bucketLabel(value: string): string {
  if (value === 'after expiry') return '到期后';
  return value.replace(/d before$/, ' 天前').replace(/d$/, ' 天')
    .replace('(early/urgent)', '（提前/紧急）').replace('(normal)', '（常规）');
}
