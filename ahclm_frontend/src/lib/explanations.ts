// Translate application explanations without modifying retained evidence or logs.
const EXPLANATIONS: Record<string, string> = {
  "The experiment is saved and waiting for an active Globalping slot.": "实验已保存，等待可用的探测名额；排队时间会保留在报告中。",
  "All sampled regions returned a fresh origin response over a TLS connection using the target origin certificate for the required stable rounds. These are observation upper bounds, including polling and queue delay, not global CDN deployment times. Trust depends on the controlled origin endpoint and CDN TLS configuration.": "所有采样地区均已连续核验：请求确实抵达受控源站，且连接使用目标源站证书。报告时间是包含轮询和排队延迟的观测上界；结论依赖源站端点和 CDN 的 TLS 配置，仅覆盖所选探测点。",
  "The experiment checks a fresh nonce and the origin TLS connection certificate through the CDN; HTTP success alone does not verify certificate adoption.": "正在经 CDN 核验源站连接证书及本轮随机标记。HTTP 成功本身不表示新证书已被采用。",
  "HTTP succeeded but fresh origin handshake with the target certificate is not verified": "HTTP 请求成功，但尚未核验使用目标证书的源站连接。",
  "The experiment reached its time limit before every sampled region verified the target origin certificate. Missing or failed regions remain unresolved.": "实验已超时，仍有采样地区未核验目标源站证书。",
  "The experiment was canceled before every sampled region verified the target origin certificate.": "实验已取消，尚未完成所有地区的源站证书核验。",
  "no probe result for configured region": "本轮未收到该地区的探测结果。",

  "This baseline watcher records each location's initial leaf and reports later fingerprint changes with first-seen times. The region spread applies only to observed probes, not every CDN point of presence.": '基线监测记录各地区的初始叶证书，以及后续指纹变更和首次观测时间。地区传播范围仅涵盖实际探测点。',
  'The baseline watcher reached its configured time limit. Its recorded changes and first-seen times describe only the sampled locations and observation interval.': '基线监测已达到配置的时间上限。变更记录和首次观测时间仅描述已采样地区及其观测时段。',
  'All configured regions served the target certificate for the required stable rounds; the observed first-seen spread is within the polling bound.': '所有配置地区均在要求的稳定轮次内提供目标证书，首次观测的地区时间差位于轮询界限内。',
  'All configured regions eventually served the target certificate, but their first-seen times show a measurable regional lag.': '所有配置地区最终都提供了目标证书，首次观测时间表明存在可测量的地区滞后。',
  'The experiment reached its time limit before every configured region served the target certificate; missing regions remain unknown rather than being treated as old.': '实验达到时间上限时，仍有地区未观测到目标证书；缺失地区的状态保留为未知。',
  'The experiment was canceled before regional propagation was confirmed.': '地区传播尚未确认，实验已取消。',
  'The experiment failed before regional propagation was confirmed.': '地区传播尚未确认，实验已失败。',
  'The experiment is still collecting independent regional HTTPS observations; completion requires every configured region to serve the target for the stable-round threshold.': '实验仍在采集独立的地区 HTTPS 观测；所有配置地区均需连续提供目标证书并达到稳定轮次阈值，才能确认完成。',
  'These probes observe what one address returns. They do not read the CDN, controller or CA log, and they do not replace an imported internal-evidence event.': '这些探测记录单个地址的返回结果；证据范围限于外部测量。内部原因仍需 CDN、控制器或 CA 日志等内部事件支持。',
  'Does this address select a different certificate when the ClientHello carries the domain SNI than when SNI is omitted?': 'ClientHello 携带域名 SNI 与省略 SNI 时，该地址是否选择不同证书？',
  'Does repeating the handshake to the same address in one round return more than one leaf?': '同轮次对同一地址重复握手，是否返回多张叶证书？',
  'Does an HTTPS request with this Host header land on the same leaf the SNI handshake selected?': '带此 Host 头的 HTTPS 请求，是否使用与 SNI 握手相同的叶证书？',
  'No certificate was obtained for evidence enrichment.': '未获得证书，无法补充证据。',
};

export function explanationText(value: string): string {
  return EXPLANATIONS[value] ?? value;
}
