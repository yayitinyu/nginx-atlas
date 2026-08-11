import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'

export type ThemeMode = 'system' | 'light' | 'dark'
export type LanguageMode = 'system' | 'zh' | 'en'
export type EffectiveLanguage = 'zh' | 'en'

type Variables = Record<string, string | number>

interface PreferencesValue {
  theme: ThemeMode
  effectiveTheme: 'light' | 'dark'
  language: LanguageMode
  effectiveLanguage: EffectiveLanguage
  locale: string
  setTheme: (theme: ThemeMode) => void
  setLanguage: (language: LanguageMode) => void
  t: (key: string, variables?: Variables) => string
}

const messages: Record<EffectiveLanguage, Record<string, string>> = {
  zh: {
    'common.add': '添加', 'common.cancel': '取消', 'common.save': '保存', 'common.close': '关闭',
    'common.search': '搜索', 'common.edit': '编辑', 'common.delete': '移除', 'common.refresh': '刷新',
    'common.online': '在线', 'common.offline': '离线', 'common.pending': '待连接', 'common.revoked': '已撤销',
    'common.valid': '有效', 'common.expiring': '即将到期', 'common.expired': '已到期', 'common.none': '无',
    'common.days': '{count} 天', 'common.items': '{count} 项', 'common.nodes': '{count} 个节点',
    'common.loading': '正在读取基础设施状态', 'common.saving': '正在保存', 'common.queueing': '正在创建任务',
    'common.noResults': '没有匹配结果', 'common.optional': '可选', 'common.select': '请选择',
    'common.system': '系统', 'common.light': '浅色', 'common.dark': '深色', 'common.chinese': '中文', 'common.english': 'English',
    'nav.overview': '概览', 'nav.domains': '域名与路由', 'nav.domainsShort': '域名', 'nav.certificates': '证书',
    'nav.nodes': '节点', 'nav.accounts': 'DNS / ACME', 'nav.audit': '审计日志', 'nav.settings': '设置',
    'nav.main': '主导航', 'nav.mobile': '移动主导航', 'nav.open': '打开导航', 'nav.close': '关闭导航',
    'app.allHealthy': '所有系统正常运行', 'app.waitingNode': '等待添加首个节点', 'app.needsAttention': '部分节点需要检查',
    'app.configVerified': '配置已验证', 'app.statusSynced': '状态已同步', 'app.refreshNow': '立即刷新',
    'app.language': '语言', 'app.theme': '主题', 'app.admin': '超级管理员', 'app.logout': '退出登录',
    'login.eyebrow': 'NGINX ORCHESTRATION', 'login.title': '一处管理，\n全部生效。',
    'login.description': '安全管理域名、证书与 Linux 节点。每次变更都会经过 Nginx 完整性检查。',
    'login.cardTitle': '管理员登录', 'login.cardDescription': '输入安装时生成的管理员密码。登录后浏览器只保存短期会话令牌。',
    'login.password': '管理员密码', 'login.passwordPlaceholder': '输入管理员密码', 'login.submit': '进入控制台',
    'login.submitting': '正在验证', 'login.secure': '密码仅用于建立会话，不会写入浏览器存储。',
    'login.tooShort': '请输入至少 12 个字符的管理员密码。', 'login.invalid': '密码无效，或主控暂时无法连接。',
    'overview.title': '基础设施，保持清晰', 'overview.description': '节点、域名、证书与最近变更的统一运行视图。',
    'overview.nodesOnline': '节点在线', 'overview.allNormal': '全部正常', 'overview.checkNeeded': '需要检查',
    'overview.certRisk': '证书临期', 'overview.within30': '30 天内到期', 'overview.noRisk': '暂无风险',
    'overview.routes': '域名与路由', 'overview.searchDomain': '搜索域名', 'overview.noDomain': '还没有匹配的域名',
    'overview.noDomainDescription': '前往“域名与路由”添加第一条路由。', 'overview.adjustSearch': '请调整搜索关键词。',
    'overview.total': '共 {count} 条', 'overview.viewAll': '查看全部', 'overview.timeline': '证书到期时间线',
    'overview.next90': '未来 90 天', 'overview.nodeHealth': '节点健康', 'overview.activity': '最近活动',
    'overview.noActivity': '暂无活动', 'overview.noActivityDescription': '部署、续期与同步事件会显示在这里。',
    'overview.noCertificates': '暂无证书', 'overview.noCertificatesDescription': '添加证书后将在这里显示到期窗口。',
    'overview.viewCertificates': '查看证书', 'overview.noNodes': '还没有节点', 'overview.noNodesDescription': '生成添加命令并在 Linux VPS 上运行。',
    'overview.viewNodes': '查看所有节点', 'overview.waitingReport': '等待上报', 'overview.nginxUndetected': 'Nginx 未检测',
    'overview.quickActions': '快捷操作与系统统计', 'overview.activeRoutes': '活跃路由占比', 'overview.autoRenewCerts': '自动续期证书',
    'domain.title': '域名与路由', 'domain.description': '将域名映射到项目端口，并以事务方式部署 Nginx 配置。',
    'domain.add': '添加域名', 'domain.editTitle': '编辑域名与路由', 'domain.updateSubmit': '保存并重载', 'domain.searchPlaceholder': '搜索域名、节点或端口', 'domain.managedTab': '已管理',
    'domain.discoveredTab': '节点发现', 'domain.discoveredTitle': '节点现有 Nginx 域名',
    'domain.discoveredDescription': '代理从 nginx -T 提取安全元数据；可只加入监控，也可备份后安全接管原规则。',
    'domain.adopt': '开始监控', 'domain.adopted': '已管理', 'domain.noDiscovered': '没有新的节点域名',
    'domain.noDiscoveredDescription': '节点下一次轮询时会同步当前 Nginx server_name。',
    'domain.empty': '还没有域名', 'domain.emptyDescription': '创建路由后，代理会先运行 nginx -t，再安全重载。',
    'domain.columnDomain': '域名', 'domain.columnRoute': '路由目标', 'domain.columnCert': '证书状态',
    'domain.columnNode': '节点', 'domain.columnState': '状态', 'domain.localConfig': '现有配置',
    'domain.managedConfig': 'Atlas 配置', 'domain.configPath': '配置文件', 'domain.tls': 'TLS', 'domain.http': 'HTTP',
    'domain.showing': '显示 {shown} / {total} 条', 'domain.transactionNote': '每次托管变更都需要通过 nginx -t',
    'domain.removeTitle': '移除域名配置？', 'domain.removeObservedTitle': '停止管理这个域名？',
    'domain.removeDescription': '节点将删除 {domain} 的托管配置，通过 nginx -t 后才会重载。证书文件不会自动删除。',
    'domain.removeObservedDescription': '只会从 Atlas 管理列表移除 {domain}，节点原有 Nginx 配置不会修改。',
    'domain.removeTakenOverTitle': '停止接管并恢复原规则？',
    'domain.removeTakenOverDescription': '节点将移除 {domain} 的 Atlas 配置、恢复接管前的 Nginx 规则，并在 nginx -t 通过后重载。证书不会删除。',
    'domain.removeAction': '移除域名', 'domain.stopManaging': '停止管理', 'domain.restoreOriginal': '恢复原规则',
    'domain.runtimeQueued': '排队中', 'domain.runtimeRunning': '部署中', 'domain.runtimeFailed': '失败',
    'domain.runtimeActive': '运行中', 'domain.runtimePending': '待部署', 'domain.unconnected': '未连接',
    'domain.certPending': '等待证书', 'domain.httpOnlyShort': '仅 HTTP',
    'domain.drawerKicker': '路由部署', 'domain.drawerSubtitle': '配置上游、证书与可选的 Cloudflare DNS', 'domain.stepRoute': '路由', 'domain.stepCertificate': '证书', 'domain.stepDeploy': '部署',
    'domain.targetNode': '目标节点', 'domain.upstreamHost': '上游地址', 'domain.projectPort': '项目端口', 'domain.certificateSource': '证书来源',
    'domain.existingCertificate': '已有证书', 'domain.uploadCertificate': '上传证书', 'domain.letsencrypt': "Let's Encrypt",
    'domain.certificateLocation': '证书位置', 'domain.localCertificate': '使用目标节点 /etc/ssl/{domain}', 'domain.controllerCertificate': '主控证书 · {domain} · {days} 天',
    'domain.syncOthers': '同步到其他节点', 'domain.noOtherNodes': '暂无其他可用节点', 'domain.syncDescription': '部署后将证书推送到所选节点，并分别验证、重载 Nginx。',
    'domain.preview': 'Nginx 配置预览', 'domain.httpOnly': '暂不启用 TLS，仅创建 HTTP 路由',
    'domain.deployProof': '部署时先执行 nginx -t。验证或重载失败会自动恢复旧配置与证书。',
    'domain.offlineWarning': '目标节点当前离线；任务会排队，节点恢复连接后自动执行。', 'domain.submit': '验证并部署',
    'domain.validation': '请完整填写有效域名、目标节点、上游地址和端口。',
    'domain.validationFiles': '请同时选择 fullchain.pem 与 privkey.pem。', 'domain.validationAccounts': '自动签发或续期需要 DNS 与 ACME 账户。',
    'certificate.title': '证书', 'certificate.description': '签发、续期与分发 TLS 证书，并检查所有节点副本。',
    'certificate.add': '添加证书', 'certificate.total': '全部证书', 'certificate.expiringCount': '即将到期',
    'certificate.autoRenewCount': '自动续期', 'certificate.nodeCopies': '节点副本',
    'certificate.searchPlaceholder': '搜索域名、签发者或指纹', 'certificate.allStatuses': '全部状态',
    'certificate.validOnly': '仅有效', 'certificate.expiringOnly': '临期 / 过期', 'certificate.empty': '还没有证书',
    'certificate.emptyDescription': '上传已有证书、使用 DNS-01 自动签发，或接管节点证书。',
    'certificate.sourceACME': "Let's Encrypt / ACME", 'certificate.sourceUpload': '手动上传', 'certificate.sourceLocal': '节点接管',
    'certificate.expiry': '到期时间', 'certificate.source': '来源', 'certificate.autoRenew': '自动续期',
    'certificate.distribution': '分发状态', 'certificate.renew': '立即续期', 'certificate.sync': '同步',
    'certificate.enabled': '已启用', 'certificate.disabled': '未启用', 'certificate.remaining': '剩余 {count} 天',
    'certificate.enableAutoRenew': '启用 {domain} 自动续期', 'certificate.disableAutoRenew': '关闭 {domain} 自动续期',
    'certificate.automationUnavailable': '请先为证书配置签发节点、DNS 与 ACME 账户。',
    'certificate.renewConfirmTitle': '确认立即续期？', 'certificate.renewConfirmDescription': '{domain} 将立即通过 DNS-01 申请新证书；成功后会安全写入目标节点并验证、重载 Nginx。', 'certificate.renewConfirmAction': '确认续期',
    'certificate.fingerprint': 'SHA-256 指纹', 'certificate.modeUpload': '上传已有证书',
    'certificate.modeUploadShort': '上传', 'certificate.modeIssue': '申请并自动续期', 'certificate.modeIssueShort': '自动签发',
    'certificate.modeImport': '从节点接管', 'certificate.modeImportShort': '节点接管',
    'certificate.modeUploadHint': '校验证书链与私钥', 'certificate.modeIssueHint': '使用 ACME DNS-01',
    'certificate.modeImportHint': '接管 /etc/ssl 中的证书', 'certificate.domain': '证书域名',
    'certificate.signingNode': '签发节点', 'certificate.sourceNode': '来源节点', 'certificate.nodeCertificate': '节点证书',
    'certificate.dnsAccount': 'DNS 账户', 'certificate.acmeAccount': 'ACME 账户',
    'certificate.syncNodes': '自动同步节点', 'certificate.syncHint': '签发或接管后推送到所选节点，并分别验证和重载 Nginx。',
    'certificate.renewToggle': '到期前自动续期', 'certificate.renewHint': '进入 {days} 天到期窗口后自动执行 DNS-01。',
    'certificate.fullchain': 'fullchain.pem', 'certificate.privkey': 'privkey.pem', 'certificate.chooseFile': '选择 PEM 文件',
    'certificate.submitUpload': '验证并添加', 'certificate.submitIssue': '申请证书', 'certificate.submitImport': '接管证书',
    'certificate.noNodeCertificates': '该节点没有上报可接管的有效证书。',
    'certificate.validationDomain': '请输入有效的证书域名。', 'certificate.validationFiles': '请同时选择 fullchain.pem 与 privkey.pem。',
    'certificate.validationNode': '请选择可用节点。', 'certificate.validationAccounts': '请选择 DNS 与 ACME 账户。',
    'nodes.title': '节点', 'nodes.description': '节点仅主动连接主控，无需暴露额外的公网管理端口。',
    'nodes.add': '添加节点', 'nodes.empty': '还没有 Linux 节点', 'nodes.emptyDescription': '生成一次性安装命令，并在目标 VPS 上执行。',
    'nodes.command': '生成添加命令', 'nodes.hostnamePending': '等待上报主机名', 'nodes.addresses': '公网 / 内网地址',
    'nodes.nginx': 'Nginx', 'nodes.platform': '平台', 'nodes.certDirectory': '证书目录', 'nodes.certFound': '{count} 个已发现',
    'nodes.siteFound': '{count} 个域名', 'nodes.lastSeen': '最后在线：{time}', 'nodes.never': '从未连接',
    'nodes.revoke': '撤销节点', 'nodes.revokeTitle': '撤销节点访问？',
    'nodes.revokeDescription': '{node} 将无法继续领取任务。节点本地现有 Nginx 配置与证书不会被删除。',
    'accounts.title': 'DNS / ACME', 'accounts.description': '只保留签发所需字段；敏感凭据始终加密保存。',
    'accounts.dnsTitle': 'DNS 账户', 'accounts.acmeTitle': 'ACME 账户', 'accounts.addDNS': '添加 DNS 账户',
    'accounts.addACME': '添加 ACME 账户', 'accounts.emptyDNS': '尚未配置 DNS', 'accounts.emptyDNSDescription': '添加 lego 支持的 DNS 提供商和最小权限 API 凭据。',
    'accounts.emptyACME': '尚未配置 ACME', 'accounts.emptyACMEDescription': '保存邮箱、目录地址以及可选的 EAB 信息。',
    'accounts.credentials': '{count} 项凭据', 'accounts.eab': '已配置 EAB', 'accounts.standard': '标准账户',
    'accounts.encrypted': 'AES-256-GCM 加密', 'accounts.editDNS': '编辑 DNS 账户', 'accounts.editACME': '编辑 ACME 账户',
    'audit.title': '审计日志', 'audit.description': '部署、续期、同步、重试与节点变更均保留可追踪记录。',
    'audit.event': '事件', 'audit.target': '对象', 'audit.time': '时间', 'audit.level': '级别', 'audit.controller': '主控',
    'audit.success': '成功', 'audit.warning': '警告', 'audit.error': '错误', 'audit.info': '信息',
    'audit.empty': '暂无审计记录', 'audit.emptyDescription': '完成一次配置操作后会出现在这里。',
    'settings.title': '设置', 'settings.description': '管理管理员凭据、会话安全与运行边界。',
    'settings.appearance': '外观与语言', 'settings.theme': '颜色模式', 'settings.language': '界面语言',
    'settings.security': '证书安全', 'settings.securityDescription': '私钥与 DNS 凭据使用主密钥加密；节点私钥权限为 0600。',
    'settings.transport': '节点通信', 'settings.transportDescription': '一次性令牌注册，节点仅进行出站 HTTPS 轮询。',
    'settings.transaction': 'Nginx 事务', 'settings.transactionDescription': '写入后执行 nginx -t；验证或重载失败会恢复旧文件。',
    'settings.atomic': '原子回滚', 'settings.password': '管理员密码', 'settings.passwordDescription': '更改面板登录密码并立即撤销其他浏览器会话。',
    'settings.changePassword': '更改密码', 'settings.logout': '退出当前管理员会话',
    'dialog.nodeTitle': '添加 Linux 节点', 'dialog.nodeDescription': '生成短期一次性安装命令，在目标 VPS 上以 root 执行。',
    'dialog.nodeName': '节点名称', 'dialog.nodeNamePlaceholder': 'nanami-sakura', 'dialog.generate': '生成命令',
    'dialog.commandReady': '节点命令已就绪', 'dialog.copyCommand': '复制命令', 'dialog.copied': '已复制',
    'dialog.commandHint': '命令包含短期注册令牌，请勿发送到公开日志。',
    'dialog.dnsAddTitle': '添加 DNS 账户', 'dialog.dnsEditTitle': '编辑 DNS 账户',
    'dialog.dnsDescription': '保存 lego 提供商与环境变量凭据；建议使用仅可编辑 DNS 记录的令牌。',
    'dialog.accountName': '账户名称', 'dialog.provider': 'lego 提供商', 'dialog.credentials': '环境变量凭据',
    'dialog.addCredential': '增加', 'dialog.keepCredentials': '保留当前加密凭据', 'dialog.replaceCredentials': '替换凭据',
    'dialog.credentialName': '凭据变量 {index}', 'dialog.credentialValue': '凭据值 {index}', 'dialog.removeCredential': '移除此项',
    'dialog.credentialHint': 'API 列表只返回变量名，凭据值不会回传到浏览器。',
    'dialog.acmeAddTitle': '添加 ACME 账户', 'dialog.acmeEditTitle': '编辑 ACME 账户',
    'dialog.acmeDescription': '默认使用 Let’s Encrypt 生产目录，也支持需要 EAB 的兼容 ACME 服务。',
    'dialog.email': '联系邮箱', 'dialog.directory': 'ACME 目录', 'dialog.eab': '外部账户绑定（EAB）',
    'dialog.keepEAB': '保留现有 EAB 密钥', 'dialog.clearEAB': '清除 EAB', 'dialog.eabKID': 'EAB KID', 'dialog.eabHMAC': 'EAB HMAC',
    'dialog.syncTitle': '同步证书', 'dialog.syncDescription': '将 {domain} 的当前证书版本安全推送到其他节点。',
    'dialog.syncOnline': '在线，任务将立即领取', 'dialog.syncOffline': '离线，任务会保持排队',
    'dialog.syncProof': '每台节点都会独立校验证书、执行 nginx -t，并在失败时恢复旧文件。',
    'dialog.syncAction': '同步到 {count} 个节点', 'dialog.passwordTitle': '更改管理员密码',
    'dialog.passwordDescription': '保存后其他会话立即失效，当前浏览器会自动换取新会话。',
    'dialog.currentPassword': '当前密码', 'dialog.newPassword': '新密码', 'dialog.confirmPassword': '确认新密码',
    'dialog.passwordRule': '至少 12 个字符，建议使用密码管理器生成。', 'dialog.passwordMismatch': '两次输入的新密码不一致。',
    'dialog.changePassword': '更改密码', 'dialog.remove': '移除',
    'settings.quickPreferences': '外观与语言',
    'domain.routeHint': '选择节点，并将请求转发到项目监听端口。', 'domain.certificateHint': '复用已管理证书，或通过 DNS-01 申请新证书。',
    'domain.validationCertificate': '请选择一张覆盖该域名的已有证书。', 'domain.validationCloudflare': '请选择可用于编辑区域 DNS 的 Cloudflare 账户。',
    'domain.noMatchingCertificate': '没有覆盖该域名的证书', 'domain.cloudflareTitle': '同步 Cloudflare DNS',
    'domain.cloudflareHint': '创建或更新同名 A、AAAA 或 CNAME 记录。', 'domain.cloudflareAccount': 'Cloudflare 账户',
    'domain.recordContent': '记录内容', 'domain.recordAuto': '自动使用节点 IP', 'domain.proxyMode': '代理状态',
    'domain.orangeCloud': '橙云代理', 'domain.grayCloud': '仅 DNS', 'domain.observe': '仅监控', 'domain.takeover': '接管规则',
    'domain.takeoverUnavailable': '接管需要可识别的上游、受支持的配置路径，以及 TLS 站点的本地证书。',
    'domain.takeoverConfirmTitle': '接管现有 Nginx 规则？', 'domain.takeoverConfirmDescription': 'Atlas 会先备份 {path}，再为 {domain} 写入托管规则。只有 nginx -t 通过后才会重载；失败会恢复原文件。',
    'domain.takeoverConfirmAction': '备份并接管',
    'certificate.additionalNames': '证书覆盖域名', 'certificate.additionalNamesHint': '按 Enter 或逗号添加，支持 *.example.com；单张证书最多 20 个名称。',
    'certificate.validationAutomation': '请选择签发节点、DNS / ACME 账户，并设置 7–60 天的续期窗口。',
    'certificate.editAutomation': '编辑签发与续期', 'certificate.editAutomationHint': '管理 {domain} 的 SAN 域名、签发账户与自动续期。',
    'certificate.renewDays': '到期前续期（天）', 'certificate.namesCount': '{count} 个域名',
    'nodes.manage': '管理节点', 'nodes.manageTitle': '管理 {node}', 'nodes.manageDescription': '更新名称、发行版、系统软件包与节点代理。',
    'nodes.controller': '主控 VPS', 'nodes.manageControllerDescription': '更新主控与本机代理共用的发行版；验证完成后会自动重启两项服务。',
    'nodes.rename': '节点显示名称', 'nodes.atlasRelease': 'Nginx Atlas 发行版', 'nodes.controllerRelease': '主控与本机代理', 'nodes.versionPair': '当前 {current} · 最新 {latest}',
    'nodes.checkUpdate': '检查更新', 'nodes.updateAvailable': '可更新至 {version}', 'nodes.upToDate': '已是最新发行版',
    'nodes.updateAtlas': '更新 Atlas', 'nodes.confirmUpdate': '确认更新', 'nodes.systemUpdate': 'APT 与 Nginx 更新',
    'nodes.systemUpdateHint': '执行 apt update / upgrade，保留现有配置，再验证并重载 Nginx。', 'nodes.systemUpdateUnsupported': '当前仅支持基于 APT 的节点。',
    'nodes.updatePackages': '更新软件包', 'nodes.confirmSystemUpdate': '确认系统更新', 'nodes.uninstallTitle': '卸载节点代理',
    'nodes.uninstallHint': '命令只移除本项目的节点代理；Nginx、站点配置和 /etc/ssl 证书均会保留。', 'nodes.copyUninstall': '复制卸载命令',
    'nodes.reinstallTitle': '再次获取安装命令', 'nodes.reinstallHint': '在目标 Linux VPS 上执行此命令以接入或重新接入本主控。',
    'nodes.generateInstallCommand': '获取安装命令', 'nodes.copyInstall': '复制安装命令',
    'toast.domainQueued': '域名已加入部署队列；节点将先验证 Nginx 配置。',
    'toast.domainObserved': '已加入节点现有域名管理；原 Nginx 配置未修改。', 'toast.domainRemoved': '域名移除任务已排队。',
    'toast.observationRemoved': '已停止管理节点现有域名，原配置未修改。', 'toast.nodeRevoked': '节点凭据已撤销。',
    'toast.dnsSaved': 'DNS 账户已安全保存。', 'toast.acmeSaved': 'ACME 账户已保存。',
    'toast.certQueued': '证书任务已加入队列。', 'toast.certUploaded': '证书已验证并加入管理。',
    'toast.renewQueued': '{domain} 已加入 DNS-01 续期队列。', 'toast.autoRenewEnabled': '{domain} 已开启自动续期。', 'toast.autoRenewDisabled': '{domain} 已关闭自动续期。', 'toast.syncQueued': '证书已加入 {count} 个节点的同步队列。',
    'toast.passwordChanged': '管理员密码已更改，其他会话已撤销。',
    'toast.domainTakeoverQueued': '现有 Nginx 规则已加入安全接管队列。', 'toast.certificateAutomationSaved': '证书签发与续期设置已保存。',
    'toast.releaseChecked': '已读取最新 GitHub 发行版。', 'toast.nodeRenamed': '节点名称已更新。',
    'toast.atlasUpdateQueued': 'Atlas 更新任务已加入节点队列。', 'toast.systemUpdateQueued': 'APT 与 Nginx 更新任务已加入节点队列。',
    'error.dashboard': '无法读取主控状态', 'error.domain': '无法创建域名', 'error.adopt': '无法接管节点域名',
    'error.node': '无法生成节点命令', 'error.dns': '无法保存 DNS 账户', 'error.acme': '无法保存 ACME 账户',
    'error.certificate': '无法创建证书任务', 'error.password': '无法更改管理员密码',
    'error.removeDomain': '无法移除域名', 'error.revokeNode': '无法撤销节点', 'error.renew': '无法创建续期任务', 'error.autoRenew': '无法更改自动续期', 'error.sync': '无法创建同步任务',
    'error.takeover': '无法接管现有 Nginx 规则', 'error.certificateAutomation': '无法保存证书自动化设置',
    'error.release': '无法检查 GitHub 发行版', 'error.uninstallCommand': '无法生成卸载命令', 'error.renameNode': '无法更改节点名称',
    'error.atlasUpdate': '无法创建 Atlas 更新任务', 'error.systemUpdate': '无法创建系统更新任务',
  },
  en: {
    'common.add': 'Add', 'common.cancel': 'Cancel', 'common.save': 'Save', 'common.close': 'Close',
    'common.search': 'Search', 'common.edit': 'Edit', 'common.delete': 'Remove', 'common.refresh': 'Refresh',
    'common.online': 'Online', 'common.offline': 'Offline', 'common.pending': 'Pending', 'common.revoked': 'Revoked',
    'common.valid': 'Valid', 'common.expiring': 'Expiring soon', 'common.expired': 'Expired', 'common.none': 'None',
    'common.days': '{count} days', 'common.items': '{count} items', 'common.nodes': '{count} nodes',
    'common.loading': 'Loading infrastructure status', 'common.saving': 'Saving', 'common.queueing': 'Creating task',
    'common.noResults': 'No matching results', 'common.optional': 'Optional', 'common.select': 'Select',
    'common.system': 'System', 'common.light': 'Light', 'common.dark': 'Dark', 'common.chinese': '中文', 'common.english': 'English',
    'nav.overview': 'Overview', 'nav.domains': 'Domains & routes', 'nav.domainsShort': 'Domains', 'nav.certificates': 'Certificates',
    'nav.nodes': 'Nodes', 'nav.accounts': 'DNS / ACME', 'nav.audit': 'Audit log', 'nav.settings': 'Settings',
    'nav.main': 'Main navigation', 'nav.mobile': 'Mobile navigation', 'nav.open': 'Open navigation', 'nav.close': 'Close navigation',
    'app.allHealthy': 'All systems operational', 'app.waitingNode': 'Waiting for the first node', 'app.needsAttention': 'Some nodes need attention',
    'app.configVerified': 'Configuration verified', 'app.statusSynced': 'Status synchronized', 'app.refreshNow': 'Refresh now',
    'app.language': 'Language', 'app.theme': 'Theme', 'app.admin': 'Super administrator', 'app.logout': 'Sign out',
    'login.eyebrow': 'NGINX ORCHESTRATION', 'login.title': 'One control plane.\nEvery node aligned.',
    'login.description': 'Manage domains, certificates, and Linux nodes safely. Every change passes an Nginx integrity check.',
    'login.cardTitle': 'Administrator sign in', 'login.cardDescription': 'Enter the administrator password created during installation. The browser stores only a short-lived session token.',
    'login.password': 'Administrator password', 'login.passwordPlaceholder': 'Enter administrator password', 'login.submit': 'Open console',
    'login.submitting': 'Verifying', 'login.secure': 'The password is used only to establish a session and is not stored by the browser.',
    'login.tooShort': 'Enter an administrator password with at least 12 characters.', 'login.invalid': 'The password is invalid or the controller is unavailable.',
    'overview.title': 'Infrastructure, kept legible', 'overview.description': 'A unified view of nodes, domains, certificates, and recent changes.',
    'overview.nodesOnline': 'Nodes online', 'overview.allNormal': 'All healthy', 'overview.checkNeeded': 'Needs attention',
    'overview.certRisk': 'Certificate risk', 'overview.within30': 'Expires within 30 days', 'overview.noRisk': 'No current risk',
    'overview.routes': 'Domains & routes', 'overview.searchDomain': 'Search domains', 'overview.noDomain': 'No matching domains',
    'overview.noDomainDescription': 'Open Domains & routes to add the first route.', 'overview.adjustSearch': 'Try a different search term.',
    'overview.total': '{count} total', 'overview.viewAll': 'View all', 'overview.timeline': 'Certificate timeline',
    'overview.next90': 'Next 90 days', 'overview.nodeHealth': 'Node health', 'overview.activity': 'Recent activity',
    'overview.noActivity': 'No activity yet', 'overview.noActivityDescription': 'Deployments, renewals, and synchronization events will appear here.',
    'overview.noCertificates': 'No certificates yet', 'overview.noCertificatesDescription': 'Expiry windows will appear after a certificate is added.',
    'overview.viewCertificates': 'View certificates', 'overview.noNodes': 'No nodes yet', 'overview.noNodesDescription': 'Generate an enrollment command and run it on a Linux VPS.',
    'overview.viewNodes': 'View all nodes', 'overview.waitingReport': 'Awaiting report', 'overview.nginxUndetected': 'Nginx undetected',
    'overview.quickActions': 'Quick Actions & System Overview', 'overview.activeRoutes': 'Active Routes', 'overview.autoRenewCerts': 'Auto-renew Certificates',
    'domain.title': 'Domains & routes', 'domain.description': 'Map domains to project ports and deploy Nginx configuration transactionally.',
    'domain.add': 'Add domain', 'domain.editTitle': 'Edit domain & route', 'domain.updateSubmit': 'Save & reload', 'domain.searchPlaceholder': 'Search domain, node, or port', 'domain.managedTab': 'Managed',
    'domain.discoveredTab': 'Discovered', 'domain.discoveredTitle': 'Existing Nginx domains',
    'domain.discoveredDescription': 'Agents extract safe metadata from nginx -T. Observe without changes, or back up and safely take over the original rule.',
    'domain.adopt': 'Start monitoring', 'domain.adopted': 'Managed', 'domain.noDiscovered': 'No new node domains',
    'domain.noDiscoveredDescription': 'Nodes synchronize current server_name entries during their next poll.',
    'domain.empty': 'No domains yet', 'domain.emptyDescription': 'After a route is created, the agent runs nginx -t before reloading safely.',
    'domain.columnDomain': 'Domain', 'domain.columnRoute': 'Route target', 'domain.columnCert': 'Certificate',
    'domain.columnNode': 'Node', 'domain.columnState': 'State', 'domain.localConfig': 'Existing config',
    'domain.managedConfig': 'Atlas config', 'domain.configPath': 'Configuration file', 'domain.tls': 'TLS', 'domain.http': 'HTTP',
    'domain.showing': 'Showing {shown} of {total}', 'domain.transactionNote': 'Every managed change must pass nginx -t',
    'domain.removeTitle': 'Remove domain configuration?', 'domain.removeObservedTitle': 'Stop managing this domain?',
    'domain.removeDescription': 'The node will remove the managed configuration for {domain} and reload only after nginx -t succeeds. Certificate files remain.',
    'domain.removeObservedDescription': 'This removes {domain} only from Atlas. The node’s original Nginx configuration will not be changed.',
    'domain.removeTakenOverTitle': 'Stop takeover and restore the original rule?',
    'domain.removeTakenOverDescription': 'The node will remove the Atlas configuration for {domain}, restore the pre-takeover Nginx rule, and reload only after nginx -t passes. Certificates are preserved.',
    'domain.removeAction': 'Remove domain', 'domain.stopManaging': 'Stop managing', 'domain.restoreOriginal': 'Restore original rule',
    'domain.runtimeQueued': 'Queued', 'domain.runtimeRunning': 'Deploying', 'domain.runtimeFailed': 'Failed',
    'domain.runtimeActive': 'Running', 'domain.runtimePending': 'Pending', 'domain.unconnected': 'Not connected',
    'domain.certPending': 'Waiting for certificate', 'domain.httpOnlyShort': 'HTTP only',
    'domain.drawerKicker': 'Route deploy', 'domain.drawerSubtitle': 'Configure upstream, certificates, and optional Cloudflare DNS', 'domain.stepRoute': 'Route', 'domain.stepCertificate': 'Certificate', 'domain.stepDeploy': 'Deploy',
    'domain.targetNode': 'Target node', 'domain.upstreamHost': 'Upstream host', 'domain.projectPort': 'Project port', 'domain.certificateSource': 'Certificate source',
    'domain.existingCertificate': 'Existing certificate', 'domain.uploadCertificate': 'Upload certificate', 'domain.letsencrypt': "Let's Encrypt",
    'domain.certificateLocation': 'Certificate location', 'domain.localCertificate': 'Use target node /etc/ssl/{domain}', 'domain.controllerCertificate': 'Controller certificate · {domain} · {days} days',
    'domain.syncOthers': 'Sync to other nodes', 'domain.noOtherNodes': 'No other available nodes', 'domain.syncDescription': 'After deployment, push the certificate to selected nodes and validate/reload Nginx on each.',
    'domain.preview': 'Nginx configuration preview', 'domain.httpOnly': 'Create an HTTP route without TLS for now',
    'domain.deployProof': 'Deployment runs nginx -t first. If validation or reload fails, old configuration and certificates are restored.',
    'domain.offlineWarning': 'The target node is offline. The task remains queued until it reconnects.', 'domain.submit': 'Validate and deploy',
    'domain.validation': 'Enter a valid domain, target node, upstream host, and port.',
    'domain.validationFiles': 'Choose both fullchain.pem and privkey.pem.', 'domain.validationAccounts': 'Automatic issuance or renewal requires both DNS and ACME accounts.',
    'certificate.title': 'Certificates', 'certificate.description': 'Issue, renew, and distribute TLS certificates while checking every node copy.',
    'certificate.add': 'Add certificate', 'certificate.total': 'All certificates', 'certificate.expiringCount': 'Expiring soon',
    'certificate.autoRenewCount': 'Auto-renew', 'certificate.nodeCopies': 'Node copies',
    'certificate.searchPlaceholder': 'Search domain, issuer, or fingerprint', 'certificate.allStatuses': 'All statuses',
    'certificate.validOnly': 'Valid only', 'certificate.expiringOnly': 'Expiring / expired', 'certificate.empty': 'No certificates yet',
    'certificate.emptyDescription': 'Upload a certificate, issue one with DNS-01, or import one from a node.',
    'certificate.sourceACME': "Let's Encrypt / ACME", 'certificate.sourceUpload': 'Manual upload', 'certificate.sourceLocal': 'Imported from node',
    'certificate.expiry': 'Expiry', 'certificate.source': 'Source', 'certificate.autoRenew': 'Auto-renew',
    'certificate.distribution': 'Distribution', 'certificate.renew': 'Renew now', 'certificate.sync': 'Sync',
    'certificate.enabled': 'Enabled', 'certificate.disabled': 'Disabled', 'certificate.remaining': '{count} days remaining',
    'certificate.enableAutoRenew': 'Enable auto-renew for {domain}', 'certificate.disableAutoRenew': 'Disable auto-renew for {domain}',
    'certificate.automationUnavailable': 'Configure a signing node, DNS account, and ACME account first.',
    'certificate.renewConfirmTitle': 'Renew this certificate now?', 'certificate.renewConfirmDescription': '{domain} will request a new certificate through DNS-01. On success it will be written safely to the target node before Nginx is validated and reloaded.', 'certificate.renewConfirmAction': 'Confirm renewal',
    'certificate.fingerprint': 'SHA-256 fingerprint', 'certificate.modeUpload': 'Upload existing certificate',
    'certificate.modeUploadShort': 'Upload', 'certificate.modeIssue': 'Issue and auto-renew', 'certificate.modeIssueShort': 'Auto-issue',
    'certificate.modeImport': 'Import from node', 'certificate.modeImportShort': 'Node import',
    'certificate.modeUploadHint': 'Validate chain and private key', 'certificate.modeIssueHint': 'Use ACME DNS-01',
    'certificate.modeImportHint': 'Import from /etc/ssl', 'certificate.domain': 'Certificate domain',
    'certificate.signingNode': 'Signing node', 'certificate.sourceNode': 'Source node', 'certificate.nodeCertificate': 'Node certificate',
    'certificate.dnsAccount': 'DNS account', 'certificate.acmeAccount': 'ACME account',
    'certificate.syncNodes': 'Automatic distribution', 'certificate.syncHint': 'After issuance or import, push to selected nodes and validate/reload Nginx on each.',
    'certificate.renewToggle': 'Renew before expiry', 'certificate.renewHint': 'Run DNS-01 automatically inside the {days}-day expiry window.',
    'certificate.fullchain': 'fullchain.pem', 'certificate.privkey': 'privkey.pem', 'certificate.chooseFile': 'Choose PEM file',
    'certificate.submitUpload': 'Validate and add', 'certificate.submitIssue': 'Issue certificate', 'certificate.submitImport': 'Import certificate',
    'certificate.noNodeCertificates': 'This node has not reported any valid certificates that can be imported.',
    'certificate.validationDomain': 'Enter a valid certificate domain.', 'certificate.validationFiles': 'Choose both fullchain.pem and privkey.pem.',
    'certificate.validationNode': 'Select an available node.', 'certificate.validationAccounts': 'Select both a DNS account and an ACME account.',
    'nodes.title': 'Nodes', 'nodes.description': 'Nodes connect outbound to the controller; no additional public management port is required.',
    'nodes.add': 'Add node', 'nodes.empty': 'No Linux nodes yet', 'nodes.emptyDescription': 'Generate a one-time installation command and run it on the target VPS.',
    'nodes.command': 'Generate command', 'nodes.hostnamePending': 'Waiting for hostname', 'nodes.addresses': 'Public / private addresses',
    'nodes.nginx': 'Nginx', 'nodes.platform': 'Platform', 'nodes.certDirectory': 'Certificate directory', 'nodes.certFound': '{count} discovered',
    'nodes.siteFound': '{count} domains', 'nodes.lastSeen': 'Last seen: {time}', 'nodes.never': 'Never connected',
    'nodes.revoke': 'Revoke node', 'nodes.revokeTitle': 'Revoke node access?',
    'nodes.revokeDescription': '{node} will no longer receive tasks. Existing Nginx configuration and certificates on the node will remain.',
    'accounts.title': 'DNS / ACME', 'accounts.description': 'Keep only the fields required for issuance; sensitive values always remain encrypted.',
    'accounts.dnsTitle': 'DNS accounts', 'accounts.acmeTitle': 'ACME accounts', 'accounts.addDNS': 'Add DNS account',
    'accounts.addACME': 'Add ACME account', 'accounts.emptyDNS': 'No DNS account configured', 'accounts.emptyDNSDescription': 'Add a lego-supported DNS provider with least-privilege API credentials.',
    'accounts.emptyACME': 'No ACME account configured', 'accounts.emptyACMEDescription': 'Store an email, directory URL, and optional EAB details.',
    'accounts.credentials': '{count} credentials', 'accounts.eab': 'EAB configured', 'accounts.standard': 'Standard account',
    'accounts.encrypted': 'AES-256-GCM encrypted', 'accounts.editDNS': 'Edit DNS account', 'accounts.editACME': 'Edit ACME account',
    'audit.title': 'Audit log', 'audit.description': 'Deployments, renewals, synchronization, retries, and node changes remain traceable.',
    'audit.event': 'Event', 'audit.target': 'Target', 'audit.time': 'Time', 'audit.level': 'Level', 'audit.controller': 'Controller',
    'audit.success': 'Success', 'audit.warning': 'Warning', 'audit.error': 'Error', 'audit.info': 'Info',
    'audit.empty': 'No audit events', 'audit.emptyDescription': 'Events will appear after the first configuration operation.',
    'settings.title': 'Settings', 'settings.description': 'Manage administrator credentials, session security, and runtime boundaries.',
    'settings.appearance': 'Appearance & language', 'settings.theme': 'Color mode', 'settings.language': 'Interface language',
    'settings.security': 'Certificate security', 'settings.securityDescription': 'Private keys and DNS credentials are encrypted; node private keys use mode 0600.',
    'settings.transport': 'Node communication', 'settings.transportDescription': 'One-time enrollment tokens; nodes use outbound HTTPS polling only.',
    'settings.transaction': 'Nginx transaction', 'settings.transactionDescription': 'Run nginx -t after writes and restore old files if validation or reload fails.',
    'settings.atomic': 'Atomic rollback', 'settings.password': 'Administrator password', 'settings.passwordDescription': 'Change the panel password and revoke other browser sessions immediately.',
    'settings.changePassword': 'Change password', 'settings.logout': 'Sign out of this administrator session',
    'dialog.nodeTitle': 'Add Linux node', 'dialog.nodeDescription': 'Generate a short-lived one-time installation command and run it as root on the target VPS.',
    'dialog.nodeName': 'Node name', 'dialog.nodeNamePlaceholder': 'nanami-sakura', 'dialog.generate': 'Generate command',
    'dialog.commandReady': 'Node command is ready', 'dialog.copyCommand': 'Copy command', 'dialog.copied': 'Copied',
    'dialog.commandHint': 'The command contains a short-lived enrollment token. Do not paste it into public logs.',
    'dialog.dnsAddTitle': 'Add DNS account', 'dialog.dnsEditTitle': 'Edit DNS account',
    'dialog.dnsDescription': 'Store the lego provider and environment credentials. Prefer a token limited to DNS record edits.',
    'dialog.accountName': 'Account name', 'dialog.provider': 'lego provider', 'dialog.credentials': 'Environment credentials',
    'dialog.addCredential': 'Add', 'dialog.keepCredentials': 'Keep current encrypted credentials', 'dialog.replaceCredentials': 'Replace credentials',
    'dialog.credentialName': 'Credential variable {index}', 'dialog.credentialValue': 'Credential value {index}', 'dialog.removeCredential': 'Remove this credential',
    'dialog.credentialHint': 'API responses return variable names only; secret values never return to the browser.',
    'dialog.acmeAddTitle': 'Add ACME account', 'dialog.acmeEditTitle': 'Edit ACME account',
    'dialog.acmeDescription': 'Uses the Let’s Encrypt production directory by default and supports ACME services that require EAB.',
    'dialog.email': 'Contact email', 'dialog.directory': 'ACME directory', 'dialog.eab': 'External Account Binding (EAB)',
    'dialog.keepEAB': 'Keep existing EAB secret', 'dialog.clearEAB': 'Clear EAB', 'dialog.eabKID': 'EAB KID', 'dialog.eabHMAC': 'EAB HMAC',
    'dialog.syncTitle': 'Sync certificate', 'dialog.syncDescription': 'Push the current {domain} certificate safely to other nodes.',
    'dialog.syncOnline': 'Online; task will be picked up immediately', 'dialog.syncOffline': 'Offline; task will remain queued',
    'dialog.syncProof': 'Each node validates the certificate, runs nginx -t, and restores old files if validation fails.',
    'dialog.syncAction': 'Sync to {count} nodes', 'dialog.passwordTitle': 'Change administrator password',
    'dialog.passwordDescription': 'Other sessions are revoked immediately; this browser receives a replacement session automatically.',
    'dialog.currentPassword': 'Current password', 'dialog.newPassword': 'New password', 'dialog.confirmPassword': 'Confirm new password',
    'dialog.passwordRule': 'At least 12 characters. A password manager is recommended.', 'dialog.passwordMismatch': 'The new passwords do not match.',
    'dialog.changePassword': 'Change password', 'dialog.remove': 'Remove',
    'settings.quickPreferences': 'Appearance & language',
    'domain.routeHint': 'Choose a node and forward traffic to the project port.', 'domain.certificateHint': 'Reuse a managed certificate or request a new one with DNS-01.',
    'domain.validationCertificate': 'Select an existing certificate that covers this domain.', 'domain.validationCloudflare': 'Select a Cloudflare account with Zone DNS edit access.',
    'domain.noMatchingCertificate': 'No certificate covers this domain', 'domain.cloudflareTitle': 'Sync Cloudflare DNS',
    'domain.cloudflareHint': 'Create or update the matching A, AAAA, or CNAME record.', 'domain.cloudflareAccount': 'Cloudflare account',
    'domain.recordContent': 'Record content', 'domain.recordAuto': 'Use node IP automatically', 'domain.proxyMode': 'Proxy status',
    'domain.orangeCloud': 'Proxied', 'domain.grayCloud': 'DNS only', 'domain.observe': 'Observe only', 'domain.takeover': 'Take over',
    'domain.takeoverUnavailable': 'Takeover requires a recognized upstream, a supported config path, and a local certificate for TLS sites.',
    'domain.takeoverConfirmTitle': 'Take over this Nginx rule?', 'domain.takeoverConfirmDescription': 'Atlas backs up {path}, then writes a managed rule for {domain}. It reloads only after nginx -t succeeds and restores the original file on failure.',
    'domain.takeoverConfirmAction': 'Back up and take over',
    'certificate.additionalNames': 'Certificate names', 'certificate.additionalNamesHint': 'Press Enter or comma to add a name. Wildcards such as *.example.com are supported; limit 20.',
    'certificate.validationAutomation': 'Choose a signing node, DNS / ACME accounts, and a renewal window from 7 to 60 days.',
    'certificate.editAutomation': 'Edit issuance & renewal', 'certificate.editAutomationHint': 'Manage SAN names, signing accounts, and auto-renew for {domain}.',
    'certificate.renewDays': 'Renew before expiry (days)', 'certificate.namesCount': '{count} names',
    'nodes.manage': 'Manage node', 'nodes.manageTitle': 'Manage {node}', 'nodes.manageDescription': 'Update its name, release, system packages, and node agent.',
    'nodes.controller': 'Controller VPS', 'nodes.manageControllerDescription': 'Updates the binary shared by the controller and local agent, then restarts both services after verification.',
    'nodes.rename': 'Node display name', 'nodes.atlasRelease': 'Nginx Atlas release', 'nodes.controllerRelease': 'Controller & local agent', 'nodes.versionPair': 'Current {current} · latest {latest}',
    'nodes.checkUpdate': 'Check update', 'nodes.updateAvailable': 'Update to {version}', 'nodes.upToDate': 'Latest release installed',
    'nodes.updateAtlas': 'Update Atlas', 'nodes.confirmUpdate': 'Confirm update', 'nodes.systemUpdate': 'APT & Nginx update',
    'nodes.systemUpdateHint': 'Runs apt update / upgrade, preserves current config, then validates and reloads Nginx.', 'nodes.systemUpdateUnsupported': 'Only APT-based nodes are currently supported.',
    'nodes.updatePackages': 'Update packages', 'nodes.confirmSystemUpdate': 'Confirm system update', 'nodes.uninstallTitle': 'Uninstall node agent',
    'nodes.uninstallHint': 'This command removes only the project node agent; Nginx, site rules, and /etc/ssl certificates remain.', 'nodes.copyUninstall': 'Copy uninstall command',
    'nodes.reinstallTitle': 'Re-obtain Install Command', 'nodes.reinstallHint': 'Run this command on the target Linux VPS to enroll or re-enroll with this controller.',
    'nodes.generateInstallCommand': 'Get Install Command', 'nodes.copyInstall': 'Copy Install Command',
    'toast.domainQueued': 'Domain queued for deployment; the node will validate Nginx first.',
    'toast.domainObserved': 'Existing node domain added to management; its original Nginx configuration was not modified.', 'toast.domainRemoved': 'Domain removal task queued.',
    'toast.observationRemoved': 'Stopped managing the existing node domain; its original configuration was not modified.', 'toast.nodeRevoked': 'Node credentials revoked.',
    'toast.dnsSaved': 'DNS account saved securely.', 'toast.acmeSaved': 'ACME account saved.',
    'toast.certQueued': 'Certificate task queued.', 'toast.certUploaded': 'Certificate validated and added to management.',
    'toast.renewQueued': '{domain} queued for DNS-01 renewal.', 'toast.autoRenewEnabled': 'Auto-renew enabled for {domain}.', 'toast.autoRenewDisabled': 'Auto-renew disabled for {domain}.', 'toast.syncQueued': 'Certificate queued for synchronization to {count} nodes.',
    'toast.passwordChanged': 'Administrator password changed; other sessions were revoked.',
    'toast.domainTakeoverQueued': 'Existing Nginx rule queued for safe takeover.', 'toast.certificateAutomationSaved': 'Certificate issuance and renewal settings saved.',
    'toast.releaseChecked': 'Latest GitHub release checked.', 'toast.nodeRenamed': 'Node name updated.',
    'toast.atlasUpdateQueued': 'Atlas update queued on the node.', 'toast.systemUpdateQueued': 'APT and Nginx update queued on the node.',
    'error.dashboard': 'Unable to load controller status', 'error.domain': 'Unable to create domain', 'error.adopt': 'Unable to adopt node domain',
    'error.node': 'Unable to generate node command', 'error.dns': 'Unable to save DNS account', 'error.acme': 'Unable to save ACME account',
    'error.certificate': 'Unable to create certificate task', 'error.password': 'Unable to change administrator password',
    'error.removeDomain': 'Unable to remove domain', 'error.revokeNode': 'Unable to revoke node', 'error.renew': 'Unable to create renewal task', 'error.autoRenew': 'Unable to change auto-renew', 'error.sync': 'Unable to create sync task',
    'error.takeover': 'Unable to take over the existing Nginx rule', 'error.certificateAutomation': 'Unable to save certificate automation settings',
    'error.release': 'Unable to check the GitHub release', 'error.uninstallCommand': 'Unable to generate uninstall command', 'error.renameNode': 'Unable to rename node',
    'error.atlasUpdate': 'Unable to queue the Atlas update', 'error.systemUpdate': 'Unable to queue the system update',
  },
}

const PreferencesContext = createContext<PreferencesValue | null>(null)
const themeKey = 'nginx-atlas-theme'
const languageKey = 'nginx-atlas-language'

function readPreference<T extends string>(key: string, allowed: readonly T[], fallback: T): T {
  try {
    const value = localStorage.getItem(key) as T | null
    return value && allowed.includes(value) ? value : fallback
  } catch {
    return fallback
  }
}

function systemLanguage(): EffectiveLanguage {
  return navigator.language.toLowerCase().startsWith('zh') ? 'zh' : 'en'
}

export function PreferencesProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<ThemeMode>(() => readPreference(themeKey, ['system', 'light', 'dark'], 'system'))
  const [language, setLanguageState] = useState<LanguageMode>(() => readPreference(languageKey, ['system', 'zh', 'en'], 'system'))
  const [systemDark, setSystemDark] = useState(() => window.matchMedia('(prefers-color-scheme: dark)').matches)
  const [detectedLanguage, setDetectedLanguage] = useState<EffectiveLanguage>(systemLanguage)

  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: dark)')
    const update = () => setSystemDark(media.matches)
    media.addEventListener('change', update)
    return () => media.removeEventListener('change', update)
  }, [])

  useEffect(() => {
    const update = () => setDetectedLanguage(systemLanguage())
    window.addEventListener('languagechange', update)
    return () => window.removeEventListener('languagechange', update)
  }, [])

  const effectiveTheme = theme === 'system' ? (systemDark ? 'dark' : 'light') : theme
  const effectiveLanguage = language === 'system' ? detectedLanguage : language
  const locale = effectiveLanguage === 'zh' ? 'zh-CN' : 'en-US'

  useEffect(() => {
    document.documentElement.dataset.theme = effectiveTheme
    document.documentElement.lang = effectiveLanguage === 'zh' ? 'zh-CN' : 'en'
    document.documentElement.style.colorScheme = effectiveTheme
  }, [effectiveTheme, effectiveLanguage])

  const setTheme = useCallback((value: ThemeMode) => {
    setThemeState(value)
    try { localStorage.setItem(themeKey, value) } catch { /* Preference remains active for this page. */ }
  }, [])

  const setLanguage = useCallback((value: LanguageMode) => {
    setLanguageState(value)
    try { localStorage.setItem(languageKey, value) } catch { /* Preference remains active for this page. */ }
  }, [])

  const t = useCallback((key: string, variables: Variables = {}) => {
    const template = messages[effectiveLanguage][key] ?? messages.zh[key] ?? key
    return Object.entries(variables).reduce((value, [name, replacement]) => value.replaceAll(`{${name}}`, String(replacement)), template)
  }, [effectiveLanguage])

  const value = useMemo<PreferencesValue>(() => ({
    theme, effectiveTheme, language, effectiveLanguage, locale, setTheme, setLanguage, t,
  }), [theme, effectiveTheme, language, effectiveLanguage, locale, setTheme, setLanguage, t])

  return <PreferencesContext.Provider value={value}>{children}</PreferencesContext.Provider>
}

export function usePreferences(): PreferencesValue {
  const value = useContext(PreferencesContext)
  if (!value) throw new Error('usePreferences must be used inside PreferencesProvider')
  return value
}
