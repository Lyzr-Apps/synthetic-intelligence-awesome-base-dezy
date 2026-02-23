'use client'

import React, { useState, useEffect, useRef, useCallback } from 'react'
import { callAIAgent } from '@/lib/aiAgent'
import { FiSend, FiPlus, FiMenu, FiX, FiChevronDown, FiChevronUp, FiTarget, FiBookOpen, FiBarChart2, FiZap, FiSearch, FiMessageSquare, FiTrash2, FiCommand, FiClock } from 'react-icons/fi'

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

const MANAGER_AGENT_ID = '699c465de4f4977cc58d9621'

const STORAGE_KEY = 'susit_conversations'

const EXAMPLE_PROMPTS = [
  'Help me create a career transition plan from engineering to product management',
  'What are the key trends in AI and how will they impact the job market?',
  'Should I start a business or continue in my corporate career?',
  'I am stuck on how to scale my side project - help me think differently',
]

const AGENT_INFO = [
  { name: 'Taskmaster Orchestrator', role: 'Manager - routes to sub-agents', id: MANAGER_AGENT_ID },
  { name: 'Strategic Planner', role: 'Phased action plans and roadmaps', id: '699c462438754b2ac5e88a3a' },
  { name: 'Knowledge Synthesizer', role: 'Research and knowledge summaries', id: '699c462423f6c95dc50e8c8d' },
  { name: 'Decision Analyst', role: 'Decision frameworks and scoring', id: '699c464938754b2ac5e88a6c' },
  { name: 'Creative Problem Solver', role: 'Lateral thinking and novel solutions', id: '699c4625889152efca4690d4' },
]

// ── Domain Config ──────────────────────────────────────────────────

const domainConfig: Record<string, { icon: React.ComponentType<{ className?: string }>, colorClass: string, bgClass: string }> = {
  'Strategic': { icon: FiTarget, colorClass: 'text-purple-400', bgClass: 'bg-purple-400/10 border-purple-400/20' },
  'Knowledge': { icon: FiBookOpen, colorClass: 'text-blue-400', bgClass: 'bg-blue-400/10 border-blue-400/20' },
  'Decision': { icon: FiBarChart2, colorClass: 'text-amber-400', bgClass: 'bg-amber-400/10 border-amber-400/20' },
  'Creative': { icon: FiZap, colorClass: 'text-emerald-400', bgClass: 'bg-emerald-400/10 border-emerald-400/20' },
}

// ── Helpers ─────────────────────────────────────────────────────────

function generateId(): string {
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15)
}

function formatInline(text: string): React.ReactNode {
  const parts = text.split(/\*\*(.*?)\*\*/g)
  if (parts.length === 1) return text
  return parts.map((part, i) =>
    i % 2 === 1 ? (
      <strong key={i} className="font-semibold">{part}</strong>
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

// ── Inline Components ───────────────────────────────────────────────

function DomainBadge({ domain }: { domain: string }) {
  const config = domainConfig[domain]
  if (!config) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium border bg-muted/50 border-border text-muted-foreground">
        {domain}
      </span>
    )
  }
  const IconComp = config.icon
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium border ${config.bgClass} ${config.colorClass}`}>
      <IconComp className="w-3 h-3" />
      {domain}
    </span>
  )
}

function ExpandableSection({ section, defaultOpen }: { section: { domain: string; title: string; content: string }, defaultOpen?: boolean }) {
  const [isOpen, setIsOpen] = useState(defaultOpen ?? false)
  const config = domainConfig[section.domain]
  const IconComp = config?.icon ?? FiCommand
  const iconColor = config?.colorClass ?? 'text-muted-foreground'

  return (
    <div className="border border-border rounded-xl overflow-hidden bg-card/50">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-muted/30 transition-colors duration-200"
      >
        <div className="flex items-center gap-2.5">
          <IconComp className={`w-4 h-4 ${iconColor}`} />
          <span className="text-sm font-semibold text-foreground">{section.title || section.domain}</span>
          {section.domain && (
            <span className={`text-xs px-1.5 py-0.5 rounded ${config?.bgClass ?? 'bg-muted/50'} ${iconColor}`}>
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
      <FiZap className="w-3 h-3 text-accent" />
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
      <div className="flex gap-3 px-4 py-3 max-w-3xl mx-auto">
        <div className="w-8 h-8 rounded-xl bg-accent/20 flex items-center justify-center flex-shrink-0 mt-0.5">
          <FiCommand className="w-4 h-4 text-accent" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-xs font-medium text-muted-foreground mb-2">S.U.S.I.T.</div>
          <div className="bg-card border border-border rounded-xl p-4">
            <LoadingDots />
            <p className="text-xs text-muted-foreground mt-2">Analyzing your request and activating intelligence domains...</p>
          </div>
        </div>
      </div>
    )
  }

  if (!parsed) {
    return (
      <div className="flex gap-3 px-4 py-3 max-w-3xl mx-auto">
        <div className="w-8 h-8 rounded-xl bg-accent/20 flex items-center justify-center flex-shrink-0 mt-0.5">
          <FiCommand className="w-4 h-4 text-accent" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-xs font-medium text-muted-foreground mb-2">S.U.S.I.T.</div>
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

  return (
    <div className="flex gap-3 px-4 py-3 max-w-3xl mx-auto">
      <div className="w-8 h-8 rounded-xl bg-accent/20 flex items-center justify-center flex-shrink-0 mt-0.5">
        <FiCommand className="w-4 h-4 text-accent" />
      </div>
      <div className="flex-1 min-w-0 space-y-3">
        <div className="text-xs font-medium text-muted-foreground">S.U.S.I.T.</div>

        {/* Domain Badges */}
        {domains.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {domains.map((d, i) => (
              <DomainBadge key={i} domain={d} />
            ))}
          </div>
        )}

        {/* Summary */}
        {parsed.summary && (
          <div className="bg-card border border-border rounded-xl p-4">
            {renderMarkdown(parsed.summary)}
          </div>
        )}

        {/* Intent Analysis */}
        {parsed.intent_analysis && (
          <div className="bg-secondary/30 border border-border/50 rounded-xl p-3">
            <div className="text-xs font-semibold text-muted-foreground mb-1 uppercase tracking-wider">Intent Analysis</div>
            <p className="text-sm text-foreground/80">{parsed.intent_analysis}</p>
          </div>
        )}

        {/* Expandable Sections */}
        {sections.length > 0 && (
          <div className="space-y-2">
            {sections.map((section, i) => (
              <ExpandableSection key={i} section={section} defaultOpen={i === 0} />
            ))}
          </div>
        )}

        {/* Proactive Suggestions */}
        {suggestions.length > 0 && (
          <div className="space-y-2">
            <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Suggestions to explore</div>
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
    <div className="flex justify-end px-4 py-3 max-w-3xl mx-auto">
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
  return (
    <div className="flex-1 flex items-center justify-center p-8">
      <div className="max-w-xl w-full text-center space-y-8">
        <div className="space-y-3">
          <div className="w-16 h-16 rounded-2xl bg-accent/20 flex items-center justify-center mx-auto mb-4">
            <FiCommand className="w-8 h-8 text-accent" />
          </div>
          <h1 className="text-3xl font-bold tracking-tight text-foreground">
            Welcome to S.U.S.I.T.
          </h1>
          <p className="text-muted-foreground text-sm leading-relaxed max-w-md mx-auto">
            Your personal intelligence command center. I can help you plan strategies,
            research topics, analyze decisions, and solve problems creatively.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {EXAMPLE_PROMPTS.map((prompt, i) => {
            const icons = [FiTarget, FiBookOpen, FiBarChart2, FiZap]
            const colors = ['text-purple-400', 'text-blue-400', 'text-amber-400', 'text-emerald-400']
            const IconComp = icons[i] ?? FiCommand
            const color = colors[i] ?? 'text-muted-foreground'
            return (
              <button
                key={i}
                onClick={() => onPromptClick(prompt)}
                className="group flex items-start gap-3 p-4 rounded-xl border border-border bg-card/50 hover:bg-card hover:border-accent/30 text-left transition-all duration-200 hover:shadow-lg hover:shadow-accent/5"
              >
                <IconComp className={`w-4 h-4 mt-0.5 flex-shrink-0 ${color}`} />
                <span className="text-sm text-foreground/80 group-hover:text-foreground leading-snug">{prompt}</span>
              </button>
            )
          })}
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
          {conv.title || 'New conversation'}
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
            <h2 className="text-xl font-semibold mb-2">Something went wrong</h2>
            <p className="text-muted-foreground mb-4 text-sm">{this.state.error}</p>
            <button
              onClick={() => this.setState({ hasError: false, error: '' })}
              className="px-4 py-2 bg-primary text-primary-foreground rounded-md text-sm"
            >
              Try again
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
      title: 'New conversation',
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
        title: trimmed.slice(0, 50),
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
          title: isFirstMsg ? trimmed.slice(0, 50) : c.title,
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
        fallbackContent = result?.error ?? result?.response?.message ?? 'An error occurred while processing your request. Please try again.'
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
        content: 'An unexpected error occurred. Please try again.',
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
  const sampleMessages: Message[] = [
    {
      id: 'sample-1',
      role: 'user',
      content: 'Help me create a career transition plan from engineering to product management',
      timestamp: new Date(Date.now() - 300000).toISOString(),
    },
    {
      id: 'sample-2',
      role: 'assistant',
      content: '',
      parsedResponse: {
        intent_analysis: 'User seeks a structured career transition roadmap from engineering to product management, requiring strategic planning, knowledge synthesis about the PM role, and creative approaches to bridge the gap.',
        domains_activated: ['Strategic', 'Knowledge', 'Creative'],
        response_sections: [
          {
            domain: 'Strategic',
            title: 'Career Transition Roadmap',
            content: '## Phase 1: Foundation (Months 1-3)\n- **Assess transferable skills**: Map your engineering skills to PM competencies\n- **Build PM knowledge**: Take courses on product strategy, user research, and agile methodologies\n- **Network strategically**: Connect with PMs at your current company and in your network\n\n## Phase 2: Experience Building (Months 3-6)\n- **Lead cross-functional projects**: Volunteer for product-adjacent work\n- **Create a portfolio**: Document products you have influenced or side projects\n- **Seek internal opportunities**: Explore PM openings within your current organization\n\n## Phase 3: Transition (Months 6-12)\n- **Apply externally**: Target companies that value engineering backgrounds in PMs\n- **Prepare for interviews**: Practice PM case studies and product sense questions\n- **Negotiate effectively**: Leverage your technical depth as a differentiator',
          },
          {
            domain: 'Knowledge',
            title: 'Key PM Skills and Resources',
            content: '### Essential Skills to Develop\n- **Product Strategy**: Understanding market dynamics, competitive analysis, and product vision\n- **User Research**: Conducting interviews, surveys, and usability tests\n- **Data Analysis**: Using metrics to drive decisions (your engineering background helps here)\n- **Communication**: Storytelling, stakeholder management, and writing PRDs\n\n### Recommended Resources\n- Inspired by Marty Cagan\n- Product Management courses on Reforge\n- The Product Manager Interview by Lewis C. Lin',
          },
          {
            domain: 'Creative',
            title: 'Unconventional Approaches',
            content: '### Think Differently About Your Transition\n- **Build a product**: Launch a small side product to demonstrate PM thinking end-to-end\n- **Write publicly**: Blog about the intersection of engineering and product management\n- **Reverse mentor**: Offer technical mentorship to PMs in exchange for product mentorship\n- **Create a transition case study**: Document your own transition as if it were a product launch with metrics and milestones',
          },
        ],
        proactive_suggestions: [
          'What specific engineering skills should I highlight in PM interviews?',
          'Help me draft a 90-day plan for my first PM role',
          'What are common mistakes engineers make when transitioning to PM?',
        ],
        summary: 'I have created a comprehensive 12-month career transition plan from engineering to product management. The plan covers three phases: building your foundation, gaining experience, and making the actual transition. I have also identified key skills to develop, recommended resources, and suggested some creative approaches to stand out in your transition.',
      },
      timestamp: new Date(Date.now() - 240000).toISOString(),
    },
  ]

  const displayMessages = sampleData && messages.length === 0 ? sampleMessages : messages
  const showWelcome = displayMessages.length === 0

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
              <div className="w-8 h-8 rounded-xl bg-accent/20 flex items-center justify-center">
                <FiCommand className="w-4 h-4 text-accent" />
              </div>
              <div>
                <h1 className="text-base font-bold tracking-tight text-foreground leading-none">S.U.S.I.T.</h1>
                <p className="text-xs text-muted-foreground hidden sm:block">Synthetic Ultimate Supreme Intelligence Taskmaster AI</p>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {/* Sample Data Toggle */}
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <span className="text-xs text-muted-foreground">Sample Data</span>
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
              title="Agent information"
            >
              <FiCommand className="w-4 h-4" />
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
                  New Chat
                </button>
                <div className="relative">
                  <FiSearch className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search conversations..."
                    className="w-full pl-9 pr-3 py-2 rounded-lg bg-muted/30 border border-border text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-1 focus:ring-accent/50 focus:border-accent/30 transition-colors"
                  />
                </div>
              </div>
              <div className="flex-1 overflow-y-auto px-2 pb-2 space-y-0.5">
                {filteredConversations.length === 0 && (
                  <div className="text-center py-8 text-muted-foreground/50 text-xs">
                    {searchQuery ? 'No matching conversations' : 'No conversations yet'}
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
            {showAgentInfo && (
              <div className="border-b border-border bg-card/50 px-4 py-3 flex-shrink-0">
                <div className="max-w-3xl mx-auto">
                  <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Intelligence Agents</div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                    {AGENT_INFO.map((agent) => (
                      <div
                        key={agent.id}
                        className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-xs ${activeAgentId === agent.id ? 'border-accent/40 bg-accent/10' : 'border-border/50 bg-muted/20'}`}
                      >
                        <div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${activeAgentId === agent.id ? 'bg-accent animate-pulse' : 'bg-muted-foreground/30'}`} />
                        <div className="min-w-0">
                          <div className="font-medium text-foreground/90 truncate">{agent.name}</div>
                          <div className="text-muted-foreground/60 truncate">{agent.role}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

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
              <div className="max-w-3xl mx-auto">
                <div className="flex items-end gap-3 bg-muted/30 border border-border rounded-xl p-2 focus-within:ring-1 focus-within:ring-accent/50 focus-within:border-accent/30 transition-all duration-200">
                  <textarea
                    ref={textareaRef}
                    value={inputValue}
                    onChange={handleTextareaChange}
                    onKeyDown={handleKeyDown}
                    placeholder="Ask me anything - plan a goal, research a topic, make a decision, solve a problem..."
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
