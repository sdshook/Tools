/*
 * Chatdisco YARA rules
 * AI service identification in memory dumps, process dumps,
 * prefetch files, pagefile, and disk artifacts.
 *
 * Usage: yara -r chatdisco_ai_services.yar <target>
 */

import "pe"

/* ── OpenAI / ChatGPT ───────────────────────────────────────────── */

rule ChatGPT_API_Endpoint {
    meta:
        description = "OpenAI ChatGPT API endpoint references"
        service     = "openai_chatgpt"
        confidence  = "high"
    strings:
        $api1 = "api.openai.com/v1/chat/completions" nocase ascii wide
        $api2 = "api.openai.com/v1/messages" nocase ascii wide
        $api3 = "backend-api/conversation" nocase ascii wide
        $api4 = "chat.openai.com" nocase ascii wide
        $api5 = "chatgpt.com" nocase ascii wide
    condition:
        any of them
}

rule ChatGPT_Session_Token {
    meta:
        description = "OpenAI session token cookie patterns"
        service     = "openai_chatgpt"
        confidence  = "high"
        artifact    = "authentication"
    strings:
        $tok1 = "__Secure-next-auth.session-token" ascii wide
        $tok2 = "__Secure-next-auth.callback-url" ascii wide
        $tok3 = "_puid" ascii wide
        $tok4 = "Bearer sk-" ascii wide
    condition:
        any of them
}

rule ChatGPT_API_Key {
    meta:
        description = "OpenAI API key pattern (sk-...)"
        service     = "openai_chatgpt"
        confidence  = "high"
        artifact    = "api_key"
    strings:
        $key = /sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}/ ascii wide
        $key2 = /sk-proj-[A-Za-z0-9_\-]{80,120}/ ascii wide
        $key3 = /sk-svcacct-[A-Za-z0-9_\-]{80,120}/ ascii wide
    condition:
        any of them
}

rule ChatGPT_SSE_Response {
    meta:
        description = "OpenAI SSE streaming response fragments"
        service     = "openai_chatgpt"
        confidence  = "medium"
    strings:
        $sse1 = "data: {\"id\":\"chatcmpl-" ascii
        $sse2 = "\"object\":\"chat.completion.chunk\"" ascii
        $sse3 = "\"delta\":{\"content\":" ascii
        $sse4 = "\"finish_reason\":\"stop\"" ascii
        $sse5 = "data: [DONE]" ascii
    condition:
        2 of them
}

rule ChatGPT_Conversation_JSON {
    meta:
        description = "ChatGPT conversation data structure"
        service     = "openai_chatgpt"
        confidence  = "medium"
    strings:
        $j1 = "\"conversation_id\":" ascii
        $j2 = "\"mapping\":" ascii
        $j3 = "\"moderation_results\":" ascii
        $j4 = "\"parent_id\":" ascii
    condition:
        3 of them
}

/* ── Anthropic / Claude ─────────────────────────────────────────── */

rule Claude_API_Endpoint {
    meta:
        description = "Anthropic Claude API endpoint references"
        service     = "anthropic_claude"
        confidence  = "high"
    strings:
        $api1 = "api.anthropic.com/v1/messages" nocase ascii wide
        $api2 = "api.anthropic.com/v1/complete" nocase ascii wide
        $api3 = "claude.ai/api" nocase ascii wide
        $api4 = "claude.ai" nocase ascii wide
    condition:
        any of them
}

rule Claude_API_Key {
    meta:
        description = "Anthropic API key pattern (sk-ant-...)"
        service     = "anthropic_claude"
        confidence  = "high"
        artifact    = "api_key"
    strings:
        $key = /sk-ant-api[0-9]{2}-[A-Za-z0-9_\-]{90,120}/ ascii wide
        $key2 = /sk-ant-[A-Za-z0-9_\-]{80,120}/ ascii wide
    condition:
        any of them
}

rule Claude_SSE_Response {
    meta:
        description = "Anthropic Claude SSE streaming response fragments"
        service     = "anthropic_claude"
        confidence  = "high"
    strings:
        $sse1 = "event: content_block_delta" ascii
        $sse2 = "\"type\":\"content_block_delta\"" ascii
        $sse3 = "\"type\":\"content_block_start\"" ascii
        $sse4 = "\"delta\":{\"type\":\"text_delta\"" ascii
        $sse5 = "event: message_stop" ascii
    condition:
        2 of them
}

rule Claude_Session_Token {
    meta:
        description = "Claude.ai session key patterns"
        service     = "anthropic_claude"
        confidence  = "high"
        artifact    = "authentication"
    strings:
        $tok1 = "sessionKey" ascii wide
        $tok2 = "activitySessionId" ascii wide
        $tok3 = "X-Api-Key: sk-ant-" ascii
        $tok4 = "anthropic-version:" ascii
    condition:
        any of them
}

/* ── Google Gemini ──────────────────────────────────────────────── */

rule Gemini_API_Endpoint {
    meta:
        description = "Google Gemini API endpoint references"
        service     = "google_gemini"
        confidence  = "high"
    strings:
        $api1 = "generativelanguage.googleapis.com" nocase ascii wide
        $api2 = "gemini.google.com" nocase ascii wide
        $api3 = "aistudio.google.com" nocase ascii wide
        $api4 = "/v1beta/models/gemini" nocase ascii
    condition:
        any of them
}

rule Gemini_API_Key {
    meta:
        description = "Google AI API key pattern (AIza...)"
        service     = "google_gemini"
        confidence  = "medium"
        artifact    = "api_key"
    strings:
        $key = /AIza[A-Za-z0-9_\-]{35}/ ascii wide
    condition:
        $key
}

rule Gemini_SSE_Response {
    meta:
        description = "Google Gemini SSE/streaming response fragments"
        service     = "google_gemini"
        confidence  = "medium"
    strings:
        $sse1 = "\"candidates\":[{\"content\":" ascii
        $sse2 = "\"finishReason\":\"STOP\"" ascii
        $sse3 = "\"usageMetadata\":{\"promptTokenCount\"" ascii
        $sse4 = "\"parts\":[{\"text\":" ascii
    condition:
        2 of them
}

/* ── Microsoft Copilot ──────────────────────────────────────────── */

rule Copilot_API_Endpoint {
    meta:
        description = "Microsoft Copilot endpoint references"
        service     = "microsoft_copilot"
        confidence  = "high"
    strings:
        $api1 = "copilot.microsoft.com" nocase ascii wide
        $api2 = "sydney.bing.com" nocase ascii wide
        $api3 = "copilot.cloud.microsoft" nocase ascii wide
        $api4 = "api.bing.microsoft.com" nocase ascii wide
    condition:
        any of them
}

rule Copilot_Conversation {
    meta:
        description = "Microsoft Copilot conversation fragments"
        service     = "microsoft_copilot"
        confidence  = "medium"
    strings:
        $j1 = "\"conversationId\":" ascii
        $j2 = "\"clientId\":\"" ascii
        $j3 = "\"conversationSignature\":" ascii
        $j4 = "sydney.bing.com/sydney/ChatHub" ascii
        $j5 = "\"invocationId\":" ascii
    condition:
        2 of them
}

/* ── Perplexity ─────────────────────────────────────────────────── */

rule Perplexity_API {
    meta:
        description = "Perplexity AI endpoint and key references"
        service     = "perplexity"
        confidence  = "high"
    strings:
        $api1 = "api.perplexity.ai" nocase ascii wide
        $api2 = "perplexity.ai" nocase ascii wide
        $key  = /pplx-[A-Za-z0-9]{48}/ ascii wide
    condition:
        any of them
}

/* ── xAI Grok ───────────────────────────────────────────────────── */

rule Grok_API {
    meta:
        description = "xAI Grok endpoint and key references"
        service     = "xai_grok"
        confidence  = "high"
    strings:
        $api1 = "api.x.ai/v1" nocase ascii wide
        $api2 = "grok.x.ai" nocase ascii wide
        $key  = /xai-[A-Za-z0-9]{48,}/ ascii wide
    condition:
        any of them
}

/* ── Local LLMs ─────────────────────────────────────────────────── */

rule Ollama_API {
    meta:
        description = "Ollama local LLM API references"
        service     = "ollama"
        confidence  = "high"
    strings:
        $api1 = "localhost:11434/api/chat" ascii
        $api2 = "127.0.0.1:11434" ascii
        $api3 = "ollama" nocase ascii wide
        $j1   = "\"model\":\"llama" ascii
        $j2   = "\"done\":false" ascii
    condition:
        2 of them
}

rule LMStudio_API {
    meta:
        description = "LM Studio local API references"
        service     = "lm_studio"
        confidence  = "high"
    strings:
        $api1 = "localhost:1234/v1/chat" ascii
        $api2 = "127.0.0.1:1234" ascii
        $api3 = "lm studio" nocase ascii wide
        $api4 = "lmstudio" nocase ascii wide
    condition:
        any of them
}

/* ── TLS Key Material ───────────────────────────────────────────── */

rule TLS_Keylog_Material {
    meta:
        description = "NSS/SSLKEYLOGFILE TLS key material"
        artifact    = "tls_keys"
        confidence  = "high"
    strings:
        $k1 = "CLIENT_RANDOM " ascii
        $k2 = "CLIENT_EARLY_TRAFFIC_SECRET " ascii
        $k3 = "CLIENT_HANDSHAKE_TRAFFIC_SECRET " ascii
        $k4 = "SERVER_HANDSHAKE_TRAFFIC_SECRET " ascii
        $k5 = "CLIENT_TRAFFIC_SECRET_0 " ascii
        $k6 = "SERVER_TRAFFIC_SECRET_0 " ascii
        $k7 = "EXPORTER_SECRET " ascii
    condition:
        any of them
}

rule SSLKEYLOGFILE_Path {
    meta:
        description = "SSLKEYLOGFILE environment variable references"
        artifact    = "tls_keys"
        confidence  = "medium"
    strings:
        $env1 = "SSLKEYLOGFILE" ascii wide
        $env2 = "ssl-keys.log" nocase ascii wide
        $env3 = "tls-keys.log" nocase ascii wide
        $env4 = "ssl_keys.log" nocase ascii wide
    condition:
        any of them
}

/* ── JWT / Bearer Tokens ────────────────────────────────────────── */

rule JWT_Bearer_Token {
    meta:
        description = "JWT Bearer token (Authorization header)"
        artifact    = "authentication"
        confidence  = "medium"
    strings:
        $b1 = "Authorization: Bearer eyJ" ascii
        $b2 = "authorization: bearer eyJ" nocase ascii
    condition:
        any of them
}

/* ── GitHub Copilot ─────────────────────────────────────────────── */

rule GitHub_Copilot {
    meta:
        description = "GitHub Copilot endpoint references"
        service     = "github_copilot"
        confidence  = "high"
    strings:
        $api1 = "copilot-proxy.githubusercontent.com" nocase ascii wide
        $api2 = "api.github.com/copilot" nocase ascii wide
        $api3 = "github.com/features/copilot" nocase ascii wide
        $tok1 = "ghu_" ascii wide  // GitHub OAuth token prefix
        $tok2 = "ghp_" ascii wide  // GitHub PAT prefix
    condition:
        any of them
}

/* ── Cursor AI ──────────────────────────────────────────────────── */

rule Cursor_AI {
    meta:
        description = "Cursor AI IDE endpoint references"
        service     = "cursor_ai"
        confidence  = "high"
    strings:
        $api1 = "api2.cursor.sh" nocase ascii wide
        $api2 = "cursor.sh" nocase ascii wide
        $api3 = "aicursor.com" nocase ascii wide
    condition:
        any of them
}
