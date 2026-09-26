/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import onFinished from 'on-finished'
import * as security from './insecurity'
import crypto from 'node:crypto'
import http from 'node:http'
import https from 'node:https'

export interface TelemetryEvent {
  event_id: string
  timestamp: string
  source_ip: string
  method: string
  path: string
  status_code: number
  response_time_ms: number
  user_agent: string
  user_identity: string
  request_body_snippet: string
  event_type: 'HTTP_REQUEST' | 'SECURITY_EVENT' | 'APP_ERROR'
}

const MAX_BUFFER_SIZE = 1000
const eventBuffer: TelemetryEvent[] = []

export function telemetryMiddleware () {
  return (req: Request, res: Response, next: NextFunction) => {
    const startTime = process.hrtime()

    onFinished(res, () => {
      try {
        const path = req.originalUrl || req.url || ''

        // Do not buffer requests to the telemetry API itself to avoid recursion/noise
        if (path.startsWith('/api/telemetry')) {
          return
        }

        const diff = process.hrtime(startTime)
        const responseTimeMs = Number((diff[0] * 1e3 + diff[1] * 1e-6).toFixed(2))

        let userIdentity = 'anonymous'
        try {
          const authUser = security.authenticatedUsers.from(req)
          if (authUser?.data?.email) {
            userIdentity = authUser.data.email
          }
        } catch {
          // ignore error decoding user token
        }

        const bodySnippet = sanitizeBodySnippet(req.body)

        const ipHeader = req.headers['x-forwarded-for']
        const rawIp = Array.isArray(ipHeader)
          ? ipHeader[0]
          : (typeof ipHeader === 'string' ? ipHeader.split(',')[0].trim() : (req.socket.remoteAddress || req.ip || 'unknown'))

        const event: TelemetryEvent = {
          event_id: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          source_ip: rawIp,
          method: req.method,
          path,
          status_code: res.statusCode,
          response_time_ms: responseTimeMs,
          user_agent: (req.headers['user-agent'] as string) || 'unknown',
          user_identity: userIdentity,
          request_body_snippet: bodySnippet,
          event_type: 'HTTP_REQUEST'
        }

        // 1. Output structured JSON to stdout for container log streams / Render log drains
        console.log(`[TELEMETRY] ${JSON.stringify(event)}`)

        // 2. Store in bounded in-memory buffer
        eventBuffer.push(event)
        if (eventBuffer.length > MAX_BUFFER_SIZE) {
          eventBuffer.shift()
        }

        // 3. Optional: Stream to remote SOC collector if TELEMETRY_URL environment variable is provided
        if (process.env.TELEMETRY_URL) {
          streamTelemetryToRemote(process.env.TELEMETRY_URL, event)
        }
      } catch {
        // Silently swallow telemetry processing errors to preserve application flow
      }
    })

    next()
  }
}

export function getTelemetryEvents (sinceId?: string, limit = 100): TelemetryEvent[] {
  let events = [...eventBuffer]

  if (sinceId) {
    const index = events.findIndex(e => e.event_id === sinceId)
    if (index !== -1) {
      events = events.slice(index + 1)
    }
  }

  const parseLimit = Math.min(Math.max(1, limit), 1000)
  return events.slice(0, parseLimit)
}

export function getTelemetryHealth () {
  return {
    status: 'ok',
    buffered_events: eventBuffer.length,
    timestamp: new Date().toISOString()
  }
}

export function clearTelemetryBuffer () {
  eventBuffer.length = 0
}

function sanitizeBodySnippet (body: any): string {
  if (!body) return ''
  try {
    if (typeof body === 'string') {
      let str = body
      str = str.replace(/("?password"?\s*[:=]\s*)"[^"]*"/gi, '$1"[REDACTED]"')
      str = str.replace(/("?password"?\s*[:=]\s*)[^\s&,]+/gi, '$1[REDACTED]')
      str = str.replace(/("?token"?\s*[:=]\s*)"[^"]*"/gi, '$1"[REDACTED]"')
      str = str.replace(/("?totpToken"?\s*[:=]\s*)"[^"]*"/gi, '$1"[REDACTED]"')
      return str.substring(0, 500)
    }
    if (typeof body === 'object') {
      const sanitized = redactSensitiveKeys(body)
      return JSON.stringify(sanitized).substring(0, 500)
    }
    return String(body).substring(0, 500)
  } catch {
    return '[Unparseable Body]'
  }
}

function redactSensitiveKeys (obj: any): any {
  if (obj === null || typeof obj !== 'object') return obj
  if (Array.isArray(obj)) return obj.map(redactSensitiveKeys)

  const redacted: Record<string, any> = {}
  for (const [key, val] of Object.entries(obj)) {
    if (/password|token|totpToken|secret|cookie|authorization|creditCard|cardNum/i.test(key)) {
      redacted[key] = '[REDACTED]'
    } else if (typeof val === 'object' && val !== null) {
      redacted[key] = redactSensitiveKeys(val)
    } else {
      redacted[key] = val
    }
  }
  return redacted
}

function streamTelemetryToRemote (targetUrl: string, event: TelemetryEvent) {
  try {
    const url = new URL(targetUrl)
    const data = JSON.stringify(event)
    const isHttps = url.protocol === 'https:'
    const client = isHttps ? https : http

    const req = client.request(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data)
      },
      timeout: 2000
    })

    req.on('error', () => {
      // Suppress network errors
    })

    req.write(data)
    req.end()
  } catch {
    // Suppress URL parsing errors
  }
}
