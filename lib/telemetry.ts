/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import onFinished from 'on-finished'
import * as security from './insecurity'
import http from 'node:http'
import https from 'node:https'

export interface TelemetryEvent {
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

export function telemetryMiddleware () {
  return (req: Request, res: Response, next: NextFunction) => {
    const startTime = process.hrtime()

    onFinished(res, () => {
      try {
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

        let bodySnippet = ''
        if (req.body && Object.keys(req.body).length > 0) {
          try {
            const bodyStr = typeof req.body === 'string' ? req.body : JSON.stringify(req.body)
            bodySnippet = bodyStr.substring(0, 500)
          } catch {
            bodySnippet = '[Unparseable Body]'
          }
        }

        const ipHeader = req.headers['x-forwarded-for']
        const rawIp = Array.isArray(ipHeader) ? ipHeader[0] : (typeof ipHeader === 'string' ? ipHeader.split(',')[0].trim() : (req.socket.remoteAddress || req.ip || 'unknown'))

        const event: TelemetryEvent = {
          timestamp: new Date().toISOString(),
          source_ip: rawIp,
          method: req.method,
          path: req.originalUrl || req.url,
          status_code: res.statusCode,
          response_time_ms: responseTimeMs,
          user_agent: (req.headers['user-agent'] as string) || 'unknown',
          user_identity: userIdentity,
          request_body_snippet: bodySnippet,
          event_type: 'HTTP_REQUEST'
        }

        // 1. Output structured JSON to stdout for container log streams / Render log drains
        console.log(`[TELEMETRY] ${JSON.stringify(event)}`)

        // 2. Stream to external SOC collector if TELEMETRY_URL environment variable is provided
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
      // Suppress network errors to avoid crashing or logging extra errors
    })

    req.write(data)
    req.end()
  } catch {
    // Suppress URL parsing errors
  }
}
