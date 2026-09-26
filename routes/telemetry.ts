/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { getTelemetryEvents, getTelemetryHealth } from '../lib/telemetry'

export function serveTelemetryHealth () {
  return (req: Request, res: Response) => {
    res.json(getTelemetryHealth())
  }
}

export function serveTelemetryEvents () {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      const authHeader = req.headers.authorization || ''
      const apiKey = process.env.TELEMETRY_API_KEY || 'telemetry-secret-key-123'
      const expectedAuth = `Bearer ${apiKey}`

      if (authHeader !== expectedAuth) {
        res.status(401).json({ error: 'Unauthorized: Invalid or missing Telemetry API key' })
        return
      }

      const since = typeof req.query.since === 'string' ? req.query.since : undefined
      const limitParam = typeof req.query.limit === 'string' ? parseInt(req.query.limit, 10) : 100
      const limit = isNaN(limitParam) ? 100 : limitParam

      const events = getTelemetryEvents(since, limit)

      res.json({
        count: events.length,
        events
      })
    } catch (error) {
      next(error)
    }
  }
}
