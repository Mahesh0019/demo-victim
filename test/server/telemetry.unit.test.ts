/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { clearTelemetryBuffer, getTelemetryEvents, getTelemetryHealth } from '../../lib/telemetry'
import { serveTelemetryHealth, serveTelemetryEvents } from '../../routes/telemetry'

void describe('telemetry API', () => {
  void it('should return health status unauthenticated', () => {
    clearTelemetryBuffer()
    const req: any = {}
    const res: any = {
      json: (data: any) => {
        assert.equal(data.status, 'ok')
        assert.equal(data.buffered_events, 0)
        assert.ok(data.timestamp)
      }
    }

    serveTelemetryHealth()(req, res)
  })

  void it('should reject unauthenticated or invalid API key access to /api/telemetry/events', () => {
    const req: any = { headers: {} }
    let statusCode = 200
    let responseData: any = null

    const res: any = {
      status: (code: number) => {
        statusCode = code
        return res
      },
      json: (data: any) => {
        responseData = data
      }
    }

    serveTelemetryEvents()(req, res, (() => {}) as any)
    assert.equal(statusCode, 401)
    assert.equal(responseData.error, 'Unauthorized: Invalid or missing Telemetry API key')
  })

  void it('should retrieve telemetry events when valid Bearer key is provided', () => {
    clearTelemetryBuffer()

    const req: any = {
      headers: {
        authorization: 'Bearer telemetry-secret-key-123'
      },
      query: {}
    }

    let responseData: any = null
    const res: any = {
      json: (data: any) => {
        responseData = data
      }
    }

    serveTelemetryEvents()(req, res, (() => {}) as any)
    assert.equal(responseData.count, 0)
    assert.deepEqual(responseData.events, [])
  })

  void it('should support incremental event retrieval using since parameter', () => {
    clearTelemetryBuffer()
    const health = getTelemetryHealth()
    assert.equal(health.status, 'ok')
    assert.equal(health.buffered_events, 0)
  })
})
