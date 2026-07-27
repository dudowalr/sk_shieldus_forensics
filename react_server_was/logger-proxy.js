'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');

const LISTEN_HOST = process.env.REACT_LOGGER_HOST || '192.168.223.143';
const LISTEN_PORT = Number.parseInt(process.env.REACT_LOGGER_PORT || '3000', 10);
const UPSTREAM_HOST = process.env.REACT_UPSTREAM_HOST || '127.0.0.1';
const UPSTREAM_PORT = Number.parseInt(process.env.REACT_UPSTREAM_PORT || '3001', 10);
const MAX_CAPTURE_BYTES = Number.parseInt(
  process.env.REACT_LOGGER_MAX_CAPTURE_BYTES || String(10 * 1024 * 1024),
  10,
);
const LOG_DIR = path.resolve(
  process.env.REACT_LOGGER_DIR || path.join(__dirname, 'logs'),
);

for (const [name, value] of Object.entries({
  LISTEN_PORT,
  UPSTREAM_PORT,
  MAX_CAPTURE_BYTES,
})) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
}

fs.mkdirSync(LOG_DIR, { recursive: true });

function appendJsonLine(entry) {
  const date = entry.timestamp_start.slice(0, 10);
  const logPath = path.join(LOG_DIR, `http-requests-${date}.jsonl`);
  const line = `${JSON.stringify(entry)}\r\n`;
  const descriptor = fs.openSync(logPath, 'a');

  try {
    fs.writeSync(descriptor, line, null, 'utf8');
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function appendError(errors, message) {
  if (message && !errors.includes(message)) {
    errors.push(message);
  }
}

function socketAddress(socket) {
  return {
    remote_ip: socket.remoteAddress || null,
    remote_port: socket.remotePort || null,
    local_ip: socket.localAddress || null,
    local_port: socket.localPort || null,
  };
}

const server = http.createServer((clientRequest, clientResponse) => {
  const startedAt = Date.now();
  const timestampStart = new Date(startedAt).toISOString();
  const requestId = crypto.randomUUID();
  const connection = socketAddress(clientRequest.socket);
  const bodyHash = crypto.createHash('sha256');
  const capturedChunks = [];
  const errors = [];

  let capturedBytes = 0;
  let totalBodyBytes = 0;
  let requestComplete = false;
  let responseComplete = false;
  let requestLogWritten = false;
  let responseLogWritten = false;
  let bodySha256 = null;
  let responseStatus = null;
  let responseBytes = 0;

  function finishRequest(errorMessage) {
    if (requestComplete) {
      appendError(errors, errorMessage);
      return;
    }

    appendError(errors, errorMessage);
    requestComplete = true;
    bodySha256 = bodyHash.digest('hex');
    writeRequestLog();
  }

  function finishResponse(errorMessage) {
    appendError(errors, errorMessage);
    responseComplete = true;
    writeResponseLog();
  }

  function writeEntry(entry, description) {
    try {
      appendJsonLine(entry);
    } catch (error) {
      console.error(
        `[${entry.timestamp_end}] request_id=${requestId}` +
          ` ${description} log write failed:`,
        error,
      );
    }
  }

  function writeRequestLog() {
    if (requestLogWritten || !requestComplete) {
      return;
    }

    requestLogWritten = true;
    const capturedBody = Buffer.concat(capturedChunks, capturedBytes);
    const endedAt = Date.now();

    const entry = {
      event_type: 'http_request',
      request_id: requestId,
      timestamp_start: timestampStart,
      timestamp_end: new Date(endedAt).toISOString(),
      duration_ms: endedAt - startedAt,
      ...connection,
      method: clientRequest.method,
      url: clientRequest.url,
      http_version: clientRequest.httpVersion,
      headers: clientRequest.headers,
      raw_headers: clientRequest.rawHeaders,
      body_total_bytes: totalBodyBytes,
      body_captured_bytes: capturedBytes,
      body_truncated: totalBodyBytes > capturedBytes,
      body_sha256: bodySha256,
      body_utf8: capturedBody.toString('utf8'),
      body_base64: capturedBody.toString('base64'),
      upstream_host: UPSTREAM_HOST,
      upstream_port: UPSTREAM_PORT,
      errors: [...errors],
    };

    writeEntry(entry, 'request');

    console.log(
      `[${entry.timestamp_end}] request_logged request_id=${requestId}` +
        ` ${entry.remote_ip}:${entry.remote_port}` +
        ` ${entry.method} ${entry.url}` +
        ` request_bytes=${entry.body_total_bytes}` +
        ` duration_ms=${entry.duration_ms}`,
    );
  }

  function writeResponseLog() {
    if (responseLogWritten || !responseComplete) {
      return;
    }

    responseLogWritten = true;
    const endedAt = Date.now();
    const entry = {
      event_type: 'http_response',
      request_id: requestId,
      timestamp_start: timestampStart,
      timestamp_end: new Date(endedAt).toISOString(),
      duration_ms: endedAt - startedAt,
      ...connection,
      method: clientRequest.method,
      url: clientRequest.url,
      upstream_host: UPSTREAM_HOST,
      upstream_port: UPSTREAM_PORT,
      request_complete: requestComplete,
      response_status: responseStatus,
      response_bytes: responseBytes,
      errors: [...errors],
    };

    writeEntry(entry, 'response');

    console.log(
      `[${entry.timestamp_end}] response_logged request_id=${requestId}` +
        ` status=${entry.response_status}` +
        ` response_bytes=${entry.response_bytes}` +
        ` duration_ms=${entry.duration_ms}`,
    );
  }

  clientRequest.on('data', (chunk) => {
    totalBodyBytes += chunk.length;
    bodyHash.update(chunk);

    const remaining = MAX_CAPTURE_BYTES - capturedBytes;
    if (remaining > 0) {
      const captured = chunk.subarray(0, Math.min(chunk.length, remaining));
      capturedChunks.push(captured);
      capturedBytes += captured.length;
    }
  });

  clientRequest.once('end', () => finishRequest());
  clientRequest.once('aborted', () => finishRequest('client request aborted'));
  clientRequest.once('error', (error) =>
    finishRequest(`client request error: ${error.message}`),
  );

  // Preserve the incoming Host, Origin, Content-Type, Next-Action, and body.
  // The TCP destination changes to 127.0.0.1:3001, but HTTP semantics do not.
  const upstreamRequest = http.request(
    {
      hostname: UPSTREAM_HOST,
      port: UPSTREAM_PORT,
      method: clientRequest.method,
      path: clientRequest.url,
      headers: clientRequest.headers,
      agent: false,
    },
    (upstreamResponse) => {
      responseStatus = upstreamResponse.statusCode || 502;

      if (!clientResponse.headersSent) {
        clientResponse.writeHead(responseStatus, upstreamResponse.headers);
      }

      upstreamResponse.on('data', (chunk) => {
        responseBytes += chunk.length;
      });
      upstreamResponse.once('end', () => finishResponse());
      upstreamResponse.once('aborted', () =>
        finishResponse('upstream response aborted'),
      );
      upstreamResponse.once('error', (error) =>
        finishResponse(`upstream response error: ${error.message}`),
      );

      upstreamResponse.pipe(clientResponse);
    },
  );

  upstreamRequest.once('error', (error) => {
    responseStatus = 502;

    if (!clientResponse.headersSent) {
      clientResponse.writeHead(502, {
        'content-type': 'text/plain; charset=utf-8',
        connection: 'close',
      });
    }

    if (!clientResponse.writableEnded) {
      clientResponse.end('Bad Gateway\r\n');
    }

    finishResponse(`upstream request error: ${error.message}`);
  });

  clientRequest.pipe(upstreamRequest);
});

server.on('clientError', (error, socket) => {
  const timestamp = new Date().toISOString();
  const entry = {
    event_type: 'http_parse_error',
    request_id: crypto.randomUUID(),
    timestamp_start: timestamp,
    timestamp_end: timestamp,
    duration_ms: 0,
    ...socketAddress(socket),
    error: error.message,
    raw_packet_base64: error.rawPacket
      ? Buffer.from(error.rawPacket).toString('base64')
      : null,
  };

  try {
    appendJsonLine(entry);
  } catch (logError) {
    console.error(`[${timestamp}] parse-error log write failed:`, logError);
  }

  if (socket.writable) {
    socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
  }
});

server.listen(LISTEN_PORT, LISTEN_HOST, () => {
  console.log(
    `React HTTP logger listening on http://${LISTEN_HOST}:${LISTEN_PORT}`,
  );
  console.log(`Forwarding to http://${UPSTREAM_HOST}:${UPSTREAM_PORT}`);
  console.log(`Writing JSONL logs to ${LOG_DIR}`);
});

function shutdown(signal) {
  console.log(`${signal} received; stopping logger`);
  server.close((error) => {
    if (error) {
      console.error('Logger shutdown failed:', error);
      process.exitCode = 1;
    }
  });
}

process.once('SIGINT', () => shutdown('SIGINT'));
process.once('SIGTERM', () => shutdown('SIGTERM'));
