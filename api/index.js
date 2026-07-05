const jwt = require('jsonwebtoken');
const zlib = require('zlib');

const JWT_SECRET = process.env.JWT_SECRET || 'change-this-to-a-random-string';
const AUTH_PASSWORD = process.env.AUTH_PASSWORD || '';
const API_KEY = process.env.API_KEY || '';

// ── Rate Limiter (simple in-memory – per cold start) ──
const RATE_LIMIT_WINDOW_MS = 60_000;  // 1 minute
const RATE_LIMIT_MAX = 60;            // requests per window per IP

const rateLimitMap = new Map();

// Clean up old entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, timestamps] of rateLimitMap.entries()) {
    const recent = timestamps.filter(t => now - t < RATE_LIMIT_WINDOW_MS);
    if (recent.length === 0) rateLimitMap.delete(ip);
    else rateLimitMap.set(ip, recent);
  }
}, 300_000).unref();  // don't keep the process alive

function checkRateLimit(ip) {
  const now = Date.now();
  const timestamps = rateLimitMap.get(ip) || [];
  const recent = timestamps.filter(t => now - t < RATE_LIMIT_WINDOW_MS);
  if (recent.length >= RATE_LIMIT_MAX) return false;
  recent.push(now);
  rateLimitMap.set(ip, recent);
  return true;
}

// ── Helpers ──────────────────────────────────────────
function sendJson(res, status, data) {
  res.setHeader('Content-Type', 'application/json');
  res.status(status).json(data);
}

function getRequestBody(req) {
  return new Promise((resolve, reject) => {
    if (req.body) return resolve(JSON.stringify(req.body));
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      let body = Buffer.concat(chunks);

      // Safely handle gzip decompression
      if (req.headers['content-encoding'] === 'gzip') {
        // Check for gzip magic bytes (1F 8B) before decompressing
        if (body.length > 2 && body[0] === 0x1F && body[1] === 0x8B) {
          try {
            body = zlib.gunzipSync(body);
          } catch (e) {
            // If decompression fails, fall back to raw string
            body = body.toString('utf-8');
          }
        } else {
          // Headers said gzip but data wasn't, fall back to raw string
          body = body.toString('utf-8');
        }
      } else {
        body = body.toString('utf-8');
      }

      resolve(body);
    });
    req.on('error', reject);
  });
}

function discoverDatabases() {
  const dbs = [];
  for (const key of Object.keys(process.env)) {
    const match = key.match(/^TURSO_DB_(.+)_URL$/);
    if (match) {
      const upper = match[1];
      const name = upper.toLowerCase();
      const url = (process.env[key] || '').trim();
      if (!url) {
        console.warn(`Skipping ${name}: URL is empty`);
        continue;
      }
      const token = (process.env[`TURSO_DB_${upper}_TOKEN`] || '').trim();
      dbs.push({ name, url, token });
    }
  }
  return dbs;
}

function getHttpUrl(libsqlUrl) {
  return libsqlUrl.replace(/^libsql:\/\//, 'https://').replace(/\/$/, '');
}

// Updated: accepts optional args array, returns full result object
async function tursoExecute(dbUrl, dbToken, sql, args = []) {
  if (!dbUrl) throw new Error('Database URL is empty – check environment variable');
  const endpoint = getHttpUrl(dbUrl) + '/v2/pipeline';
  const requests = [
    { type: 'execute', stmt: { sql, args } },
    { type: 'close' }
  ];
  const body = JSON.stringify({ requests });

  let response;
  try {
    response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${dbToken}`,
        'Content-Type': 'application/json'
      },
      body
    });
  } catch (fetchErr) {
    throw new Error(`Turso fetch failed: ${fetchErr.message}`);
  }

  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || data.message || `HTTP ${response.status}`);
  }

  const executeResponse = data.results?.[0];
  if (executeResponse?.type === 'error') {
    throw new Error(executeResponse.error?.message || 'Turso pipeline error');
  }
  const executeResult = executeResponse?.response?.result;
  if (!executeResult) {
    throw new Error('Unexpected Turso response: ' + JSON.stringify(data).substring(0, 300));
  }

  // Return structured result
  return {
    columns: (executeResult.cols || []).map(c => ({ name: c.name, type: c.type })),
    rows: (executeResult.rows || []).map(row => row.map(cell => cell.value)),
    rowsAffected: executeResult.rowsAffected,
    lastInsertRowid: executeResult.lastInsertRowid || null
  };
}

// ── Smart SQL splitter (unchanged) ──
function splitSqlStatements(sql) {
  const statements = [];
  let current = '';
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let inBlockComment = false;
  let inLineComment = false;
  let parenDepth = 0;
  let beginDepth = 0;

  let i = 0;
  while (i < sql.length) {
    const char = sql[i];

    if (!inSingleQuote && !inDoubleQuote && !inLineComment && char === '/' && sql[i + 1] === '*') {
      inBlockComment = true;
      current += '/*';
      i += 2; continue;
    }
    if (inBlockComment && char === '*' && sql[i + 1] === '/') {
      inBlockComment = false;
      current += '*/';
      i += 2; continue;
    }
    if (inBlockComment) { current += char; i++; continue; }

    if (!inSingleQuote && !inDoubleQuote && !inBlockComment && char === '-' && sql[i + 1] === '-') {
      inLineComment = true;
      current += '--';
      i += 2; continue;
    }
    if (inLineComment && char === '\n') {
      inLineComment = false;
      current += char; i++; continue;
    }
    if (inLineComment) { current += char; i++; continue; }

    if (char === "'" && !inDoubleQuote && !inBlockComment && !inLineComment) {
      inSingleQuote = !inSingleQuote;
    } else if (char === '"' && !inSingleQuote && !inBlockComment && !inLineComment) {
      inDoubleQuote = !inDoubleQuote;
    }

    if (!inSingleQuote && !inDoubleQuote && !inBlockComment && !inLineComment) {
      if (char === '(') parenDepth++;
      else if (char === ')') { if (parenDepth > 0) parenDepth--; }
    }

    if (!inSingleQuote && !inDoubleQuote && !inBlockComment && !inLineComment) {
      if (char === 'B' || char === 'b') {
        const sub = sql.substring(i, i + 5);
        if (/^BEGIN\b/i.test(sub) && !/[A-Za-z0-9_]/.test(sql[i + 5] || '')) beginDepth++;
      }
      if (char === 'E' || char === 'e') {
        const sub = sql.substring(i, i + 3);
        if (/^END\b/i.test(sub) && !/[A-Za-z0-9_]/.test(sql[i + 3] || '')) {
          if (beginDepth > 0) beginDepth--;
        }
      }
    }

    if (char === ';' && !inSingleQuote && !inDoubleQuote && !inBlockComment && !inLineComment && parenDepth === 0 && beginDepth === 0) {
      const trimmed = current.trim();
      if (trimmed) statements.push(trimmed);
      current = '';
      i++;
      continue;
    }

    current += char;
    i++;
  }

  const remaining = current.trim();
  if (remaining) statements.push(remaining);
  return statements.filter(s => s.length > 0);
}

// ── Main handler ─────────────────────────────────────
module.exports = async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-api-key, Authorization');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  // Rate limiting (basic, per IP)
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  if (!checkRateLimit(clientIp)) {
    return sendJson(res, 429, { error: 'Too many requests. Please slow down.' });
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(req.url, `http://${req.headers.host}`);
  } catch (e) {
    return sendJson(res, 400, { error: 'Invalid URL' });
  }

  const { pathname } = parsedUrl;
  const searchParams = parsedUrl.searchParams;
  const method = req.method;

  // ── Login endpoint (no auth required) ──────────────
  if (method === 'POST' && pathname === '/auth/login') {
    if (!AUTH_PASSWORD) {
      return sendJson(res, 500, { error: 'AUTH_PASSWORD not set' });
    }
    let bodyStr;
    try { bodyStr = await getRequestBody(req); } catch { return sendJson(res, 400, { error: 'Failed to read body' }); }
    let password;
    try { password = JSON.parse(bodyStr).password; } catch { return sendJson(res, 400, { error: 'Invalid JSON' }); }
    if (password !== AUTH_PASSWORD) {
      return sendJson(res, 401, { error: 'Incorrect password' });
    }
    const token = jwt.sign({ user: 'fifa-editor' }, JWT_SECRET, { expiresIn: '24h' });
    return sendJson(res, 200, { token });
  }

  // ── PUBLIC DEBUG ROUTE (no auth) ───────────────────
  if (method === 'GET' && pathname === '/api/debug') {
    const allKeys = Object.keys(process.env)
      .filter(k => k.startsWith('TURSO_DB_'))
      .reduce((acc, key) => {
        acc[key] = (process.env[key] || '').trim().substring(0, 50) + (process.env[key]?.length > 50 ? '...' : '');
        return acc;
      }, {});

    const dbs = discoverDatabases();
    const safe = dbs.map(d => ({
      name: d.name,
      url: d.url ? d.url.substring(0, 30) + '...' : 'MISSING'
    }));

    return sendJson(res, 200, {
      rawEnvKeys: allKeys,
      discoveredDbs: safe
    });
  }

  // ── PUBLIC USER DETAIL ROUTE (no auth) ─────────────
  const userMatch = pathname.match(/^\/api\/user\/([^\/]+)$/);
  if (userMatch && method === 'GET') {
    const username = decodeURIComponent(userMatch[1]);
    if (!username) return sendJson(res, 400, { error: 'Missing username' });

    try {
      const tiktokUrl = `https://www.tiktok.com/@${username}`;
      const tiktokResp = await fetch(tiktokUrl, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'Accept-Language': 'en-US,en;q=0.9'
        }
      });
      if (!tiktokResp.ok) {
        return sendJson(res, tiktokResp.status, { error: `TikTok returned ${tiktokResp.status}` });
      }
      const html = await tiktokResp.text();

      const match = html.match(
        /<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__" type="application\/json">(.*?)<\/script>/s
      );
      if (!match) return sendJson(res, 404, { error: 'User not found' });

      const data = JSON.parse(match[1]);
      const userDetail = data['__DEFAULT_SCOPE__']?.['webapp.user-detail'];
      if (!userDetail) return sendJson(res, 404, { error: 'User not found' });

      const user = userDetail?.userInfo?.user;
      const avatar =
        user?.avatarLarger ||
        user?.avatarMedium ||
        user?.avatarThumb ||
        user?.avatar ||
        null;

      const userData = {
        username: user?.uniqueId || username,
        nickname: user?.nickname || '',
        avatar: avatar,
        secUid: user?.secUid || null,
        bio: user?.signature || '',
        followerCount: user?.followerCount || 0,
        followingCount: user?.followingCount || 0,
      };
      return sendJson(res, 200, { success: true, data: userData });
    } catch (err) {
      console.error('Error fetching user:', err.message);
      return sendJson(res, 500, { error: 'Failed to fetch user data' });
    }
  }

  // ── Authentication check ───────────────────────────
  // Supports: x-api-key header, ?api_key= query param, and Authorization: Bearer <token>
  const providedKey =
    req.headers['x-api-key'] ||
    searchParams.get('api_key') ||
    (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null);

  if (AUTH_PASSWORD) {
    if (!providedKey) return sendJson(res, 401, { error: 'Missing authentication token' });
    try {
      jwt.verify(providedKey, JWT_SECRET);
    } catch (e) {
      if (API_KEY && providedKey === API_KEY) {
        // legacy API key fallback
      } else {
        return sendJson(res, 401, { error: 'Unauthorized – invalid or expired token' });
      }
    }
  } else if (API_KEY) {
    if (providedKey !== API_KEY) return sendJson(res, 401, { error: 'Unauthorized' });
  }

  // ── Route handling ─────────────────────────────────
  try {
    // Root
    if (method === 'GET' && pathname === '/') {
      return sendJson(res, 200, {
        status: 'ok',
        message: 'Multi‑database server (Turso) on Vercel',
        endpoints: {
          listDatabases: 'GET /api/databases',
          createDb: 'POST /api/database/:name',
          deleteDb: 'DELETE /api/database/:name',
          query: 'GET /api/:database/query?sql=...  (supports ? placeholders via GET)',
          parameterisedQuery: 'POST /api/:database/query  (body: { "sql": "...", "params": [...] })',
          exec: 'POST /api/:database/exec  (body: { "sql": "..." })',
          pipeline: 'POST /api/:database/pipeline  (body: { "requests": [{ "sql": "...", "args": [] }] })',
          login: 'POST /auth/login  (body: { "password": "..." })',
          debug: 'GET /api/debug  (public)'
        }
      });
    }

    // List databases
    if (method === 'GET' && pathname === '/api/databases') {
      const dbs = discoverDatabases().map(d => d.name);
      return sendJson(res, 200, dbs);
    }

    // Create/Delete (informational)
    const dbMatch = pathname.match(/^\/api\/database\/([^\/]+)$/);
    if (dbMatch) {
      const dbName = dbMatch[1].toLowerCase();
      if (method === 'POST') {
        return sendJson(res, 200, {
          message: 'Create the database in the Turso dashboard, then add URL & token as environment variables.'
        });
      }
      if (method === 'DELETE') {
        return sendJson(res, 200, {
          message: 'Delete the database in the Turso dashboard. Remove its environment variables from Railway.'
        });
      }
      return sendJson(res, 405, { error: 'Method not allowed' });
    }

    // ── Database‑specific endpoints ──────────────────
    // Dynamic route extraction
    const parts = pathname.split('/').filter(p => p);
    if (parts.length < 3 || parts[0] !== 'api') {
      return sendJson(res, 404, { error: 'Not found' });
    }
    const dbName = parts[1].toLowerCase();
    const action = parts[2]; // "query", "exec", "pipeline"

    const dbs = discoverDatabases();
    const db = dbs.find(d => d.name === dbName);
    if (!db) return sendJson(res, 404, { error: `Database '${dbName}' not found` });

    // ── Read‑only query (GET) ──
    if (method === 'GET' && action === 'query') {
      const sql = searchParams.get('sql');
      if (!sql) return sendJson(res, 400, { error: 'Missing ?sql= parameter' });
      if (!/^\s*SELECT\b/i.test(sql)) {
        return sendJson(res, 400, { error: 'Only SELECT queries are allowed on this endpoint' });
      }

      try {
        const result = await tursoExecute(db.url, db.token, sql);
        const cols = result.columns;
        const rows = result.rows.map(row =>
          Object.fromEntries(row.map((cell, idx) => [cols[idx]?.name || `col${idx}`, cell]))
        );
        return sendJson(res, 200, rows);
      } catch (err) {
        return sendJson(res, 400, { error: err.message });
      }
    }

    // ── Parameterised query (POST) ──
    if (method === 'POST' && action === 'query') {
      let body;
      try { body = await getRequestBody(req); } catch { return sendJson(res, 400, { error: 'Failed to read body' }); }
      let payload;
      try { payload = JSON.parse(body); } catch { return sendJson(res, 400, { error: 'Invalid JSON' }); }
      const { sql, params } = payload;
      if (!sql) return sendJson(res, 400, { error: 'Missing sql' });

      try {
        const result = await tursoExecute(db.url, db.token, sql, params || []);
        const cols = result.columns.map(c => c.name);
        const rows = result.rows.map(row =>
          Object.fromEntries(row.map((cell, idx) => [cols[idx], cell]))
        );
        return sendJson(res, 200, { columns: cols, rows });
      } catch (err) {
        return sendJson(res, 400, { error: err.message });
      }
    }

    // ── Script execution (POST /exec) ──
    if (method === 'POST' && action === 'exec') {
      let body;
      try { body = await getRequestBody(req); } catch { return sendJson(res, 400, { error: 'Failed to read body' }); }
      let sql;
      try { sql = JSON.parse(body).sql; } catch { return sendJson(res, 400, { error: 'Invalid JSON' }); }
      if (!sql) return sendJson(res, 400, { error: 'Missing "sql" in body' });

      try {
        const statements = splitSqlStatements(sql);
        let totalChanges = 0;
        let lastInsertRowid = null;
        for (const stmt of statements) {
          const result = await tursoExecute(db.url, db.token, stmt);
          totalChanges += result.rowsAffected || 0;
          lastInsertRowid = result.lastInsertRowid;
        }
        return sendJson(res, 200, { changes: totalChanges, lastInsertRowid });
      } catch (err) {
        return sendJson(res, 400, { error: err.message });
      }
    }

    // ── Pipeline execution (POST /pipeline) ──
    if (method === 'POST' && action === 'pipeline') {
      let body;
      try { body = await getRequestBody(req); } catch { return sendJson(res, 400, { error: 'Failed to read body' }); }
      let payload;
      try { payload = JSON.parse(body); } catch { return sendJson(res, 400, { error: 'Invalid JSON' }); }
      const { requests } = payload;
      if (!Array.isArray(requests)) return sendJson(res, 400, { error: 'requests must be an array' });

      try {
        // Build pipeline request to Turso
        const pipelineRequests = requests.map(r => ({
          type: 'execute',
          stmt: { sql: r.sql, args: r.args || [] }
        }));
        pipelineRequests.push({ type: 'close' });

        const endpoint = getHttpUrl(db.url) + '/v2/pipeline';
        const pipelineBody = JSON.stringify({ requests: pipelineRequests });

        const response = await fetch(endpoint, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${db.token}`,
            'Content-Type': 'application/json'
          },
          body: pipelineBody
        });

        const data = await response.json();
        if (!response.ok) {
          throw new Error(data.error || data.message || `HTTP ${response.status}`);
        }

        const results = (data.results || []).slice(0, -1).map((r, idx) => {
          if (r.type === 'error') {
            throw new Error(`Statement ${idx} error: ${r.error?.message}`);
          }
          const result = r.response?.result;
          if (!result) throw new Error(`Empty result for statement ${idx}`);
          return {
            columns: (result.cols || []).map(c => c.name),
            rows: (result.rows || []).map(row => row.map(cell => cell.value)),
            rowsAffected: result.rowsAffected,
            lastInsertRowid: result.lastInsertRowid
          };
        });

        return sendJson(res, 200, { results });
      } catch (err) {
        return sendJson(res, 400, { error: err.message });
      }
    }

    // Unknown action
    return sendJson(res, 404, { error: `Unknown endpoint /api/${dbName}/${action}` });

  } catch (err) {
    console.error('Request error:', err.message);
    sendJson(res, 500, { error: err.message });
  }
};
