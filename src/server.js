const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const pty = require('node-pty');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const { execSync } = require('child_process');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const PASSWORD_HASH = process.env.PASSWORD_HASH;

if (!JWT_SECRET || !PASSWORD_HASH) {
  console.error('Missing JWT_SECRET or PASSWORD_HASH in .env — run: npm run setup');
  process.exit(1);
}

app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

app.post('/api/login', async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });
  const valid = await bcrypt.compare(password, PASSWORD_HASH);
  if (!valid) return res.status(401).json({ error: 'Wrong password' });
  const token = jwt.sign({ auth: true }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token });
});

app.get('/api/sessions', authMiddleware, (req, res) => {
  try {
    const out = execSync(
      'tmux list-sessions -F "#{session_name}|#{session_windows}|#{session_attached}|#{session_activity}" 2>/dev/null',
      { encoding: 'utf8' }
    );
    const sessions = out.trim().split('\n').filter(Boolean).map(line => {
      const [name, windows, attached, activity] = line.split('|');
      return {
        name,
        windows: parseInt(windows),
        attached: attached === '1',
        activity: new Date(parseInt(activity) * 1000).toISOString(),
      };
    });
    res.json({ sessions });
  } catch {
    res.json({ sessions: [] });
  }
});

app.post('/api/sessions', authMiddleware, (req, res) => {
  const name = (req.body.name || `claude-${Date.now()}`).replace(/[^a-zA-Z0-9_-]/g, '');
  try {
    execSync(`tmux new-session -d -s "${name}" -x 200 -y 50`);
    execSync(`tmux send-keys -t "${name}" "claude" Enter`);
    res.json({ name });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/sessions/:name', authMiddleware, (req, res) => {
  const name = req.params.name.replace(/[^a-zA-Z0-9_-]/g, '');
  try {
    execSync(`tmux kill-session -t "${name}"`);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// WebSocket terminal bridge
wss.on('connection', (ws, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const token = url.searchParams.get('token');
  const session = url.searchParams.get('session');

  try {
    jwt.verify(token, JWT_SECRET);
  } catch {
    ws.close(1008, 'Unauthorized');
    return;
  }

  if (!session || !/^[a-zA-Z0-9_-]+$/.test(session)) {
    ws.close(1008, 'Invalid session');
    return;
  }

  let shell;
  try {
    shell = pty.spawn('tmux', ['attach-session', '-t', session], {
      name: 'xterm-256color',
      cols: 200,
      rows: 50,
      env: { ...process.env, TERM: 'xterm-256color' },
    });
  } catch (e) {
    ws.send(JSON.stringify({ type: 'error', data: `Failed to attach: ${e.message}` }));
    ws.close();
    return;
  }

  shell.onData(data => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'data', data }));
    }
  });

  shell.onExit(() => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'exit' }));
      ws.close();
    }
  });

  ws.on('message', raw => {
    try {
      const msg = JSON.parse(raw);
      if (msg.type === 'input') shell.write(msg.data);
      if (msg.type === 'resize') shell.resize(Math.max(2, msg.cols), Math.max(2, msg.rows));
    } catch {}
  });

  ws.on('close', () => {
    try { shell.kill(); } catch {}
  });
});

server.listen(PORT, () => {
  console.log(`Claude Pilot → http://localhost:${PORT}`);
});
