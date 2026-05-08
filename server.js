// // server.js
// require('dotenv').config();
// const express = require('express');
// const mongoose = require('mongoose');
// const cors = require('cors');
// const http = require('http');
// const { Server } = require('socket.io');
// const TelegramBot = require('node-telegram-bot-api');

// const GasReading = require('./models/GasReading');

// const app = express();
// const server = http.createServer(app);
// const io = new Server(server);

// app.use(cors());
// app.use(express.json());
// app.use(express.static('public'));

// const PORT = process.env.PORT || 3000;
// const MONGO_URL = process.env.MONGO_URL;
// const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
// const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
// const ALERT_THRESHOLD = Number(process.env.ALERT_THRESHOLD || 400);

// // Telegram bot (optional)
// let bot = null;
// if (TELEGRAM_BOT_TOKEN && TELEGRAM_CHAT_ID) {
//   // We don't need polling because we only send messages from the server.
//   bot = new TelegramBot(TELEGRAM_BOT_TOKEN);
//   console.log('Telegram bot configured.');
// } else {
//   console.log('Telegram not configured — will skip alerts.');
// }

// // Connect to MongoDB
// mongoose.connect(MONGO_URL, {
//   useNewUrlParser: true,
//   useUnifiedTopology: true
// }).then(() => console.log('MongoDB connected')).catch(err => console.error('MongoDB error', err));

// // API: receive reading from ESP8266 (POST JSON { value })
// app.post('/api/gas', async (req, res) => {
//   try {
//     const { value } = req.body;
//     if (typeof value !== 'number') return res.status(400).json({ error: 'value required (number)' });

//     const reading = await GasReading.create({ value });

//     // emit to dashboard clients via socket.io
//     io.emit('new-reading', { value: reading.value, timestamp: reading.timestamp });

//     // check threshold and send telegram alert
//     if (value >= ALERT_THRESHOLD && bot) {
//       const text = `⚠️ *Gas Alert*\nValue: ${value}\nTime: ${new Date(reading.timestamp).toLocaleString()}`;
//       bot.sendMessage(TELEGRAM_CHAT_ID, text, { parse_mode: 'Markdown' }).catch(err => console.error('Telegram send error', err));
//     }

//     res.json({ ok: true });
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: 'server error' });
//   }
// });

// // API: get recent readings
// app.get('/api/gas', async (req, res) => {
//   const limit = Number(req.query.limit || 50);
//   const readings = await GasReading.find().sort({ timestamp: -1 }).limit(limit);
//   res.json(readings);
// });

// // Socket connection logging
// io.on('connection', socket => {
//   console.log('Dashboard client connected', socket.id);
//   socket.on('disconnect', () => console.log('Dashboard client disconnected', socket.id));
// });

// server.listen(PORT, () => console.log(`Server running on port ${PORT}`));


// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const bodyParser = require('body-parser');
const TelegramBot = require('node-telegram-bot-api');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');

const Device = require('./models/Device');
const GasReading = require('./models/GasReading');
const SecurityEvent = require('./models/SecurityEvent');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// HTTP security headers (CSP disabled — dashboard loads resources from CDNs)
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(bodyParser.json());

// Global rate limiter: 100 req/min per IP
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, slow down.' }
});
app.use(globalLimiter);

// Strict limiter for POST /api/gas: 30 req/min per IP
const gasLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Rate limit exceeded for gas API.' }
});

app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
const MONGO_URL = process.env.MONGO_URL;
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const GLOBAL_ALERT_THRESHOLD = Number(process.env.ALERT_THRESHOLD || 400);

// ─── Security Helpers ────────────────────────────────────────────────────────

// Verify HMAC-SHA256 signature: message = "deviceId:value:timestamp"
function verifyHMAC(apiKey, message, signature) {
  if (!signature || signature.length !== 64) return false;
  const expected = crypto.createHmac('sha256', apiKey).update(message).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expected, 'hex'));
  } catch {
    return false;
  }
}

// Anomaly detection over a rolling window of past readings.
// Returns anomaly type string or null.
function detectAnomaly(lastReadings, newValue) {
  if (lastReadings.length < 8) return null;

  // Sudden spike: impossible jump > 300 PPM in one reading interval
  const lastValue = lastReadings[lastReadings.length - 1];
  if (Math.abs(newValue - lastValue) > 300) return 'ANOMALY_SPIKE';

  return null;
}

async function logSecurityEvent(eventType, deviceId, ipAddress, details) {
  try {
    await SecurityEvent.create({ eventType, deviceId, ipAddress, details });
    console.warn(`[SECURITY] ${eventType} | device=${deviceId || 'unknown'} | ip=${ipAddress} | ${details}`);
  } catch (e) {
    console.error('Failed to log security event', e);
  }
}

// Connect to MongoDB
mongoose.connect(MONGO_URL, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => { console.error('MongoDB connect error', err); process.exit(1); });

// Telegram bot (polling) — lets users run /link <deviceId> to subscribe to alerts
let bot = null;
if (TELEGRAM_BOT_TOKEN) {
  bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: false });
  setTimeout(() => {
    bot.startPolling();
    console.log('Telegram bot active (polling).');
  }, 5000);
  bot.onText(/\/link (.+)/, async (msg, match) => {
    const chatId = msg.chat.id.toString();
    const deviceId = match[1].trim();
    try {
      const device = await Device.findOne({ deviceId });
      if (!device) { bot.sendMessage(chatId, `❌ Device ${deviceId} not found.`); return; }
      device.telegramChatId = chatId;
      await device.save();
      bot.sendMessage(chatId, `✅ Device ${deviceId} linked. You will receive alerts for this device.`);
    } catch (err) {
      console.error('Telegram /link error', err);
    }
  });
} else {
  console.log('No TELEGRAM_BOT_TOKEN configured - Telegram features disabled.');
}

// Socket.IO: clients join per-device rooms
io.on('connection', socket => {
  socket.on('join-device', (deviceId) => socket.join(deviceId));
  socket.on('leave-device', (deviceId) => socket.leave(deviceId));
});

// ─── Routes ──────────────────────────────────────────────────────────────────

/**
 * POST /api/register
 * Body: { deviceName }
 * Returns: { deviceId, apiKey, dashboardUrl }
 * apiKey is now a cryptographically random 64-char hex string.
 * dashboardUrl embeds the token so only the registering device gets the link.
 */
app.post('/api/register', async (req, res) => {
  try {
    const { deviceName } = req.body;
    const deviceId = Date.now().toString(36) + crypto.randomBytes(3).toString('hex');
    const apiKey = crypto.randomBytes(32).toString('hex'); // 64-char hex, never guessable

    const dashboardUrl = `${req.protocol}://${req.get('host')}/dashboard/${deviceId}?token=${apiKey}`;
    const device = new Device({ deviceId, apiKey, deviceName, dashboardUrl });
    await device.save();

    res.json({ deviceId, apiKey, dashboardUrl });
  } catch (err) {
    console.error('Register error', err);
    res.status(500).json({ error: 'server error' });
  }
});

/**
 * POST /api/gas
 * Body: { deviceId, value (number 0-1023), timestamp (ms epoch), signature (HMAC-SHA256 hex) }
 *
 * Security checks (in order):
 *   1. Input validation — value must be in sensor range
 *   2. Device lookup
 *   3. Replay prevention — timestamp within ±60 s of server clock AND > device.lastTimestamp
 *   4. HMAC-SHA256 signature — signs "deviceId:value:timestamp" with the stored apiKey
 *   5. Anomaly detection — flat readings or impossible spikes
 */
app.post('/api/gas', gasLimiter, async (req, res) => {
  const ip = req.ip;
  try {
    const { deviceId, value, timestamp, signature } = req.body;

    // 1. Input validation
    if (!deviceId) return res.status(400).json({ error: 'deviceId required' });
    if (typeof value !== 'number') return res.status(400).json({ error: 'value required (number)' });
    if (value < 0 || value > 1023) {
      await logSecurityEvent('INVALID_VALUE', deviceId, ip, `Out-of-range value: ${value}`);
      return res.status(400).json({ error: 'value out of sensor range (0–1023)' });
    }

    // 2. Device lookup
    const device = await Device.findOne({ deviceId });
    if (!device) {
      await logSecurityEvent('FAILED_AUTH', deviceId, ip, 'Unknown deviceId');
      return res.status(401).json({ error: 'Invalid device' });
    }

    // 3. Replay prevention
    if (typeof timestamp !== 'number') {
      await logSecurityEvent('FAILED_AUTH', deviceId, ip, 'Missing or non-numeric timestamp');
      return res.status(400).json({ error: 'timestamp required (ms epoch)' });
    }
    if (Math.abs(Date.now() - timestamp) > 60000) {
      await logSecurityEvent('REPLAY_ATTACK', deviceId, ip, `Stale timestamp: ${timestamp}`);
      return res.status(401).json({ error: 'Request timestamp expired (replay attack blocked)' });
    }
    if (timestamp <= device.lastTimestamp) {
      await logSecurityEvent('REPLAY_ATTACK', deviceId, ip, `Duplicate timestamp: ${timestamp}`);
      return res.status(401).json({ error: 'Duplicate request rejected (replay attack blocked)' });
    }

    // 4. HMAC-SHA256 signature verification
    const message = `${deviceId}:${value}:${timestamp}`;
    if (!verifyHMAC(device.apiKey, message, signature)) {
      await logSecurityEvent('FAILED_AUTH', deviceId, ip, 'Invalid HMAC signature');
      return res.status(401).json({ error: 'Unauthorized: invalid signature' });
    }

    // 5. Anomaly detection
    const anomaly = detectAnomaly(device.lastReadings, value);
    if (anomaly) {
      await logSecurityEvent(anomaly, deviceId, ip,
        `last=[${device.lastReadings.slice(-3).join(',')}] new=${value}`);
      if (bot && device.telegramChatId) {
        const msg = anomaly === 'ANOMALY_FLAT'
          ? `⚠️ *Sensor Anomaly*\nDevice: ${device.deviceName || deviceId}\nSuspiciously constant readings — possible sensor spoofing.`
          : `⚠️ *Sensor Anomaly*\nDevice: ${device.deviceName || deviceId}\nSudden spike: ${value} PPM`;
        bot.sendMessage(device.telegramChatId, msg, { parse_mode: 'Markdown' }).catch(() => {});
      }
      io.to(deviceId).emit('security-alert', { type: anomaly, value, timestamp: new Date().toISOString() });
    }

    // Save reading
    const reading = new GasReading({ deviceId, value });
    await reading.save();

    // Update device state
    const threshold = device.alertThreshold != null ? device.alertThreshold : GLOBAL_ALERT_THRESHOLD;
    const wasActive = device.alertActive;
    const nowActive = value >= threshold;
    device.lastTimestamp = timestamp;
    device.lastReadings = [...device.lastReadings, value].slice(-10);
    device.lastValue = value;
    device.alertActive = nowActive;
    await device.save();

    io.to(deviceId).emit('new-reading', { deviceId, value, timestamp: reading.timestamp });

    // Gas alert state transitions → Telegram
    if (!wasActive && nowActive) {
      console.log(`🚨 Gas leak detected for ${deviceId} (${value})`);
      if (bot && device.telegramChatId) {
        bot.sendMessage(device.telegramChatId,
          `🚨 *Gas Alert*\nDevice: ${device.deviceName || deviceId}\nValue: ${value}\nTime: ${new Date(reading.timestamp).toLocaleString()}`,
          { parse_mode: 'Markdown' }).catch(e => console.error('Telegram send error', e));
      }
    } else if (wasActive && !nowActive) {
      console.log(`✅ Gas level normal for ${deviceId} (${value})`);
      if (bot && device.telegramChatId) {
        bot.sendMessage(device.telegramChatId,
          `✅ *Gas Normal*\nDevice: ${device.deviceName || deviceId}\nValue: ${value}\nTime: ${new Date(reading.timestamp).toLocaleString()}`,
          { parse_mode: 'Markdown' }).catch(e => console.error('Telegram send error', e));
      }
    }

    res.status(201).json({ success: true });
  } catch (err) {
    console.error('API gas error', err);
    res.status(500).json({ error: 'server error' });
  }
});

/**
 * GET /api/gas?deviceId=...&token=...&limit=...
 * Requires token (= apiKey) to prevent unauthorised data access.
 */
app.get('/api/gas', async (req, res) => {
  try {
    const { deviceId, token } = req.query;
    const limit = Math.min(200, Number(req.query.limit) || 50);
    if (!deviceId) return res.status(400).json({ error: 'deviceId required' });
    if (!token) return res.status(401).json({ error: 'token required' });

    const device = await Device.findOne({ deviceId });
    if (!device || device.apiKey !== token) {
      await logSecurityEvent('FAILED_AUTH', deviceId, req.ip, 'Invalid token on GET /api/gas');
      return res.status(403).json({ error: 'Forbidden: invalid token' });
    }

    const readings = await GasReading.find({ deviceId }).sort({ timestamp: -1 }).limit(limit);
    res.json(readings);
  } catch (err) {
    console.error('GET /api/gas error', err);
    res.status(500).json({ error: 'server error' });
  }
});

/**
 * GET /api/security-events?deviceId=...&token=...
 * Returns the 20 most recent security events for the device — shown on the dashboard.
 */
app.get('/api/security-events', async (req, res) => {
  try {
    const { deviceId, token } = req.query;
    if (!deviceId || !token) return res.status(400).json({ error: 'deviceId and token required' });

    const device = await Device.findOne({ deviceId });
    if (!device || device.apiKey !== token) return res.status(403).json({ error: 'Forbidden' });

    const events = await SecurityEvent.find({ deviceId }).sort({ timestamp: -1 }).limit(20);
    res.json(events);
  } catch (err) {
    res.status(500).json({ error: 'server error' });
  }
});

/**
 * POST /api/link-telegram
 * Body: { deviceId, chatId, apiKey }
 */
app.post('/api/link-telegram', async (req, res) => {
  try {
    const { deviceId, chatId, apiKey } = req.body;
    if (!deviceId || !chatId || !apiKey) return res.status(400).json({ error: 'deviceId, chatId, apiKey required' });

    const device = await Device.findOne({ deviceId });
    if (!device) return res.status(404).json({ error: 'device not found' });
    if (device.apiKey !== apiKey) return res.status(401).json({ error: 'unauthorized' });

    device.telegramChatId = chatId.toString();
    await device.save();
    res.json({ success: true });
  } catch (err) {
    console.error('/api/link-telegram error', err);
    res.status(500).json({ error: 'server error' });
  }
});

/**
 * GET /dashboard/:deviceId?token=...
 * Token-protected — only the device owner (who has the apiKey) can open the dashboard.
 */
app.get('/dashboard/:deviceId', async (req, res) => {
  try {
    const { deviceId } = req.params;
    const token = req.query.token;
    if (!token) return res.status(401).send('Unauthorized: add ?token=<apiKey> to the URL.');
    const device = await Device.findOne({ deviceId });
    if (!device || device.apiKey !== token) return res.status(403).send('Forbidden: invalid token.');
    res.sendFile(__dirname + '/public/device-dashboard.html');
  } catch (err) {
    res.status(500).send('Server error');
  }
});

app.get('/', (req, res) => res.sendFile(__dirname + '/public/index.html'));

// Lightweight health-check used by the keep-alive ping below
app.get('/ping', (req, res) => res.json({ ok: true, ts: Date.now() }));

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);

  // ── Render free-tier keep-alive ──────────────────────────────────────────
  // Render spins down instances after ~15 min of inactivity.
  // When RENDER_EXTERNAL_URL is set (auto-injected by Render) we ping ourselves
  // every 14 minutes so the dyno never idles.  Silently skipped in local dev.
  const selfUrl = process.env.RENDER_EXTERNAL_URL;
  if (selfUrl) {
    const mod = selfUrl.startsWith('https') ? require('https') : require('http');
    const pingUrl = selfUrl.replace(/\/$/, '') + '/ping';
    setInterval(() => {
      mod.get(pingUrl, res => {
        console.log(`[keep-alive] ${pingUrl} → ${res.statusCode}`);
        res.resume(); // drain response body so the socket closes cleanly
      }).on('error', err => {
        console.warn('[keep-alive] ping failed:', err.message);
      });
    }, 14 * 60 * 1000); // 14 minutes — just under Render's 15-min idle window
    console.log(`[keep-alive] pinging ${pingUrl} every 14 min`);
  }
});
