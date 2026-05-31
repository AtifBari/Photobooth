require('dotenv').config();

// ── Sentry (must be first) ────────────────────────────────
const Sentry = require('@sentry/node');
Sentry.init({
  dsn: process.env.SENTRY_DSN,
  environment: process.env.NODE_ENV || 'production',
  tracesSampleRate: 0.2,
  sendDefaultPii: false
});

var express    = require('express');
var multer     = require('multer');
var Stripe     = require('stripe');
var axios      = require('axios');
var FormData   = require('form-data');
var cors       = require('cors');
var crypto     = require('crypto');
var mongoose   = require('mongoose');

var app    = express();
var stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// ── MongoDB ───────────────────────────────────────────────
mongoose.connect(process.env.MONGODB_URI).then(function() {
  console.log('MongoDB connected');
}).catch(function(err) {
  console.error('MongoDB error:', err.message);
  Sentry.captureException(err);
});

var orderSchema = new mongoose.Schema({
  orderRef:        { type: String, required: true, unique: true },
  date:            { type: Date, default: Date.now },
  name:            String,
  email:           String,
  phone:           String,
  country:         String,
  centre:          String,
  purpose:         String,
  govRef:          String,
  amount:          { type: Number, default: 6.99 },
  currency:        { type: String, default: 'GBP' },
  status:          { type: String, default: 'completed' },
  paymentIntentId: String,
  source:          { type: String, default: 'direct' },
  emailSent:       { type: Boolean, default: false },
  emailError:      String,
  resentAt:        Date,
  printOption:     { type: String, default: 'digital' },
  printCode:       { type: String, default: null },
  printCodeExpiry: { type: Date, default: null },
  printLocation:   { type: String, default: null },
  printed:         { type: Boolean, default: false },
  printedAt:       { type: Date, default: null },
  retakeIssued:    { type: Boolean, default: false },
  retakeIssuedAt:  { type: Date, default: null },
  retakeUsed:      { type: Boolean, default: false },
  retakeUsedAt:    { type: Date, default: null },
  retakeToken:     { type: String, default: null }
});
var Order = mongoose.model('Order', orderSchema);

var retakeSchema = new mongoose.Schema({
  token:      { type: String, required: true, unique: true },
  orderRef:   { type: String, required: true },
  email:      String,
  name:       String,
  centre:     String,
  purpose:    String,
  source:     String,
  used:       { type: Boolean, default: false },
  usedAt:     Date,
  createdAt:  { type: Date, default: Date.now, expires: 604800 }
});
var Retake = mongoose.model('Retake', retakeSchema);

var printPhotoSchema = new mongoose.Schema({
  printCode:   { type: String, required: true, unique: true },
  expiresAt:   { type: Date, default: null },  // MongoDB TTL auto-deletes after 72h
  photoData:   { type: String, required: true },
  createdAt:   { type: Date, default: Date.now, expires: 259200 }
});
var PrintPhoto = mongoose.model('PrintPhoto', printPhotoSchema);

var locationSchema = new mongoose.Schema({
  locationId:   { type: String, required: true, unique: true },
  name:         String,
  address:      String,
  active:       { type: Boolean, default: true },
  createdAt:    { type: Date, default: Date.now }
});
var Location = mongoose.model('Location', locationSchema);

Location.findOne({ locationId: 'LON-WILSON' }).then(function(loc) {
  if (!loc) {
    new Location({ locationId: 'LON-WILSON', name: 'London Wilson', address: 'London, UK', active: true }).save()
    .then(function() { console.log('Default location LON-WILSON created'); })
    .catch(function(e) { console.error('Location seed error:', e.message); });
  }
}).catch(function() {});

// ── File validation ───────────────────────────────────────
var ALLOWED_MIME = ['image/jpeg','image/png','image/jpg'];
function validateFileType(buffer) {
  var hex = buffer.slice(0,4).toString('hex');
  return hex.startsWith('ffd8ff') || hex.startsWith('89504e47');
}

function validateImageDimensions(buffer) {
  return new Promise(function(resolve) {
    try {
      var hex = buffer.slice(0,4).toString('hex');
      var width = 0, height = 0;
      if (hex.startsWith('ffd8ff')) {
        var i = 2;
        while (i < buffer.length - 8) {
          if (buffer[i] === 0xFF && (buffer[i+1] === 0xC0 || buffer[i+1] === 0xC2)) {
            height = buffer.readUInt16BE(i+5);
            width  = buffer.readUInt16BE(i+7);
            break;
          }
          i++;
        }
      } else if (hex.startsWith('89504e47')) {
        width  = buffer.readUInt32BE(16);
        height = buffer.readUInt32BE(20);
      }
      if (width < 100 || height < 100) return resolve({ valid: false, error: 'Image too small — minimum 100x100 pixels.' });
      if (width > 8000 || height > 8000) return resolve({ valid: false, error: 'Image too large — maximum 8000x8000 pixels.' });
      resolve({ valid: true, width: width, height: height });
    } catch(e) {
      resolve({ valid: true });
    }
  });
}

var upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024, files: 1 },
  fileFilter: function(req, file, cb) {
    if (!ALLOWED_MIME.includes(file.mimetype)) return cb(new Error('Only JPEG and PNG files are allowed'), false);
    cb(null, true);
  }
});

// ── Security headers ──────────────────────────────────────
app.use(function(req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://js.stripe.com https://www.google.com https://www.gstatic.com https://cdn.jsdelivr.net; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "img-src 'self' data: blob: https:; " +
    "frame-src https://js.stripe.com https://www.google.com; " +
    "connect-src 'self' https://api.stripe.com https://www.google.com https://cdn.jsdelivr.net https://ipapi.co https://huggingface.co https://*.huggingface.co wss://localhost:8181 wss://localhost:8182 ws://localhost:8181 ws://localhost:8182; " +
    "worker-src blob: 'self';"
  );
  next();
});

app.use(cors());

app.use(function(req, res, next) {
  var start = Date.now();
  var ip = req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress || 'unknown';
  res.on('finish', function() {
    var log = {
      ts:       new Date().toISOString(),
      method:   req.method,
      endpoint: req.path,
      status:   res.statusCode,
      ms:       Date.now() - start,
      ip:       ip.split(',')[0].trim(),
      ua:       (req.headers['user-agent'] || '').substring(0, 120),
    };
    var level = res.statusCode >= 500 ? 'ERROR' : res.statusCode >= 400 ? 'WARN' : 'INFO';
    console.log('[' + level + '] ' + JSON.stringify(log));
  });
  next();
});

var rateLimitStore = {};
function rateLimit(maxRequests, windowMs) {
  return function(req, res, next) {
    var ip = req.ip || req.connection.remoteAddress || 'unknown';
    var key = ip + ':' + req.path;
    var now = Date.now();
    if (!rateLimitStore[key]) rateLimitStore[key] = { count: 0, resetAt: now + windowMs };
    if (now > rateLimitStore[key].resetAt) rateLimitStore[key] = { count: 0, resetAt: now + windowMs };
    rateLimitStore[key].count++;
    if (rateLimitStore[key].count > maxRequests) {
      return res.status(429).json({ error: 'Too many requests. Please wait a moment and try again.' });
    }
    next();
  };
}
setInterval(function() { rateLimitStore = {}; }, 10 * 60 * 1000);

function sanitise(str) {
  if (!str) return '';
  return String(str)
    .replace(/[<>]/g, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+=/gi, '')
    .trim()
    .substring(0, 500);
}

function verifyRecaptcha(token, minScore) {
  if (!token || !process.env.RECAPTCHA_SECRET_KEY) return Promise.resolve(true);
  minScore = minScore || 0.1;
  return axios.post('https://www.google.com/recaptcha/api/siteverify', null, {
    params: { secret: process.env.RECAPTCHA_SECRET_KEY, response: token }
  }).then(function(r) {
    var data = r.data;
    if (!data.success) return true;
    if (data.score < minScore) return false;
    return true;
  }).catch(function() { return true; });
}

app.use(express.json({ limit: '20mb' }));
app.use('/api/stripe-webhook', express.raw({ type: 'application/json' }));
app.use(express.static(process.env.STATIC_DIR || 'public'));

var path = require('path');
var staticDir = process.env.STATIC_DIR ? process.env.STATIC_DIR : path.join(__dirname, 'public');

// ── Apple Pay domain verification ────────────────────────
// Stripe serves this automatically — but we need the route in case
// of direct requests. The actual file content comes from Stripe dashboard.
app.get('/.well-known/apple-developer-merchantid-domain-association', function(req, res) {
  var filePath = path.join(staticDir, '.well-known', 'apple-developer-merchantid-domain-association');
  res.setHeader('Content-Type', 'text/plain');
  res.sendFile(filePath, function(err) {
    if (err) {
      // File not yet added — return empty response (Stripe will handle)
      console.log('[INFO] Apple Pay domain file not found — add from Stripe dashboard');
      res.status(200).send('');
    }
  });
});

app.get('/', function(req, res) { res.sendFile(path.join(staticDir, 'index.html')); });
app.get('/order', function(req, res) { res.sendFile(path.join(staticDir, 'order.html')); });
app.get('/vfs', function(req, res) { res.sendFile(path.join(staticDir, 'vfs.html')); });
app.get('/kiosk', function(req, res) { res.sendFile(path.join(staticDir, 'kiosk.html')); });
app.get('/admin-sabtech', function(req, res) { res.sendFile(path.join(staticDir, 'admin-sabtech.html')); });
app.get('/admin-vfs', function(req, res) { res.sendFile(path.join(staticDir, 'admin-vfs.html')); });
app.get('/retake/:token', function(req, res) { res.sendFile(path.join(staticDir, 'retake.html')); });

// ── In-memory photo store ─────────────────────────────────
var photoStore = {};
var printPhotoStore = {};

// ── CHANGE 1: storePhoto now accepts bgRemoved flag ───────
function storePhoto(token, imgBuffer, bgRemoved) {
  photoStore[token] = {
    buffer: imgBuffer,
    createdAt: Date.now(),
    used: false,
    bgRemoved: bgRemoved !== false // default true for backwards compat
  };
  setTimeout(function() { delete photoStore[token]; }, 30 * 60 * 1000);
}

function getPhoto(token) {
  var entry = photoStore[token];
  if (!entry) return null;
  if (entry.used) return null;
  return entry;
}

function deletePhoto(token) {
  if (photoStore[token]) {
    photoStore[token].used = true;
    photoStore[token].buffer = null;
    delete photoStore[token];
  }
}

async function storePrintPhoto(printCode, imgBuffer) {
  var base64 = imgBuffer.toString('base64');
  // Save to memory immediately
  printPhotoStore[printCode] = { buffer: imgBuffer, createdAt: Date.now() };
  // Auto-delete from memory after 72 hours (GDPR compliance)
  setTimeout(function() { delete printPhotoStore[printCode]; }, 72 * 60 * 60 * 1000);
  // Save to MongoDB (awaited — not fire-and-forget, so it survives restarts)
  try {
    await PrintPhoto.findOneAndUpdate(
      { printCode: printCode },
      { printCode: printCode, photoData: base64, createdAt: new Date(),
        expiresAt: new Date(Date.now() + 72 * 60 * 60 * 1000) },
      { upsert: true, new: true }
    );
    console.log('[INFO] Print photo saved to DB for code: ' + printCode);
  } catch(e) {
    console.error('[ERROR] Print photo DB save failed:', e.message);
  }
}

function getPrintPhoto(printCode) { return printPhotoStore[printCode] || null; }

async function getPrintPhotoAsync(printCode) {
  if (printPhotoStore[printCode]) return printPhotoStore[printCode];
  try {
    var doc = await PrintPhoto.findOne({ printCode: printCode }).lean();
    if (doc && doc.photoData) return { buffer: Buffer.from(doc.photoData, 'base64'), createdAt: doc.createdAt };
  } catch(e) { console.error('Print photo DB fetch error:', e.message); }
  return null;
}

function deletePrintPhoto(printCode) {
  delete printPhotoStore[printCode];
  PrintPhoto.deleteOne({ printCode: printCode }).catch(function(){});
}

// ── SERVER-SIDE remove.bg ─────────────────────────────────
// Called only after payment is confirmed — prevents free API usage by non-paying users
function getPassportDimensions(purpose) {
  var DPI = 300;
  var w_mm = 35, h_mm = 45;
  if (purpose) {
    var p = purpose.toLowerCase();
    if (p.includes('20') && p.includes('25'))      { w_mm=20; h_mm=25; }
    else if (p.includes('25') && p.includes('30')) { w_mm=25; h_mm=30; }
    else if (p.includes('33') && p.includes('48')) { w_mm=33; h_mm=48; }
    else if (p.includes('40') && p.includes('60')) { w_mm=40; h_mm=60; }
    else if (p.includes('43') && p.includes('55')) { w_mm=43; h_mm=55; }
    else if (p.includes('50') && p.includes('70')) { w_mm=50; h_mm=70; }
    else if (p.includes('51') || p.includes('2x2')){ w_mm=51; h_mm=51; }
  }
  return {
    w_px: Math.round(w_mm / 25.4 * DPI),
    h_px: Math.round(h_mm / 25.4 * DPI),
    w_mm: w_mm, h_mm: h_mm
  };
}

// ── Resize to passport dimensions using jimp (pure JS) ──────────────────────
async function resizeToPassport(imgBuffer, purpose) {
  var dims = getPassportDimensions(purpose);
  console.log('[INFO] Resizing to ' + dims.w_px + 'x' + dims.h_px + 'px (' + dims.w_mm + 'x' + dims.h_mm + 'mm)');

  // Try jimp first
  try {
    var Jimp = require('jimp');
    var image = await Jimp.read(imgBuffer);
    var iw = image.getWidth();
    var ih = image.getHeight();

    // Scale so the subject fills ~85% of the output height (face prominent)
    // Use cover to fill then crop from centre-top
    var scale = Math.max(dims.w_px / iw, (dims.h_px * 0.95) / ih);
    var newW = Math.round(iw * scale);
    var newH = Math.round(ih * scale);

    image.resize(newW, newH);

    // Crop: centre horizontally, anchor 8% from top (headroom)
    var cropX = Math.max(0, Math.round((newW - dims.w_px) / 2));
    var cropY = Math.max(0, Math.round(newH * 0.04));
    // Clamp crop so we don't go out of bounds
    if (cropX + dims.w_px > newW) cropX = newW - dims.w_px;
    if (cropY + dims.h_px > newH) cropY = newH - dims.h_px;

    image.crop(cropX, cropY, dims.w_px, dims.h_px);
    var result = await image.quality(95).getBufferAsync(Jimp.MIME_JPEG);
    console.log('[INFO] jimp resize success: ' + result.length + 'bytes');
    return result;
  } catch(jimpErr) {
    console.warn('[WARN] jimp not available: ' + jimpErr.message);
  }

  // Fallback: try @napi-rs/canvas
  try {
    var { createCanvas, loadImage } = require('@napi-rs/canvas');
    var img = await loadImage(imgBuffer);
    var canvas = createCanvas(dims.w_px, dims.h_px);
    var ctx = canvas.getContext('2d');
    // Cover: maintain aspect ratio, crop to fill
    var scale = Math.max(dims.w_px / img.width, dims.h_px / img.height);
    var sw = img.width * scale, sh = img.height * scale;
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, dims.w_px, dims.h_px);
    ctx.drawImage(img, (dims.w_px - sw) / 2, 0, sw, sh); // anchor top
    var result = canvas.toBuffer('image/jpeg', { quality: 0.95 });
    console.log('[INFO] canvas resize success');
    return result;
  } catch(canvasErr) {
    console.warn('[WARN] canvas not available: ' + canvasErr.message);
  }

  // Final fallback: return as-is (will be wrong size but at least bg removed)
  console.warn('[WARN] No resize library available — returning bg-removed image at original size');
  return imgBuffer;
}

function removeBackgroundServer(imgBuffer, mimeType, purpose) {
  return new Promise(function(resolve, reject) {
    // Validate API key exists
    if (!process.env.REMOVE_BG_KEY) {
      return reject(new Error('REMOVE_BG_KEY not set in environment'));
    }

    // If image is very large, downscale before sending to remove.bg (saves credits + faster)
    // remove.bg free tier: max 0.25MP preview; paid: full HD
    var fd = new FormData();
    fd.append('image_file', imgBuffer, {
      filename: 'photo.jpg',
      contentType: mimeType || 'image/jpeg',
      knownLength: imgBuffer.length
    });
    fd.append('size', 'auto');
    fd.append('type', 'person');
    fd.append('bg_color', 'ffffff');
    fd.append('format', 'jpg');

    console.log('[INFO] Calling remove.bg, imgSize=' + imgBuffer.length + ' key=' + (process.env.REMOVE_BG_KEY||'').substring(0,8) + '...');

    axios.post('https://api.remove.bg/v1.0/removebg', fd, {
      headers: Object.assign({ 'X-Api-Key': process.env.REMOVE_BG_KEY }, fd.getHeaders()),
      responseType: 'arraybuffer',
      timeout: 60000,
      maxContentLength: Infinity,
      maxBodyLength: Infinity
    }).then(function(response) {
      var resultBuf = Buffer.from(response.data);
      // Check for error response (remove.bg returns JSON errors even with arraybuffer)
      var first = resultBuf.slice(0, 1).toString();
      if (first === '{') {
        var errMsg = resultBuf.toString();
        console.error('[ERROR] remove.bg returned error JSON:', errMsg);
        return reject(new Error('remove.bg error: ' + errMsg));
      }
      console.log('[INFO] remove.bg success, resultSize=' + resultBuf.length + 'bytes');
      resolve(resultBuf);
    }).catch(function(err) {
      var msg = err.message;
      if (err.response && err.response.data) {
        try { msg = Buffer.from(err.response.data).toString(); } catch(e) {}
      }
      console.error('[ERROR] remove.bg axios error:', msg);
      reject(new Error('Background removal failed: ' + msg));
    });
  });
}

// ── Resend email ──────────────────────────────────────────
function sendEmail(to, subject, html, attachments) {
  var payload = { from: 'Photobooth App <info@photoboothapp.co.uk>', to: [to], subject: subject, html: html };
  if (attachments && attachments.length > 0) {
    payload.attachments = attachments.map(function(a) {
      return { filename: a.filename, content: a.content.toString('base64') };
    });
  }
  return axios.post('https://api.resend.com/emails', payload, {
    headers: { 'Authorization': 'Bearer ' + process.env.RESEND_API_KEY, 'Content-Type': 'application/json' }
  });
}

// ── Admin auth ────────────────────────────────────────────
function adminAuth(req, res, next) {
  var token = req.headers['x-admin-token'] || req.query.token;
  if (!token) return res.status(401).json({ error: 'Unauthorised' });
  if (token === process.env.ADMIN_TOKEN) { req.adminRole = 'master'; req.adminSource = null; return next(); }
  if (token === process.env.SABTECH_ADMIN_TOKEN) { req.adminRole = 'sabtech'; req.adminSource = 'sabtech'; return next(); }
  if (token === process.env.VFS_ADMIN_TOKEN) { req.adminRole = 'vfs'; req.adminSource = 'vfs'; return next(); }
  return res.status(401).json({ error: 'Unauthorised' });
}

// ════════════════════════════════════════════════════════
// PUBLIC API
// ════════════════════════════════════════════════════════

// ── Validate photo (Claude AI) ────────────────────────────
app.post('/api/validate-photo', rateLimit(20, 60000), upload.single('photo'), function(req, res) {
  if (!req.file) return res.status(400).json({ error: 'No photo uploaded' });
  if (!validateFileType(req.file.buffer)) return res.status(400).json({ error: 'Invalid file type.' });
  var base64Image = req.file.buffer.toString('base64');
  var mimeType = req.file.mimetype;
  axios.post('https://api.anthropic.com/v1/messages', {
    model: 'claude-haiku-4-5-20251001', max_tokens: 400,
    messages: [{ role: 'user', content: [
      { type: 'image', source: { type: 'base64', media_type: mimeType, data: base64Image } },
      { type: 'text', text: 'You are a passport photo compliance checker.\n\nAnalyse this photo. Reply ONLY with valid JSON, no markdown.\n\nFormat: {\"approved\":true,\"issues\":[],\"message\":\"one sentence\"}\n\nCheck for these issues (use exact keys):\n- glasses_detected: ONLY flag if you can clearly see actual glasses FRAMES on the nose bridge AND arms over the ears. Do NOT flag for eyebrows, eye bags, under-eye shadows, skin reflections, or any natural facial feature. If uncertain, do NOT flag.\n- no_face: no human face visible\n- multiple_faces: more than one person\n- eyes_closed: eyes not fully open\n- head_tilted: head significantly tilted or turned\n- hat_or_headwear: hat or cap present (religious headwear allowed)\n- poor_lighting: very harsh uneven lighting or deep shadows on face\n- face_too_small: face less than 40% of frame height\n- blurry: clearly out of focus\n- mouth_open: lips noticeably open\n\nOnly flag issues that are clearly and obviously present. When in doubt, approve.' }
    ]}]
  }, { headers: { 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' } })
  .then(function(r) {
    var text = r.data.content.filter(function(b){return b.type==='text';}).map(function(b){return b.text;}).join('');
    try { res.json(JSON.parse(text.replace(/```json|```/g,'').trim())); }
    catch(e) { res.json({ approved: true, issues: [], message: 'Photo accepted.' }); }
  }).catch(function(err) {
    Sentry.captureException(err);
    res.json({ approved: true, issues: [], message: 'Photo accepted.' });
  });
});

// ── Remove background (public endpoint — only used for retake flow) ───
// NOTE: For new orders, background removal now happens server-side in /api/confirm-order
// after payment is verified. This endpoint is kept for the retake flow only.
app.post('/api/remove-bg', rateLimit(20, 60000), upload.single('photo'), function(req, res) {
  if (!req.file) return res.status(400).json({ error: 'No photo uploaded' });
  if (!validateFileType(req.file.buffer)) return res.status(400).json({ error: 'Invalid file type.' });
  var recaptchaToken = req.body && req.body.recaptchaToken;
  validateImageDimensions(req.file.buffer).then(function(dimCheck) {
    if (!dimCheck.valid) return res.status(400).json({ error: dimCheck.error });
    verifyRecaptcha(recaptchaToken, 0.1).then(function(valid) {
      if (!valid) return res.status(400).json({ error: 'Security check failed. Please try again.' });
      removeBackgroundServer(req.file.buffer, req.file.mimetype)
      .then(function(resultBuffer) {
        // remove.bg now returns JPEG with white background
        res.json({ success: true, image: 'data:image/jpeg;base64,' + resultBuffer.toString('base64') });
      }).catch(function(err) {
        Sentry.captureException(err);
        res.status(500).json({ error: err.message });
      });
    });
  });
});

// ── Create payment intent ─────────────────────────────────
var PRICES = {
  GBP: { digital: 699,  print: 999,  symbol: '£', currency: 'gbp' },
  EUR: { digital: 829,  print: 1199, symbol: '€', currency: 'eur' },
  USD: { digital: 899,  print: 1299, symbol: '$', currency: 'usd' }
};

app.post('/api/create-payment-intent', rateLimit(30, 60000), function(req, res) {
  var name        = sanitise(req.body.name || '');
  var email       = sanitise(req.body.email || '');
  var currencyKey = (req.body.currency || 'GBP').toUpperCase();
  if (!PRICES[currencyKey]) currencyKey = 'GBP';
  var priceSet    = PRICES[currencyKey];
  var printOption = req.body.printOption || 'digital';
  var amount      = printOption === 'print' ? priceSet.print : priceSet.digital;
  if (!name || !email || !email.includes('@')) return res.status(400).json({ error: 'Invalid details' });
  stripe.paymentIntents.create({
    amount: amount,
    currency: priceSet.currency,
    metadata: { customer_name: name, customer_email: email, amount: amount, currency: currencyKey },
    receipt_email: email
  }).then(function(intent) {
    res.json({ clientSecret: intent.client_secret });
  }).catch(function(err) {
    Sentry.captureException(err);
    res.status(500).json({ error: err.message });
  });
});

// ── CHANGE 2: Store photo — now records bgRemoved flag ────
app.post('/api/store-photo', rateLimit(20, 60000), function(req, res) {
  var passportImage = req.body.passportImage;
  var bgRemoved     = req.body.bgRemoved !== false; // false means server must call remove.bg
  if (!passportImage) return res.status(400).json({ error: 'No image' });
  var token = crypto.randomBytes(32).toString('hex');
  var imgBuffer = Buffer.from(passportImage.replace(/^data:image\/\w+;base64,/, ''), 'base64');
  if (imgBuffer.length > 10 * 1024 * 1024) return res.status(400).json({ error: 'Image too large' });
  storePhoto(token, imgBuffer, bgRemoved);
  console.log('[INFO] Photo stored. bgRemoved=' + bgRemoved + ' token=' + token.substring(0,8) + '...');
  res.json({ token: token });
});

// ── CHANGE 3: Confirm order — calls remove.bg after payment if needed ──
app.post('/api/confirm-order', rateLimit(10, 60000), async function(req, res) {
  var name             = sanitise(req.body.name);
  var email            = sanitise(req.body.email);
  var phone            = sanitise(req.body.phone);
  var centre           = sanitise(req.body.centre);
  var purpose          = sanitise(req.body.purpose);
  var govRef           = sanitise(req.body.govRef);
  var photoToken       = req.body.photoToken;
  var orderRef         = sanitise(req.body.orderRef);
  var paymentIntentId  = sanitise(req.body.paymentIntentId);
  var printOption      = sanitise(req.body.printOption) || 'digital';
  var printLocation    = sanitise(req.body.printLocation) || null;
  var source           = sanitise(req.body.source) || 'direct';
  var currency         = sanitise(req.body.currency) || 'GBP';
  if (!PRICES[currency]) currency = 'GBP';
  var priceData        = PRICES[currency];
  var orderAmount      = printOption === 'print' ? priceData.print / 100 : priceData.digital / 100;
  var currencySymbol   = currency === 'EUR' ? '€' : currency === 'USD' ? '$' : '£';

  if (!name||!email||!phone||!centre||!purpose||!photoToken||!paymentIntentId)
    return res.status(400).json({ error: 'Missing required fields' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: 'Invalid email address' });

  try {
    // ── Step 1: Verify payment with Stripe ───────────────
    var intent = await stripe.paymentIntents.retrieve(paymentIntentId);
    if (!intent || intent.status !== 'succeeded') {
      Sentry.captureMessage('Payment verification failed: ' + paymentIntentId);
      return res.status(402).json({ error: 'Payment not verified. Please contact support.' });
    }

    // ── Step 2: Get stored photo ──────────────────────────
    var photoData = getPhoto(photoToken);
    if (!photoData) return res.status(400).json({ error: 'Photo expired. Please start again.' });
    var imgBuffer = photoData.buffer;
    var bgAlreadyRemoved = photoData.bgRemoved;

    // ── Step 3: Always run remove.bg server-side after payment ──
    // Guarantees white background regardless of what client sent
    // Skip remove.bg if SKIP_REMOVEBG=true in env (for testing — saves credits)
    if (process.env.SKIP_REMOVEBG === 'true') {
      console.log('[INFO] SKIP_REMOVEBG=true — skipping remove.bg for: ' + orderRef);
    } else {
    console.log('[INFO] Running server-side remove.bg for order: ' + orderRef + ' imgSize=' + imgBuffer.length + 'bytes');
    try {
      var removedBuffer = await removeBackgroundServer(imgBuffer, 'image/jpeg', purpose);
      if (!removedBuffer || removedBuffer.length < 1000) {
        throw new Error('remove.bg returned empty or invalid response (' + (removedBuffer ? removedBuffer.length : 0) + ' bytes)');
      }
      imgBuffer = removedBuffer;
      console.log('[INFO] remove.bg success for: ' + orderRef + ' resultSize=' + imgBuffer.length + 'bytes');
      // Resize to exact passport dimensions
      imgBuffer = await resizeToPassport(imgBuffer, purpose);
    } catch(bgErr) {
      Sentry.captureException(bgErr);
      console.error('[ERROR] remove.bg FAILED for ' + orderRef + ': ' + bgErr.message);
      if (bgErr.response) {
        console.error('[ERROR] remove.bg response status: ' + bgErr.response.status);
        console.error('[ERROR] remove.bg response data: ' + JSON.stringify(bgErr.response.data || ''));
      }
    } // end SKIP_REMOVEBG else
    }


    var firstName = name.split(' ')[0];
    var cleanPurpose = purpose.replace(/\s*[—–-]\s*[\d×xX\/\s\(\)inchmm\.]+$/i, '').trim();

    // ── Step 4: Generate print code if needed ────────────
    var printCode = null;
    var printCodeExpiry = null;
    if (printOption === 'print') {
      printCode = generatePrintCode();
      printCodeExpiry = new Date(Date.now() + 72 * 60 * 60 * 1000);
    }

    // ── Step 5: Save to MongoDB ───────────────────────────
    new Order({
      orderRef: orderRef, date: new Date(),
      name: name, email: email, phone: phone,
      centre: centre, purpose: purpose, govRef: govRef || '',
      amount: orderAmount, currency: currency, status: 'completed',
      source: source, paymentIntentId: paymentIntentId, emailSent: false,
      printOption: printOption, printCode: printCode,
      printCodeExpiry: printCodeExpiry, printLocation: printLocation
    }).save().catch(function(e) {
      Sentry.captureException(e);
      console.error('DB save error:', e.message);
    });

    // ── Step 6: Build email ───────────────────────────────
    var printCodeSection = '';
    if (printOption === 'print' && printCode) {
      printCodeSection =
        '<div style="background:#0d1b2e;color:white;padding:20px;border-radius:10px;margin:20px 0;text-align:center;">' +
        '<p style="font-size:13px;color:#8a9bb0;margin-bottom:8px;letter-spacing:1px;text-transform:uppercase;">Your Print Code</p>' +
        '<p style="font-size:36px;font-weight:bold;letter-spacing:6px;color:#F5D06A;margin:0;">' + printCode + '</p>' +
        '<p style="font-size:12px;color:#8a9bb0;margin-top:8px;">Valid for 72 hours · Location: ' + (printLocation || 'LON-WILSON') + '</p>' +
        '<p style="font-size:12px;color:#8a9bb0;margin-top:4px;">Enter this code at the photo kiosk to print your photos</p>' +
        '</div>';
    }

    var amountPaid = currency === 'EUR'
      ? (printOption === 'print' ? '€11.99' : '€8.29')
      : currency === 'USD'
        ? (printOption === 'print' ? '$12.99' : '$8.99')
        : (printOption === 'print' ? '£9.99' : '£6.99');

    var customerHtml =
      '<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;">' +
      '<div style="background:#0d1b2e;padding:28px 32px;"><h1 style="color:white;font-size:22px;margin:0;">Photobooth App</h1>' +
      '<p style="color:#8a9bb0;font-size:12px;margin:4px 0 0;">by Sabtech Limited</p></div>' +
      '<div style="padding:32px;"><h2>Your photo is ready, ' + firstName + '!</h2>' +
      '<p style="color:#5a6275;">Thank you for your order. Your passport photo is attached.</p>' +
      printCodeSection +
      '<div style="background:#f8f9fb;padding:20px;border-radius:10px;margin:20px 0;font-size:13px;">' +
      '<p><strong>Order Ref:</strong> ' + orderRef + '</p>' +
      '<p><strong>Photo Purpose:</strong> ' + cleanPurpose + '</p>' +
      '<p><strong>Application Centre:</strong> ' + centre + '</p>' +
      (govRef ? '<p><strong>Your Reference:</strong> ' + govRef + '</p>' : '') +
      '<p><strong>Total Paid:</strong> ' + amountPaid + '</p>' +
      '<p><strong>Service:</strong> ' + (printOption === 'print' ? 'Digital + Print' : 'Digital Only') + '</p></div>' +
      '<p style="background:#f0fdf4;color:#166534;padding:14px;border-radius:8px;">Your photo is attached — formatted to the correct size for your application. Photos are automatically deleted from our servers immediately after this email is sent.</p>' +
      '<div style="margin-top:24px;padding:14px;background:#f8f9fb;border-radius:8px;font-size:12px;color:#8a9bb0;">' +
      '<p><strong>Data & Privacy:</strong> Your photo and personal data are processed under UK GDPR. Photos are deleted automatically after delivery.</p>' +
      '<p style="margin-top:8px;"><strong>Refund Policy:</strong> If your photo is rejected by the application centre, contact us within 7 days for a replacement or full refund.</p>' +
      '</div>' +
      '<p style="color:#8a9bb0;font-size:12px;margin-top:20px;">Questions? Contact us at info@photoboothapp.co.uk · Photobooth App · Sabtech Limited</p>' +
      '</div></div>';

    var adminHtml =
      '<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;">' +
      '<div style="background:#0d1b2e;padding:20px 24px;"><h2 style="color:white;margin:0;">New Order — ' + orderRef + '</h2></div>' +
      '<div style="padding:24px;background:#f8f9fb;font-size:14px;">' +
      '<p><strong>Customer:</strong> ' + name + '</p><p><strong>Email:</strong> ' + email + '</p>' +
      '<p><strong>Phone:</strong> ' + phone + '</p><p><strong>Purpose:</strong> ' + cleanPurpose + '</p>' +
      '<p><strong>Centre:</strong> ' + centre + '</p>' +
      (govRef ? '<p><strong>Gov Ref:</strong> ' + govRef + '</p>' : '') +
      '<p><strong>BG Removed Server-side:</strong> ' + (!bgAlreadyRemoved ? 'Yes (paid)' : 'No (RMBG free)') + '</p>' +
      '<p><strong>Stripe PI:</strong> ' + paymentIntentId + '</p>' +
      '<p style="font-size:16px;font-weight:bold;margin-top:12px;">Amount: ' + amountPaid + ' ✓ VERIFIED</p>' +
      '</div></div>';

    var attachment = [{ filename: 'passport_photo_' + orderRef + '.jpg', content: imgBuffer }];

    // ── Step 7: Send emails ───────────────────────────────
    await sendEmail(email, 'Your Passport Photo - Order ' + orderRef, customerHtml, attachment);
    await sendEmail(process.env.ADMIN_EMAIL, 'New Order ' + orderRef + ' - ' + name, adminHtml, attachment);

    // ── Step 8: Store for print kiosk if needed ───────────
    if (printOption === 'print' && printCode) {
      storePrintPhoto(printCode, imgBuffer);
    }

    deletePhoto(photoToken);
    Order.findOneAndUpdate({ orderRef: orderRef }, { emailSent: true }).catch(function(){});
    // Return processed image to client so downloads also have white background
    var processedImageBase64 = 'data:image/jpeg;base64,' + imgBuffer.toString('base64');
    res.json({ success: true, orderRef: orderRef, printCode: printCode, processedImage: processedImageBase64 });

  } catch(err) {
    Sentry.captureException(err);
    console.error('[ERROR] confirm-order:', err.message);
    res.status(500).json({ error: 'Payment received but email failed. Order ref: ' + orderRef + '. Contact support at info@photoboothapp.co.uk' });
  }
});

// ── Stripe webhook ────────────────────────────────────────
app.post('/api/stripe-webhook', function(req, res) {
  var sig = req.headers['stripe-signature'];
  var event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET || '');
  } catch(err) {
    Sentry.captureException(err);
    return res.status(400).send('Webhook Error: ' + err.message);
  }
  if (event.type === 'payment_intent.succeeded') {
    console.log('Webhook: Payment confirmed', event.data.object.id);
  }
  res.json({ received: true });
});

// ════════════════════════════════════════════════════════
// ADMIN API
// ════════════════════════════════════════════════════════

app.post('/api/admin/login', rateLimit(5, 60000), function(req, res) {
  var ip = (req.headers['x-forwarded-for'] || req.ip || 'unknown').split(',')[0].trim();
  var password = req.body.password;
  var portal   = req.body.portal || 'master';
  var token = null;
  if (portal === 'vfs' && password === process.env.VFS_ADMIN_PASSWORD) token = process.env.VFS_ADMIN_TOKEN;
  else if (portal === 'sabtech' && password === process.env.SABTECH_ADMIN_PASSWORD) token = process.env.SABTECH_ADMIN_TOKEN;
  else if (password === process.env.ADMIN_PASSWORD) token = process.env.ADMIN_TOKEN;
  if (!token) {
    console.log('[WARN] ' + JSON.stringify({ ts: new Date().toISOString(), event: 'admin_login_failed', portal: portal, ip: ip }));
    return res.status(401).json({ error: 'Invalid password' });
  }
  res.json({ success: true, token: token, portal: portal });
});

app.get('/api/admin/orders', adminAuth, function(req, res) {
  var search   = sanitise(req.query.search||'').toLowerCase();
  var status   = sanitise(req.query.status||'');
  var dateFrom = req.query.dateFrom||'';
  var dateTo   = req.query.dateTo||'';
  var query = {};
  if (req.adminSource) query.source = req.adminSource;
  if (status) query.status = status;
  if (dateFrom || dateTo) {
    query.date = {};
    if (dateFrom) query.date.$gte = new Date(dateFrom);
    if (dateTo)   query.date.$lte = new Date(dateTo + 'T23:59:59');
  }
  Order.find(query).sort({ date: -1 }).lean().then(function(orders) {
    if (search) orders = orders.filter(function(o) {
      return (o.name||'').toLowerCase().includes(search) ||
             (o.email||'').toLowerCase().includes(search) ||
             (o.orderRef||'').toLowerCase().includes(search) ||
             (o.govRef||'').toLowerCase().includes(search);
    });
    var now = new Date();
    var today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    var monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
    Order.find({}).lean().then(function(all) {
      var tod = all.filter(function(o){ return new Date(o.date) >= today; });
      var mon = all.filter(function(o){ return new Date(o.date) >= monthStart; });
      res.json({ orders: orders, stats: {
        total: all.length, totalRevenue: all.reduce(function(s,o){ return s+(o.amount||0); }, 0),
        todayCount: tod.length, todayRevenue: tod.reduce(function(s,o){ return s+(o.amount||0); }, 0),
        monthCount: mon.length, monthRevenue: mon.reduce(function(s,o){ return s+(o.amount||0); }, 0),
      }});
    });
  }).catch(function(err) {
    Sentry.captureException(err);
    res.status(500).json({ error: err.message });
  });
});

app.get('/api/admin/export', adminAuth, function(req, res) {
  var query = {};
  if (req.adminSource) query.source = req.adminSource;
  if (req.query.dateFrom || req.query.dateTo) {
    query.date = {};
    if (req.query.dateFrom) query.date.$gte = new Date(req.query.dateFrom);
    if (req.query.dateTo)   query.date.$lte = new Date(req.query.dateTo + 'T23:59:59');
  }
  Order.find(query).sort({ date: -1 }).lean().then(function(orders) {
    var headers = ['Order Ref','Date','Time','Customer Name','Email','Phone','Application Centre','Photo Purpose','Gov Reference','Amount','Currency','Status','Email Sent','Payment ID'];
    var rows = orders.map(function(o) {
      var d = o.date ? new Date(o.date) : new Date();
      return [o.orderRef, d.toLocaleDateString('en-GB'), d.toLocaleTimeString('en-GB'),
        o.name, o.email, o.phone, o.centre, o.purpose, o.govRef||'',
        o.amount||6.99, o.currency||'GBP', o.status, o.emailSent?'Yes':'No', o.paymentIntentId||''
      ].map(function(v){ return '"'+(v||'').toString().replace(/"/g,'""')+'"'; }).join(',');
    });
    res.setHeader('Content-Type','text/csv');
    res.setHeader('Content-Disposition','attachment; filename="photobooth_orders_'+new Date().toISOString().split('T')[0]+'.csv"');
    res.send([headers.join(',')].concat(rows).join('\n'));
  }).catch(function(err) { res.status(500).json({ error: err.message }); });
});

app.post('/api/admin/resend-email', adminAuth, function(req, res) {
  Order.findOne({ orderRef: sanitise(req.body.orderRef) }).lean().then(function(order) {
    if (!order) return res.status(404).json({ error: 'Order not found' });
    var html = '<div style="font-family:Arial,sans-serif;padding:24px;"><h2>Your Passport Photo — Order ' + order.orderRef + '</h2>' +
      '<p>This is a resent confirmation. Contact info@photoboothapp.co.uk for assistance.</p>' +
      '<p><strong>Purpose:</strong> ' + order.purpose + '</p><p><strong>Centre:</strong> ' + order.centre + '</p></div>';
    sendEmail(order.email, '[Resent] Passport Photo Order ' + order.orderRef, html, [])
    .then(function() {
      Order.findOneAndUpdate({ orderRef: order.orderRef }, { resentAt: new Date() }).catch(function(){});
      res.json({ success: true });
    }).catch(function(err) { res.status(500).json({ error: err.message }); });
  }).catch(function(err) { res.status(500).json({ error: err.message }); });
});

app.delete('/api/admin/orders/:ref', adminAuth, function(req, res) {
  Order.findOneAndDelete({ orderRef: sanitise(req.params.ref) })
  .then(function() { res.json({ success: true }); })
  .catch(function(err) { res.status(500).json({ error: err.message }); });
});

function generatePrintCode() {
  var digits = Math.floor(100000 + Math.random() * 900000).toString();
  return 'PBA-' + digits;
}

app.get('/api/health', function(req, res) {
  res.json({
    status: 'ok',
    db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    removeBgKey: process.env.REMOVE_BG_KEY ? 'set (' + process.env.REMOVE_BG_KEY.substring(0,6) + '...)' : 'MISSING'
  });
});

// Debug: check order + photo status
// Usage: /api/admin/check-order?code=PBA-537321&token=sabtech-admin-token-2024
app.get('/api/admin/check-order', async function(req, res) {
  if (req.query.token !== 'sabtech-admin-token-2024') return res.status(401).json({ error: 'Unauthorised' });
  var code = (req.query.code || '').toUpperCase().trim();
  try {
    var order = await Order.findOne({
      $or: [{ printCode: code }, { orderRef: code }]
    }).lean();
    if (!order) return res.json({ found: false, code: code });
    var photo = await getPrintPhotoAsync(order.printCode);
    res.json({
      found: true,
      orderRef: order.orderRef,
      printCode: order.printCode,
      printOption: order.printOption,
      printed: order.printed,
      photoStored: !!photo,
      photoSize: photo ? photo.buffer.length : 0
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Admin: reset print code so it can be reused for testing ──────────────────
// Usage: GET /api/admin/reset-print?code=PBA-XXXXXX&token=sabtech-admin-token-2024
app.get('/api/admin/reset-print', async function(req, res) {
  if (req.query.token !== 'sabtech-admin-token-2024') {
    return res.status(401).json({ error: 'Unauthorised' });
  }
  var code = (req.query.code || '').toUpperCase().trim();
  if (!code) return res.status(400).json({ error: 'code required' });
  try {
    var result = await Order.updateOne(
      { orderRef: code },
      { $set: { printed: false, printedAt: null } }
    );
    if (result.matchedCount === 0) {
      return res.status(404).json({ error: 'Order not found: ' + code });
    }
    console.log('[ADMIN] Print code reset: ' + code);
    res.json({ success: true, message: 'Print code reset — ' + code + ' can be used again' });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Test remove.bg connectivity (admin only) ──────────────
app.get('/api/admin/test-removebg', adminAuth, async function(req, res) {
  try {
    // Make a minimal test call to remove.bg to check key and credits
    var testResponse = await axios.get('https://api.remove.bg/v1.0/account', {
      headers: { 'X-Api-Key': process.env.REMOVE_BG_KEY }
    });
    res.json({
      ok: true,
      credits_subscription: testResponse.data.data.attributes.credits.subscription,
      credits_payg: testResponse.data.data.attributes.credits.payg,
      credits_enterprise: testResponse.data.data.attributes.credits.enterprise
    });
  } catch(err) {
    res.status(500).json({
      ok: false,
      error: err.response ? JSON.stringify(err.response.data) : err.message,
      status: err.response ? err.response.status : 'no response'
    });
  }
});

// ── Free Retake Endpoints ─────────────────────────────────
app.post('/api/admin/issue-retake', function(req, res) {
  var token = req.headers['x-admin-token'] || req.body.adminToken;
  if (token !== process.env.SABTECH_ADMIN_TOKEN && token !== process.env.ADMIN_TOKEN) {
    return res.status(401).json({ error: 'Unauthorised' });
  }
  var orderRef = sanitise(req.body.orderRef);
  if (!orderRef) return res.status(400).json({ error: 'Order ref required' });
  Order.findOne({ orderRef: orderRef }).then(function(order) {
    if (!order) return res.status(404).json({ error: 'Order not found' });
    if (order.retakeIssued) return res.status(400).json({ error: 'Retake already issued for this order' });
    var retakeToken = require('crypto').randomBytes(24).toString('hex');
    var retakeUrl = 'https://photoboothapp.co.uk/retake/' + retakeToken;
    return new Retake({
      token: retakeToken, orderRef: order.orderRef,
      email: order.email, name: order.name,
      centre: order.centre, purpose: order.purpose, source: order.source || 'sabtech'
    }).save().then(function() {
      return Order.findOneAndUpdate({ orderRef: orderRef }, { retakeIssued: true, retakeIssuedAt: new Date(), retakeToken: retakeToken });
    }).then(function() {
      var firstName = order.name ? order.name.split(' ')[0] : 'there';
      var html =
        '<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;">' +
        '<div style="background:#0d1b2e;padding:28px 32px;"><h1 style="color:white;font-size:22px;margin:0;">Photobooth App</h1></div>' +
        '<div style="padding:32px;">' +
        '<h2 style="color:#0d1b2e;">Your free retake is ready, ' + firstName + '!</h2>' +
        '<p style="color:#5a6275;">We\'re sorry your photo was rejected. We\'ve issued you a <strong>free retake</strong> — no payment needed.</p>' +
        '<div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:10px;padding:20px;margin:20px 0;text-align:center;">' +
        '<a href="' + retakeUrl + '" style="display:inline-block;background:#0d1b2e;color:white;padding:14px 32px;border-radius:99px;text-decoration:none;font-weight:600;font-size:15px;">📸 Retake My Photo — Free</a>' +
        '<p style="font-size:11px;color:#8a9bb0;margin-top:12px;">Link valid for 7 days · Single use only</p>' +
        '</div>' +
        '<div style="background:#f8f9fb;border-radius:8px;padding:16px;font-size:13px;">' +
        '<p><strong>Original Order:</strong> ' + order.orderRef + '</p>' +
        '<p><strong>Photo Purpose:</strong> ' + order.purpose + '</p>' +
        '<p><strong>Application Centre:</strong> ' + order.centre + '</p>' +
        '</div>' +
        '<p style="color:#8a9bb0;font-size:12px;margin-top:20px;">Questions? Contact info@photoboothapp.co.uk</p>' +
        '</div></div>';
      return sendEmail(order.email, 'Your Free Photo Retake — ' + order.orderRef, html, null);
    }).then(function() {
      res.json({ success: true, retakeToken: retakeToken, retakeUrl: retakeUrl });
    });
  }).catch(function(err) { res.status(500).json({ error: err.message }); });
});

app.get('/api/retake/:token', function(req, res) {
  var token = sanitise(req.params.token);
  Retake.findOne({ token: token, used: false }).lean().then(function(retake) {
    if (!retake) return res.status(404).json({ error: 'Invalid or expired retake link.' });
    res.json({ success: true, name: retake.name, email: retake.email, centre: retake.centre, purpose: retake.purpose, source: retake.source, orderRef: retake.orderRef });
  }).catch(function(err) { res.status(500).json({ error: err.message }); });
});

app.post('/api/retake/confirm', rateLimit(10, 60000), function(req, res) {
  var token      = sanitise(req.body.token);
  var photoToken = req.body.photoToken;
  var orderRef   = sanitise(req.body.orderRef);
  Retake.findOne({ token: token, used: false }).then(function(retake) {
    if (!retake) return res.status(400).json({ error: 'Invalid or already used retake link.' });
    var photo = getPhoto(photoToken);
    if (!photo) return res.status(400).json({ error: 'Photo not found. Please upload again.' });
    var imgBuffer = photo.buffer;
    var attachment = { filename: 'passport_photo_retake.jpg', content: imgBuffer, contentType: 'image/jpeg' };
    return Order.findOne({ orderRef: retake.orderRef }).lean().then(function(originalOrder) {
      var isPrint = originalOrder && originalOrder.printOption === 'print';
      var newPrintCode = null;
      var newPrintCodeExpiry = null;
      if (isPrint) {
        newPrintCode = generatePrintCode();
        newPrintCodeExpiry = new Date(Date.now() + 72 * 60 * 60 * 1000);
        storePrintPhoto(newPrintCode, imgBuffer);
      }
      retake.used = true; retake.usedAt = new Date(); retake.save().catch(function(){});
      Order.findOneAndUpdate({ orderRef: retake.orderRef }, { retakeUsed: true, retakeUsedAt: new Date() }).catch(function(){});
      var firstName = retake.name ? retake.name.split(' ')[0] : 'there';
      var printCodeSection = '';
      if (isPrint && newPrintCode) {
        printCodeSection =
          '<div style="background:#0d1b2e;color:white;padding:20px;border-radius:10px;margin:20px 0;text-align:center;">' +
          '<p style="font-size:13px;color:#8a9bb0;margin-bottom:8px;letter-spacing:1px;text-transform:uppercase;">Your New Print Code</p>' +
          '<p style="font-size:36px;font-weight:bold;letter-spacing:6px;color:#F5D06A;margin:0;">' + newPrintCode + '</p>' +
          '<p style="font-size:12px;color:#8a9bb0;margin-top:8px;">Valid for 72 hours · Location: LON-WILSON</p>' +
          '</div>';
      }
      var html =
        '<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;">' +
        '<div style="background:#0d1b2e;padding:28px 32px;"><h1 style="color:white;font-size:22px;margin:0;">Photobooth App</h1></div>' +
        '<div style="padding:32px;"><h2>Your new photo is ready, ' + firstName + '!</h2>' +
        '<p style="color:#5a6275;">Your free retake has been processed and is attached.</p>' +
        printCodeSection +
        '<div style="background:#f8f9fb;padding:20px;border-radius:10px;margin:20px 0;font-size:13px;">' +
        '<p><strong>Order Ref:</strong> ' + retake.orderRef + ' (Retake)</p>' +
        '<p><strong>Photo Purpose:</strong> ' + retake.purpose + '</p>' +
        '<p><strong>Application Centre:</strong> ' + retake.centre + '</p>' +
        '</div>' +
        '<p style="color:#8a9bb0;font-size:12px;margin-top:20px;">Questions? Contact info@photoboothapp.co.uk</p>' +
        '</div></div>';
      return sendEmail(retake.email, 'Your New Passport Photo — ' + retake.orderRef, html, attachment)
      .then(function() {
        deletePhoto(photoToken);
        res.json({ success: true, printCode: newPrintCode });
      });
    });
  }).catch(function(err) { res.status(500).json({ error: err.message }); });
});

// ── Gratis order ──────────────────────────────────────────
app.post('/api/admin/issue-gratis', function(req, res) {
  var token = req.headers['x-admin-token'] || req.body.adminToken;
  if (token !== process.env.SABTECH_ADMIN_TOKEN && token !== process.env.ADMIN_TOKEN) {
    return res.status(401).json({ error: 'Unauthorised' });
  }
  var email    = sanitise(req.body.email);
  var name     = sanitise(req.body.name);
  var centre   = sanitise(req.body.centre) || 'Not specified';
  var purpose  = sanitise(req.body.purpose) || 'Not specified';
  var note     = sanitise(req.body.note) || '';
  var withPrint = req.body.withPrint === true || req.body.withPrint === 'true';
  var source   = sanitise(req.body.source) || 'sabtech';
  if (!email || !name) return res.status(400).json({ error: 'Name and email required' });
  var gratisToken = require('crypto').randomBytes(24).toString('hex');
  var gratisUrl = 'https://photoboothapp.co.uk/retake/' + gratisToken;
  new Retake({
    token: gratisToken,
    orderRef: 'GRATIS-' + Date.now().toString(36).toUpperCase(),
    email: email, name: name, centre: centre, purpose: purpose, source: source
  }).save().then(function() {
    var firstName = name.split(' ')[0];
    var serviceLabel = withPrint ? 'Digital + Print (Lon-Wilson)' : 'Digital Only';
    var html =
      '<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;">' +
      '<div style="background:#0d1b2e;padding:28px 32px;"><h1 style="color:white;font-size:22px;margin:0;">Photobooth App</h1></div>' +
      '<div style="padding:32px;">' +
      '<h2 style="color:#0d1b2e;">Your complimentary photo session, ' + firstName + '!</h2>' +
      '<p style="color:#5a6275;margin-bottom:20px;">We\'d like to offer you a <strong>complimentary passport photo</strong> — completely free of charge.</p>' +
      '<div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:10px;padding:20px;margin:20px 0;text-align:center;">' +
      '<a href="' + gratisUrl + '" style="display:inline-block;background:#0d1b2e;color:white;padding:14px 32px;border-radius:99px;text-decoration:none;font-weight:600;font-size:15px;">📸 Get My Free Photo</a>' +
      '<p style="font-size:11px;color:#8a9bb0;margin-top:12px;">Service: ' + serviceLabel + ' · Link valid for 7 days</p>' +
      '</div>' +
      (note ? '<p style="color:#5a6275;font-size:13px;font-style:italic;">Note: ' + note + '</p>' : '') +
      '<p style="color:#8a9bb0;font-size:12px;margin-top:20px;">Questions? Contact info@photoboothapp.co.uk · Photobooth App · Sabtech Limited</p>' +
      '</div></div>';
    return sendEmail(email, 'Your Complimentary Passport Photo — Photobooth App', html, null);
  }).then(function() {
    res.json({ success: true, gratisUrl: gratisUrl });
  }).catch(function(err) { res.status(500).json({ error: err.message }); });
});

// ── Kiosk endpoints ───────────────────────────────────────
app.post('/api/kiosk/verify-code', rateLimit(20, 60000), function(req, res) {
  var code = sanitise(req.body.code || '').toUpperCase().trim();
  var locationId = sanitise(req.body.locationId || '').toUpperCase().trim();
  if (!code) return res.status(400).json({ error: 'Please enter a print code.' });
  if (!code.startsWith('PBA-')) code = 'PBA-' + code;
  Order.findOne({ printCode: code }).lean().then(function(order) {
    if (!order) return res.status(404).json({ error: 'Invalid code. Please check and try again.' });
    if (order.printed) return res.status(400).json({ error: 'This code has already been used.' });
    if (order.printCodeExpiry && new Date() > new Date(order.printCodeExpiry)) {
      return res.status(400).json({ error: 'This code has expired. Please contact support.' });
    }
    if (order.printOption !== 'print') return res.status(400).json({ error: 'This order does not include printing.' });
    res.json({ success: true, orderRef: order.orderRef, name: order.name, purpose: order.purpose, centre: order.centre, expiresAt: order.printCodeExpiry });
  }).catch(function(err) { res.status(500).json({ error: err.message }); });
});

app.post('/api/kiosk/get-photo', rateLimit(20, 60000), async function(req, res) {
  var code = sanitise(req.body.code || '').toUpperCase().trim();
  if (!code.startsWith('PBA-')) code = 'PBA-' + code;
  try {
    var order = await Order.findOne({ printCode: code }).lean();
    if (!order) return res.status(404).json({ error: 'Order not found.' });
    if (order.printed) return res.status(400).json({ error: 'Already printed.' });
    if (order.printCodeExpiry && new Date() > new Date(order.printCodeExpiry)) {
      return res.status(400).json({ error: 'Code expired.' });
    }
    var photo = await getPrintPhotoAsync(code);
    if (!photo) return res.status(404).json({ error: 'Photo not available. Please contact support.' });
    var base64 = photo.buffer.toString('base64');
    res.json({ success: true, photo: 'data:image/jpeg;base64,' + base64, orderRef: order.orderRef, name: order.name, purpose: order.purpose });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/kiosk/mark-printed', rateLimit(20, 60000), function(req, res) {
  var code = sanitise(req.body.code || '').toUpperCase().trim();
  var locationId = sanitise(req.body.locationId || '').toUpperCase().trim();
  if (!code.startsWith('PBA-')) code = 'PBA-' + code;
  Order.findOneAndUpdate(
    { printCode: code, printed: false },
    { printed: true, printedAt: new Date(), printLocation: locationId },
    { new: true }
  ).then(function(order) {
    if (!order) return res.status(404).json({ error: 'Code not found or already used.' });
    deletePrintPhoto(code);
    res.json({ success: true, orderRef: order.orderRef });
  }).catch(function(err) { res.status(500).json({ error: err.message }); });
});

app.get('/api/kiosk/locations', function(req, res) {
  Location.find({ active: true }).lean().then(function(locations) {
    res.json({ locations: locations });
  }).catch(function(err) { res.status(500).json({ error: err.message }); });
});

// ── Sentry error handler (must be last) ───────────────────
Sentry.setupExpressErrorHandler(app);

app.use(function(err, req, res, next) {
  Sentry.captureException(err);
  res.status(500).json({ error: 'Something went wrong. Please try again.' });
});

var PORT = process.env.PORT || 3000;
app.listen(PORT, function() {
  console.log('Photobooth App running on port ' + PORT);
});
