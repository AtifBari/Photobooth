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
  // Print options
  printOption:     { type: String, default: 'digital' },
  printCode:       { type: String, default: null },
  printCodeExpiry: { type: Date, default: null },
  printLocation:   { type: String, default: null },
  printed:         { type: Boolean, default: false },
  printedAt:       { type: Date, default: null },
  // Free retake
  retakeIssued:    { type: Boolean, default: false },
  retakeIssuedAt:  { type: Date, default: null },
  retakeUsed:      { type: Boolean, default: false },
  retakeUsedAt:    { type: Date, default: null },
  retakeToken:     { type: String, default: null }
});
var Order = mongoose.model('Order', orderSchema);

// ── Retake Token Schema ───────────────────────────────────
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
  createdAt:  { type: Date, default: Date.now, expires: 604800 } // 7 days
});
var Retake = mongoose.model('Retake', retakeSchema);

// ── Print Photo Schema (stored in MongoDB for persistence) ─
var printPhotoSchema = new mongoose.Schema({
  printCode:   { type: String, required: true, unique: true },
  photoData:   { type: String, required: true }, // base64 jpeg
  createdAt:   { type: Date, default: Date.now, expires: 86400 } // auto-delete after 24h
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

// Seed default location
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

// Validate image dimensions using buffer
function validateImageDimensions(buffer) {
  return new Promise(function(resolve) {
    try {
      var hex = buffer.slice(0,4).toString('hex');
      var width = 0, height = 0;
      if (hex.startsWith('ffd8ff')) {
        // JPEG — scan for SOF marker
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
        // PNG — dimensions at bytes 16-24
        width  = buffer.readUInt32BE(16);
        height = buffer.readUInt32BE(20);
      }
      if (width < 100 || height < 100) return resolve({ valid: false, error: 'Image too small — minimum 100x100 pixels.' });
      if (width > 8000 || height > 8000) return resolve({ valid: false, error: 'Image too large — maximum 8000x8000 pixels.' });
      resolve({ valid: true, width: width, height: height });
    } catch(e) {
      resolve({ valid: true }); // fail open
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
    "connect-src 'self' https://api.stripe.com https://www.google.com https://cdn.jsdelivr.net https://ipapi.co wss://localhost:8181 wss://localhost:8182 ws://localhost:8181 ws://localhost:8182; " +
    "worker-src blob: 'self';"
  );
  next();
});

// ── CORS ──────────────────────────────────────────────────
app.use(cors());

// ── Structured request logging ────────────────────────────
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
      console.log('[WARN] ' + JSON.stringify({
        ts: new Date().toISOString(),
        event: 'rate_limit_exceeded',
        ip: ip,
        endpoint: req.path,
        count: rateLimitStore[key].count
      }));
      return res.status(429).json({ error: 'Too many requests. Please wait a moment and try again.' });
    }
    next();
  };
}
setInterval(function() { rateLimitStore = {}; }, 10 * 60 * 1000);

// ── Input sanitisation ────────────────────────────────────
function sanitise(str) {
  if (!str) return '';
  return String(str)
    .replace(/[<>]/g, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+=/gi, '')
    .trim()
    .substring(0, 500);
}

// ── reCAPTCHA v3 verification ─────────────────────────────
function verifyRecaptcha(token, minScore) {
  if (!token || !process.env.RECAPTCHA_SECRET_KEY) return Promise.resolve(true);
  minScore = minScore || 0.1; // Low threshold — just block obvious bots
  return axios.post('https://www.google.com/recaptcha/api/siteverify', null, {
    params: { secret: process.env.RECAPTCHA_SECRET_KEY, response: token }
  }).then(function(r) {
    var data = r.data;
    console.log('[INFO] reCAPTCHA score:', data.score, '| success:', data.success, '| action:', data.action);
    if (!data.success) {
      console.warn('[WARN] reCAPTCHA failed:', data['error-codes']);
      return true; // Fail open — don't block real users
    }
    if (data.score < minScore) {
      console.warn('[WARN] reCAPTCHA score too low:', data.score);
      return false;
    }
    return true;
  }).catch(function(err) {
    console.error('[ERROR] reCAPTCHA API error:', err.message);
    return true; // Always fail open on API errors
  });
}

app.use(express.json({ limit: '20mb' }));
app.use('/api/stripe-webhook', express.raw({ type: 'application/json' }));
app.use(express.static(process.env.STATIC_DIR || 'public'));

// ── Explicit page routes ──────────────────────────────────
var path = require('path');
var staticDir = process.env.STATIC_DIR ? process.env.STATIC_DIR : path.join(__dirname, 'public');

app.get('/', function(req, res) { res.sendFile(path.join(staticDir, 'index.html')); });
app.get('/order', function(req, res) { res.sendFile(path.join(staticDir, 'order.html')); });
app.get('/vfs', function(req, res) { res.sendFile(path.join(staticDir, 'vfs.html')); });
app.get('/kiosk', function(req, res) { res.sendFile(path.join(staticDir, 'kiosk.html')); });
app.get('/admin-sabtech', function(req, res) { res.sendFile(path.join(staticDir, 'admin-sabtech.html')); });
app.get('/admin-vfs', function(req, res) { res.sendFile(path.join(staticDir, 'admin-vfs.html')); });
app.get('/retake/:token', function(req, res) { res.sendFile(path.join(staticDir, 'retake.html')); });

// ── In-memory photo store ─────────────────────────────────
var photoStore = {};
var printPhotoStore = {}; // stores photos for print orders (24 hours)

function storePhoto(token, imgBuffer) {
  photoStore[token] = { buffer: imgBuffer, createdAt: Date.now(), used: false };
  setTimeout(function() { delete photoStore[token]; }, 30 * 60 * 1000);
}
function getPhoto(token) {
  var entry = photoStore[token];
  if (!entry) return null;
  if (entry.used) {
    console.log('[WARN] ' + JSON.stringify({ ts: new Date().toISOString(), event: 'photo_token_reuse_attempt', token: token.substring(0,8)+'...' }));
    return null;
  }
  return entry;
}
function deletePhoto(token) {
  if (photoStore[token]) {
    photoStore[token].used = true;
    photoStore[token].buffer = null;
    delete photoStore[token];
  }
}

// Print photo store — MongoDB backed for persistence across restarts
var printPhotoStore = {}; // memory cache for speed

function storePrintPhoto(printCode, imgBuffer) {
  var base64 = imgBuffer.toString('base64');
  // Save to MongoDB (survives restarts)
  PrintPhoto.findOneAndUpdate(
    { printCode: printCode },
    { printCode: printCode, photoData: base64, createdAt: new Date() },
    { upsert: true, new: true }
  ).then(function() {
    console.log('[INFO] Print photo saved to DB for code: ' + printCode);
  }).catch(function(e) { console.error('Print photo DB save error:', e.message); });
  // Also cache in memory for fast access
  printPhotoStore[printCode] = { buffer: imgBuffer, createdAt: Date.now() };
  setTimeout(function() { delete printPhotoStore[printCode]; }, 24 * 60 * 60 * 1000);
}

function getPrintPhoto(printCode) { return printPhotoStore[printCode] || null; }

async function getPrintPhotoAsync(printCode) {
  // Try memory first
  if (printPhotoStore[printCode]) return printPhotoStore[printCode];
  // Fall back to MongoDB
  try {
    var doc = await PrintPhoto.findOne({ printCode: printCode }).lean();
    if (doc) {
      console.log('[INFO] Print photo fetched from DB for code: ' + printCode);
      return { buffer: Buffer.from(doc.photoData, 'base64'), createdAt: doc.createdAt };
    }
  } catch(e) { console.error('Print photo DB fetch error:', e.message); }
  return null;
}

function deletePrintPhoto(printCode) {
  delete printPhotoStore[printCode];
  PrintPhoto.deleteOne({ printCode: printCode }).catch(function(){});
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
      { type: 'text', text: 'Analyse this photo for passport compliance. Reply ONLY valid JSON no markdown.\n{"approved":true,"issues":[],"message":"one sentence"}\nCheck: glasses_detected, no_face, multiple_faces, eyes_closed, head_tilted, hat_or_headwear, poor_lighting, face_too_small, blurry, mouth_open. Set approved false if issues found.' }
    ]}]
  }, { headers: { 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' } })
  .then(function(r) {
    var text = r.data.content.filter(function(b){return b.type==='text';}).map(function(b){return b.text;}).join('');
    try { res.json(JSON.parse(text.replace(/```json|```/g,'').trim())); }
    catch(e) { res.json({ approved: true, issues: [], message: 'Photo accepted.' }); }
  }).catch(function(err) {
    Sentry.captureException(err);
    console.error('Claude error:', err.response ? JSON.stringify(err.response.data) : err.message);
    res.json({ approved: true, issues: [], message: 'Photo accepted.' });
  });
});

// ── Remove background ─────────────────────────────────────
app.post('/api/remove-bg', rateLimit(20, 60000), upload.single('photo'), function(req, res) {
  if (!req.file) return res.status(400).json({ error: 'No photo uploaded' });
  if (!validateFileType(req.file.buffer)) return res.status(400).json({ error: 'Invalid file type.' });
  var recaptchaToken = req.body && req.body.recaptchaToken;
  validateImageDimensions(req.file.buffer).then(function(dimCheck) {
    if (!dimCheck.valid) return res.status(400).json({ error: dimCheck.error });
    verifyRecaptcha(recaptchaToken, 0.1).then(function(valid) {
    if (!valid) return res.status(400).json({ error: 'Security check failed. Please try again.' });
    var fd = new FormData();
    fd.append('image_file', req.file.buffer, { filename: 'photo.jpg', contentType: req.file.mimetype });
    fd.append('size', 'auto');
    axios.post('https://api.remove.bg/v1.0/removebg', fd, {
      headers: Object.assign({ 'X-Api-Key': process.env.REMOVE_BG_KEY }, fd.getHeaders()),
      responseType: 'arraybuffer'
    }).then(function(response) {
      res.json({ success: true, image: 'data:image/png;base64,' + Buffer.from(response.data).toString('base64') });
    }).catch(function(err) {
      Sentry.captureException(err);
      var msg = err.message;
      if (err.response && err.response.data) msg = Buffer.from(err.response.data).toString();
      res.status(500).json({ error: msg });
    });
    });
  });
});

// ── Create payment intent ─────────────────────────────────
app.post('/api/create-payment-intent', rateLimit(30, 60000), function(req, res) {
  var name  = sanitise(req.body.name);
  var email = sanitise(req.body.email);
  var amountPence = parseInt(req.body.amountPence) || parseInt(process.env.PRICE_PENCE) || 699;

  // Only allow valid amounts
  if (amountPence !== 699 && amountPence !== 999) amountPence = 699;

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
    console.error('Stripe error:', err.message);
    res.status(500).json({ error: err.message });
  });
});

// ── Store photo ───────────────────────────────────────────
app.post('/api/store-photo', rateLimit(20, 60000), function(req, res) {
  var passportImage = req.body.passportImage;
  if (!passportImage) return res.status(400).json({ error: 'No image' });
  var token = crypto.randomBytes(32).toString('hex');
  var imgBuffer = Buffer.from(passportImage.replace(/^data:image\/\w+;base64,/, ''), 'base64');
  // Server-side file size check
  if (imgBuffer.length > 10 * 1024 * 1024) return res.status(400).json({ error: 'Image too large' });
  storePhoto(token, imgBuffer);
  res.json({ token: token });
});

// ── Confirm order ─────────────────────────────────────────
app.post('/api/confirm-order', rateLimit(10, 60000), function(req, res) {
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
  var currencySymbol   = currency === 'EUR' ? '€' : currency === 'USD' ? '$' : '£';
  if (!PRICES[currency]) currency = 'GBP';
  var priceData        = PRICES[currency];
  var orderAmount      = printOption === 'print' ? priceData.print / 100 : priceData.digital / 100;

  if (!name||!email||!phone||!centre||!purpose||!photoToken||!paymentIntentId)
    return res.status(400).json({ error: 'Missing required fields' });

  // Validate email format
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: 'Invalid email address' });

  // Verify payment with Stripe
  stripe.paymentIntents.retrieve(paymentIntentId, function(err, intent) {
    if (err || !intent || intent.status !== 'succeeded') {
      var ip2 = (req.headers['x-forwarded-for'] || req.ip || 'unknown').split(',')[0].trim();
      console.log('[WARN] ' + JSON.stringify({ ts: new Date().toISOString(), event: 'payment_verification_failed', ip: ip2, paymentIntentId: paymentIntentId, status: intent ? intent.status : 'error' }));
      Sentry.captureMessage('Payment verification failed: ' + paymentIntentId);
      return res.status(402).json({ error: 'Payment not verified. Please contact support.' });
    }
    if (intent.amount !== 699 && intent.amount !== 999) {
      return res.status(402).json({ error: 'Payment amount mismatch.' });
    }

    var photoData = getPhoto(photoToken);
    if (!photoData) return res.status(400).json({ error: 'Photo expired. Please start again.' });
    var imgBuffer = photoData.buffer;
    var firstName = name.split(' ')[0];
    var cleanPurpose = purpose.replace(/\s*[—–-]\s*[\d×xX\/\s\(\)inchmm\.]+$/i, '').trim();

    // Save to MongoDB
    // Generate print code if print option selected
    var printCode = null;
    var printCodeExpiry = null;
    if (printOption === 'print') {
      printCode = generatePrintCode();
      printCodeExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
    }

    // Save to MongoDB
    new Order({
      orderRef: orderRef, date: new Date(),
      name: name, email: email, phone: phone,
      centre: centre, purpose: purpose, govRef: govRef || '',
      amount: orderAmount,
      currency: currency, status: 'completed',
      source: source,
      paymentIntentId: paymentIntentId, emailSent: false,
      printOption: printOption,
      printCode: printCode,
      printCodeExpiry: printCodeExpiry,
      printLocation: printLocation
    }).save().catch(function(e) {
      Sentry.captureException(e);
      console.error('DB save error:', e.message);
    });

    var printCodeSection = '';
    if (printOption === 'print' && printCode) {
      printCodeSection =
        '<div style="background:#0d1b2e;color:white;padding:20px;border-radius:10px;margin:20px 0;text-align:center;">' +
        '<p style="font-size:13px;color:#8a9bb0;margin-bottom:8px;letter-spacing:1px;text-transform:uppercase;">Your Print Code</p>' +
        '<p style="font-size:36px;font-weight:bold;letter-spacing:6px;color:#F5D06A;margin:0;">' + printCode + '</p>' +
        '<p style="font-size:12px;color:#8a9bb0;margin-top:8px;">Valid for 24 hours · Location: ' + (printLocation || 'LON-WILSON') + '</p>' +
        '<p style="font-size:12px;color:#8a9bb0;margin-top:4px;">Enter this code at the photo kiosk to print your photos</p>' +
        '</div>';
    }

    var amountPaid = printOption === 'print' ? '£9.99' : '£6.99';

    var customerHtml =
      '<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;">' +
      '<div style="background:#0d1b2e;padding:28px 32px;"><h1 style="color:white;font-size:22px;margin:0;">Photobooth App</h1>' +
      '<p style="color:#8a9bb0;font-size:12px;margin:4px 0 0;">by Sabtech Limited</p></div>' +
      '<div style="padding:32px;"><h2>Your photo is ready, '+firstName+'!</h2>' +
      '<p style="color:#5a6275;">Thank you for your order. Your passport photo is attached.</p>' +
      printCodeSection +
      '<div style="background:#f8f9fb;padding:20px;border-radius:10px;margin:20px 0;font-size:13px;">' +
      '<p><strong>Order Ref:</strong> '+orderRef+'</p>' +
      '<p><strong>Photo Purpose:</strong> '+cleanPurpose+'</p>' +
      '<p><strong>Application Centre:</strong> '+centre+'</p>' +
      (govRef?'<p><strong>Your Reference:</strong> '+govRef+'</p>':'') +
      '<p><strong>Total Paid:</strong> '+amountPaid+'</p>' +
      '<p><strong>Service:</strong> '+(printOption === 'print' ? 'Digital + Print' : 'Digital Only')+'</p></div>' +
      '<p style="background:#f0fdf4;color:#166534;padding:14px;border-radius:8px;">Your photo is attached — formatted to the correct size for your application. Photos are automatically deleted from our servers immediately after this email is sent.</p>' +
      '<div style="margin-top:24px;padding:14px;background:#f8f9fb;border-radius:8px;font-size:12px;color:#8a9bb0;">' +
      '<p><strong>Data & Privacy:</strong> Your photo and personal data are processed under UK GDPR. Photos are deleted automatically after delivery.</p>' +
      '<p style="margin-top:8px;"><strong>Refund Policy:</strong> If your photo is rejected by the application centre, contact us within 7 days for a replacement or full refund.</p>' +
      '</div>' +
      '<p style="color:#8a9bb0;font-size:12px;margin-top:20px;">Questions? Contact us at info@photoboothapp.co.uk · Photobooth App · Sabtech Limited</p>' +
      '</div></div>';

    var adminHtml =
      '<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;">' +
      '<div style="background:#0d1b2e;padding:20px 24px;"><h2 style="color:white;margin:0;">New Order — '+orderRef+'</h2></div>' +
      '<div style="padding:24px;background:#f8f9fb;font-size:14px;">' +
      '<p><strong>Customer:</strong> '+name+'</p><p><strong>Email:</strong> '+email+'</p>' +
      '<p><strong>Phone:</strong> '+phone+'</p><p><strong>Purpose:</strong> '+cleanPurpose+'</p>' +
      '<p><strong>Centre:</strong> '+centre+'</p>' +
      (govRef?'<p><strong>Gov Ref:</strong> '+govRef+'</p>':'') +
      '<p><strong>Stripe PI:</strong> '+paymentIntentId+'</p>' +
      '<p style="font-size:16px;font-weight:bold;margin-top:12px;">Amount: £6.99 ✓ VERIFIED</p>' +
      '</div></div>';

    var attachment = [{ filename: 'passport_photo_'+orderRef+'.jpg', content: imgBuffer }];

    sendEmail(email, 'Your Passport Photo - Order '+orderRef, customerHtml, attachment)
    .then(function() {
      return sendEmail(process.env.ADMIN_EMAIL, 'New Order '+orderRef+' - '+name, adminHtml, attachment);
    }).then(function() {
      // Store photo for print orders BEFORE deleting
      if (printOption === 'print' && printCode) {
        storePrintPhoto(printCode, imgBuffer);
      }
      deletePhoto(photoToken);
      Order.findOneAndUpdate({ orderRef: orderRef }, { emailSent: true }).catch(function(){});
      res.json({ success: true, orderRef: orderRef, printCode: printCode });
    }).catch(function(err) {
      Sentry.captureException(err);
      console.error('Email error:', err.response ? JSON.stringify(err.response.data) : err.message);
      Order.findOneAndUpdate({ orderRef: orderRef }, { emailSent: false, emailError: err.message }).catch(function(){});
      res.status(500).json({ error: 'Payment received but email failed. Order ref: '+orderRef+'. Contact support at info@photoboothapp.co.uk' });
    });
  });
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
  console.log('[INFO] ' + JSON.stringify({ ts: new Date().toISOString(), event: 'admin_login_success', portal: portal, ip: ip }));
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
    var headers = ['Order Ref','Date','Time','Customer Name','Email','Phone','Application Centre','Photo Purpose','Gov Reference','Amount (GBP)','Status','Email Sent','Payment ID'];
    var rows = orders.map(function(o) {
      var d = o.date ? new Date(o.date) : new Date();
      return [o.orderRef, d.toLocaleDateString('en-GB'), d.toLocaleTimeString('en-GB'),
        o.name, o.email, o.phone, o.centre, o.purpose, o.govRef||'',
        o.amount||6.99, o.status, o.emailSent?'Yes':'No', o.paymentIntentId||''
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
    var html = '<div style="font-family:Arial,sans-serif;padding:24px;"><h2>Your Passport Photo — Order '+order.orderRef+'</h2>' +
      '<p>This is a resent confirmation. Contact info@photoboothapp.co.uk for assistance.</p>' +
      '<p><strong>Purpose:</strong> '+order.purpose+'</p><p><strong>Centre:</strong> '+order.centre+'</p></div>';
    sendEmail(order.email, '[Resent] Passport Photo Order '+order.orderRef, html, [])
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

// ── Print code generator ──────────────────────────────────
function generatePrintCode() {
  var digits = Math.floor(100000 + Math.random() * 900000).toString();
  return 'PBA-' + digits;
}

app.get('/api/health', function(req, res) {
  res.json({ status: 'ok', db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' });
});

// ── Free Retake Endpoints ─────────────────────────────────

// Admin issues free retake
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
    var retakeUrl = 'https://photobooth-v2.onrender.com/retake/' + retakeToken;

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
        '<p style="color:#5a6275;margin-bottom:20px;">We\'re sorry your photo was rejected. We\'ve issued you a <strong>free retake</strong> — no payment needed.</p>' +
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
      console.log('[INFO] Free retake issued for order: ' + orderRef);
      res.json({ success: true, retakeToken: retakeToken, retakeUrl: retakeUrl });
    });
  }).catch(function(err) { res.status(500).json({ error: err.message }); });
});

// Validate retake token
app.get('/api/retake/:token', function(req, res) {
  var token = sanitise(req.params.token);
  Retake.findOne({ token: token, used: false }).lean().then(function(retake) {
    if (!retake) return res.status(404).json({ error: 'Invalid or expired retake link.' });
    res.json({ success: true, name: retake.name, email: retake.email, centre: retake.centre, purpose: retake.purpose, source: retake.source, orderRef: retake.orderRef });
  }).catch(function(err) { res.status(500).json({ error: err.message }); });
});

// Confirm retake order (no payment)
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

    // Check if original order had print option
    return Order.findOne({ orderRef: retake.orderRef }).lean().then(function(originalOrder) {
      var isPrint = originalOrder && originalOrder.printOption === 'print';
      var newPrintCode = null;
      var newPrintCodeExpiry = null;

      if (isPrint) {
        newPrintCode = generatePrintCode();
        newPrintCodeExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);
        // Store photo for kiosk printing
        storePrintPhoto(newPrintCode, imgBuffer);
      }

      retake.used = true; retake.usedAt = new Date(); retake.save().catch(function(){});
      Order.findOneAndUpdate({ orderRef: retake.orderRef }, { retakeUsed: true, retakeUsedAt: new Date() }).catch(function(){});

      var firstName = retake.name ? retake.name.split(' ')[0] : 'there';

      // Build print code section if needed
      var printCodeSection = '';
      if (isPrint && newPrintCode) {
        printCodeSection =
          '<div style="background:#0d1b2e;color:white;padding:20px;border-radius:10px;margin:20px 0;text-align:center;">' +
          '<p style="font-size:13px;color:#8a9bb0;margin-bottom:8px;letter-spacing:1px;text-transform:uppercase;">Your New Print Code</p>' +
          '<p style="font-size:36px;font-weight:bold;letter-spacing:6px;color:#F5D06A;margin:0;">' + newPrintCode + '</p>' +
          '<p style="font-size:12px;color:#8a9bb0;margin-top:8px;">Valid for 24 hours · Location: LON-WILSON</p>' +
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

// ── Gratis (Complimentary) Order ─────────────────────────
// Admin issues a completely free order for special cases
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
  var gratisUrl = 'https://photobooth-v2.onrender.com/retake/' + gratisToken;

  // Create a retake token for gratis order (same flow, different label)
  new Retake({
    token: gratisToken,
    orderRef: 'GRATIS-' + Date.now().toString(36).toUpperCase(),
    email: email, name: name,
    centre: centre, purpose: purpose, source: source
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
      '<p style="font-size:13px;color:#166534;margin-bottom:16px;">Click below to take your passport photo — no payment needed:</p>' +
      '<a href="' + gratisUrl + '" style="display:inline-block;background:#0d1b2e;color:white;padding:14px 32px;border-radius:99px;text-decoration:none;font-weight:600;font-size:15px;">📸 Get My Free Photo</a>' +
      '<p style="font-size:11px;color:#8a9bb0;margin-top:12px;">Service: ' + serviceLabel + ' · Link valid for 7 days</p>' +
      '</div>' +
      (note ? '<p style="color:#5a6275;font-size:13px;font-style:italic;">Note: ' + note + '</p>' : '') +
      '<p style="color:#8a9bb0;font-size:12px;margin-top:20px;">Questions? Contact info@photoboothapp.co.uk · Photobooth App · Sabtech Limited</p>' +
      '</div></div>';

    return sendEmail(email, 'Your Complimentary Passport Photo — Photobooth App', html, null);
  }).then(function() {
    console.log('[INFO] Gratis order issued for: ' + email);
    res.json({ success: true, gratisUrl: gratisUrl });
  }).catch(function(err) { res.status(500).json({ error: err.message }); });
});

// ── Kiosk endpoints ───────────────────────────────────────
// Verify print code and return photo data
app.post('/api/kiosk/verify-code', rateLimit(20, 60000), function(req, res) {
  var code = sanitise(req.body.code || '').toUpperCase().trim();
  var locationId = sanitise(req.body.locationId || '').toUpperCase().trim();

  if (!code) return res.status(400).json({ error: 'Please enter a print code.' });

  // Normalise code format
  if (!code.startsWith('PBA-')) code = 'PBA-' + code;

  Order.findOne({ printCode: code }).lean().then(function(order) {
    if (!order) return res.status(404).json({ error: 'Invalid code. Please check and try again.' });
    if (order.printed) return res.status(400).json({ error: 'This code has already been used.' });
    if (order.printCodeExpiry && new Date() > new Date(order.printCodeExpiry)) {
      return res.status(400).json({ error: 'This code has expired. Please contact support.' });
    }
    if (order.printOption !== 'print') return res.status(400).json({ error: 'This order does not include printing.' });

    console.log('[INFO] ' + JSON.stringify({ ts: new Date().toISOString(), event: 'kiosk_code_verified', code: code, location: locationId, orderRef: order.orderRef }));

    res.json({
      success: true,
      orderRef: order.orderRef,
      name: order.name,
      purpose: order.purpose,
      centre: order.centre,
      expiresAt: order.printCodeExpiry
    });
  }).catch(function(err) { res.status(500).json({ error: err.message }); });
});

// Get print photo for kiosk
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
    res.json({
      success: true,
      photo: 'data:image/jpeg;base64,' + base64,
      orderRef: order.orderRef,
      name: order.name,
      purpose: order.purpose
    });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// Mark order as printed
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
    deletePrintPhoto(code); // delete from memory after printing
    console.log('[INFO] ' + JSON.stringify({ ts: new Date().toISOString(), event: 'photo_printed', code: code, location: locationId, orderRef: order.orderRef }));
    res.json({ success: true, orderRef: order.orderRef });
  }).catch(function(err) { res.status(500).json({ error: err.message }); });
});

// Get kiosk locations
app.get('/api/kiosk/locations', function(req, res) {
  Location.find({ active: true }).lean().then(function(locations) {
    res.json({ locations: locations });
  }).catch(function(err) { res.status(500).json({ error: err.message }); });
});

// ── Sentry error handler (must be last) ───────────────────
Sentry.setupExpressErrorHandler(app);

app.use(function(err, req, res, next) {
  var ip = (req.headers['x-forwarded-for'] || req.ip || 'unknown').split(',')[0].trim();
  console.log('[ERROR] ' + JSON.stringify({
    ts:       new Date().toISOString(),
    method:   req.method,
    endpoint: req.path,
    ip:       ip,
    error:    err.message,
    stack:    err.stack ? err.stack.split('\n')[1].trim() : ''
  }));
  Sentry.captureException(err);
  res.status(500).json({ error: 'Something went wrong. Please try again.' });
});

var PORT = process.env.PORT || 3000;
app.listen(PORT, function() {
  console.log('Photobooth App running on port ' + PORT);
});
