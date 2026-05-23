require('dotenv').config();

// ── Sentry (must be first) ────────────────────────────────-
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
  emailSent:       { type: Boolean, default: false },
  emailError:      String,
  resentAt:        Date
});
var Order = mongoose.model('Order', orderSchema);

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
    "script-src 'self' 'unsafe-inline' https://js.stripe.com https://www.google.com https://www.gstatic.com; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "img-src 'self' data: blob:; " +
    "frame-src https://js.stripe.com https://www.google.com; " +
    "connect-src 'self' https://api.stripe.com https://www.google.com;"
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
  if (!token || !process.env.RECAPTCHA_SECRET_KEY) return Promise.resolve(true); // skip if not configured
  minScore = minScore || 0.5;
  return axios.post('https://www.google.com/recaptcha/api/siteverify', null, {
    params: { secret: process.env.RECAPTCHA_SECRET_KEY, response: token }
  }).then(function(r) {
    var data = r.data;
    console.log('reCAPTCHA score:', data.score, '| success:', data.success, '| action:', data.action);
    if (!data.success) { console.warn('reCAPTCHA failed:', data['error-codes']); return false; }
    if (data.score < minScore) { console.warn('reCAPTCHA score too low:', data.score); return false; }
    return true;
  }).catch(function(err) {
    console.error('reCAPTCHA error:', err.message);
    return true; // fail open — never block real users due to API error
  });
}

app.use(express.json({ limit: '20mb' }));
app.use('/api/stripe-webhook', express.raw({ type: 'application/json' }));
app.use(express.static('public'));

// ── In-memory photo store ─────────────────────────────────
var photoStore = {};
function storePhoto(token, imgBuffer) {
  photoStore[token] = { buffer: imgBuffer, createdAt: Date.now(), used: false };
  setTimeout(function() { delete photoStore[token]; }, 30 * 60 * 1000);
}
function getPhoto(token) {
  var entry = photoStore[token];
  if (!entry) return null;
  if (entry.used) {
    console.log('[WARN] ' + JSON.stringify({ ts: new Date().toISOString(), event: 'photo_token_reuse_attempt', token: token.substring(0,8)+'...' }));
    return null; // token already used — reject
  }
  return entry;
}
function deletePhoto(token) {
  if (photoStore[token]) {
    photoStore[token].used = true; // mark as used immediately
    photoStore[token].buffer = null; // clear buffer from memory immediately
    delete photoStore[token];
  }
}
setInterval(function() {
  var now = Date.now();
  Object.keys(photoStore).forEach(function(k) {
    if (now - photoStore[k].createdAt > 30 * 60 * 1000) delete photoStore[k];
  });
}, 15 * 60 * 1000);

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
  if (!token || token !== process.env.ADMIN_TOKEN) return res.status(401).json({ error: 'Unauthorised' });
  next();
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
    verifyRecaptcha(recaptchaToken, 0.3).then(function(valid) {
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

  if (!name || !email || !email.includes('@')) return res.status(400).json({ error: 'Invalid details' });

  stripe.paymentIntents.create({
    amount: parseInt(process.env.PRICE_PENCE) || 699,
    currency: 'gbp',
    metadata: { customer_name: name, customer_email: email },
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
    if (intent.amount !== (parseInt(process.env.PRICE_PENCE) || 699))
      return res.status(402).json({ error: 'Payment amount mismatch.' });

    var photoData = getPhoto(photoToken);
    if (!photoData) return res.status(400).json({ error: 'Photo expired. Please start again.' });
    var imgBuffer = photoData.buffer;
    var firstName = name.split(' ')[0];
    var cleanPurpose = purpose.replace(/\s*[—–-]\s*[\d×xX\/\s\(\)inchmm\.]+$/i, '').trim();

    // Save to MongoDB
    new Order({
      orderRef: orderRef, date: new Date(),
      name: name, email: email, phone: phone,
      centre: centre, purpose: purpose, govRef: govRef || '',
      amount: 6.99, currency: 'GBP', status: 'completed',
      paymentIntentId: paymentIntentId, emailSent: false
    }).save().catch(function(e) {
      Sentry.captureException(e);
      console.error('DB save error:', e.message);
    });

    var customerHtml =
      '<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;">' +
      '<div style="background:#0d1b2e;padding:28px 32px;"><h1 style="color:white;font-size:22px;margin:0;">Photobooth App</h1>' +
      '<p style="color:#8a9bb0;font-size:12px;margin:4px 0 0;">by Sabtech Limited</p></div>' +
      '<div style="padding:32px;"><h2>Your photo is ready, '+firstName+'!</h2>' +
      '<p style="color:#5a6275;">Thank you for your order. Your passport photo is attached.</p>' +
      '<div style="background:#f8f9fb;padding:20px;border-radius:10px;margin:20px 0;font-size:13px;">' +
      '<p><strong>Order Ref:</strong> '+orderRef+'</p>' +
      '<p><strong>Photo Purpose:</strong> '+cleanPurpose+'</p>' +
      '<p><strong>Application Centre:</strong> '+centre+'</p>' +
      (govRef?'<p><strong>Your Reference:</strong> '+govRef+'</p>':'') +
      '<p><strong>Total Paid:</strong> £6.99</p></div>' +
      '<p style="background:#f0fdf4;color:#166534;padding:14px;border-radius:8px;">Your photo is attached — formatted to the correct size for your application. Photos are automatically deleted from our servers immediately after this email is sent.</p>' +
      '<div style="margin-top:24px;padding:14px;background:#f8f9fb;border-radius:8px;font-size:12px;color:#8a9bb0;">' +
      '<p><strong>Data & Privacy:</strong> Your photo and personal data are processed under UK GDPR. Photos are deleted automatically after delivery. For data requests or deletion, email info@photoboothapp.co.uk.</p>' +
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
      deletePhoto(photoToken);
      Order.findOneAndUpdate({ orderRef: orderRef }, { emailSent: true }).catch(function(){});
      res.json({ success: true, orderRef: orderRef });
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
  if (!req.body.password || req.body.password !== process.env.ADMIN_PASSWORD) {
    console.log('[WARN] ' + JSON.stringify({ ts: new Date().toISOString(), event: 'admin_login_failed', ip: ip }));
    return res.status(401).json({ error: 'Invalid password' });
  }
  console.log('[INFO] ' + JSON.stringify({ ts: new Date().toISOString(), event: 'admin_login_success', ip: ip }));
  res.json({ success: true, token: process.env.ADMIN_TOKEN });
});

app.get('/api/admin/orders', adminAuth, function(req, res) {
  var search   = sanitise(req.query.search||'').toLowerCase();
  var status   = sanitise(req.query.status||'');
  var dateFrom = req.query.dateFrom||'';
  var dateTo   = req.query.dateTo||'';
  var query = {};
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

app.get('/api/health', function(req, res) {
  res.json({ status: 'ok', db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' });
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
