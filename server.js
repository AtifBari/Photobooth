require('dotenv').config();
var express    = require('express');
var multer     = require('multer');
var nodemailer = require('nodemailer');
var Stripe     = require('stripe');
var axios      = require('axios');
var FormData   = require('form-data');
var cors       = require('cors');
var fs         = require('fs');
var path       = require('path');

var app    = express();
var stripe = Stripe(process.env.STRIPE_SECRET_KEY);
var upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));

// ── Simple file-based database ───────────────────────────
var DB_FILE = path.join(__dirname, 'orders.json');

function readOrders() {
  try {
    if (fs.existsSync(DB_FILE)) {
      return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    }
  } catch(e) {}
  return [];
}

function saveOrder(order) {
  var orders = readOrders();
  orders.unshift(order);
  fs.writeFileSync(DB_FILE, JSON.stringify(orders, null, 2));
}

function updateOrder(orderRef, updates) {
  var orders = readOrders();
  var idx = orders.findIndex(function(o) { return o.orderRef === orderRef; });
  if (idx !== -1) {
    orders[idx] = Object.assign(orders[idx], updates);
    fs.writeFileSync(DB_FILE, JSON.stringify(orders, null, 2));
  }
}

// ── Email transporter ────────────────────────────────────
var transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// ── Admin auth middleware ─────────────────────────────────
function adminAuth(req, res, next) {
  var token = req.headers['x-admin-token'] || req.query.token;
  if (token !== process.env.ADMIN_TOKEN) {
    return res.status(401).json({ error: 'Unauthorised' });
  }
  next();
}

// ── Claude AI photo validation ───────────────────────────
app.post('/api/validate-photo', upload.single('photo'), function(req, res) {
  if (!req.file) return res.status(400).json({ error: 'No photo uploaded' });
  var base64Image = req.file.buffer.toString('base64');
  var mimeType    = req.file.mimetype;
  axios.post('https://api.anthropic.com/v1/messages', {
    model: 'claude-opus-4-6',
    max_tokens: 400,
    messages: [{
      role: 'user',
      content: [
        { type: 'image', source: { type: 'base64', media_type: mimeType, data: base64Image } },
        { type: 'text', text: 'Analyse this photo for passport photo compliance. Reply ONLY with valid JSON, no markdown.\n\n{"approved":true or false,"issues":[],"message":"one friendly sentence"}\n\nCheck for: glasses_detected, no_face, multiple_faces, eyes_closed, head_tilted, hat_or_headwear, poor_lighting, face_too_small, blurry, mouth_open\n\nIf any issues found set approved to false.' }
      ]
    }]
  }, {
    headers: { 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01', 'content-type': 'application/json' }
  }).then(function(response) {
    var text = response.data.content.filter(function(b) { return b.type === 'text'; }).map(function(b) { return b.text; }).join('');
    try {
      res.json(JSON.parse(text.replace(/```json|```/g, '').trim()));
    } catch(e) {
      res.json({ approved: true, issues: [], message: 'Photo looks good!' });
    }
  }).catch(function(err) {
    console.error('Claude error:', err.message);
    res.json({ approved: true, issues: [], message: 'Photo accepted.' });
  });
});

// ── remove.bg ────────────────────────────────────────────
app.post('/api/remove-bg', upload.single('photo'), function(req, res) {
  if (!req.file) return res.status(400).json({ error: 'No photo uploaded' });
  var fd = new FormData();
  fd.append('image_file', req.file.buffer, { filename: req.file.originalname, contentType: req.file.mimetype });
  fd.append('size', 'auto');
  axios.post('https://api.remove.bg/v1.0/removebg', fd, {
    headers: Object.assign({ 'X-Api-Key': process.env.REMOVE_BG_KEY }, fd.getHeaders()),
    responseType: 'arraybuffer'
  }).then(function(response) {
    var base64 = Buffer.from(response.data).toString('base64');
    res.json({ success: true, image: 'data:image/png;base64,' + base64 });
  }).catch(function(err) {
    var msg = err.message;
    if (err.response && err.response.data) msg = Buffer.from(err.response.data).toString();
    res.status(500).json({ error: msg });
  });
});

// ── Create payment intent ────────────────────────────────
app.post('/api/create-payment-intent', function(req, res) {
  var name = req.body.name; var email = req.body.email;
  stripe.paymentIntents.create({
    amount: parseInt(process.env.PRICE_PENCE),
    currency: 'gbp',
    metadata: { customer_name: name, customer_email: email },
    receipt_email: email
  }).then(function(intent) {
    res.json({ clientSecret: intent.client_secret });
  }).catch(function(err) {
    res.status(500).json({ error: err.message });
  });
});

// ── Confirm order + save to DB + send emails ─────────────
app.post('/api/confirm-order', function(req, res) {
  var name=req.body.name, email=req.body.email, phone=req.body.phone;
  var centre=req.body.centre, purpose=req.body.purpose, govRef=req.body.govRef;
  var passportImage=req.body.passportImage, orderRef=req.body.orderRef;
  var country=req.body.country || '';

  if (!passportImage) return res.status(400).json({ error: 'No image provided' });

  var base64Data = passportImage.replace(/^data:image\/\w+;base64,/, '');
  var imgBuffer  = Buffer.from(base64Data, 'base64');
  var firstName  = name.split(' ')[0];

  // Save to database
  saveOrder({
    orderRef:  orderRef,
    date:      new Date().toISOString(),
    name:      name,
    email:     email,
    phone:     phone,
    country:   country,
    centre:    centre,
    purpose:   purpose,
    govRef:    govRef || '',
    amount:    6.99,
    currency:  'GBP',
    status:    'completed',
    emailSent: false
  });

  var customerHtml =
    '<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;">' +
    '<div style="background:#0d1b2e;padding:28px 32px;"><h1 style="color:white;font-size:22px;margin:0;">Photobooth App</h1>' +
    '<p style="color:#8a9bb0;font-size:12px;margin:4px 0 0;">Professional Photo Service</p></div>' +
    '<div style="padding:32px;"><h2>Your photo is ready, '+firstName+'!</h2>' +
    '<p style="color:#5a6275;">Thank you for your order. Your passport photo is attached.</p>' +
    '<div style="background:#f8f9fb;padding:20px;border-radius:10px;margin:20px 0;font-size:13px;">' +
    '<p><strong>Order Ref:</strong> '+orderRef+'</p>' +
    '<p><strong>Photo Purpose:</strong> '+purpose+'</p>' +
    '<p><strong>Application Centre:</strong> '+centre+'</p>' +
    (govRef ? '<p><strong>Your Reference:</strong> '+govRef+'</p>' : '') +
    '<p><strong>Total Paid:</strong> £6.99</p></div>' +
    '<p style="background:#f0fdf4;color:#166534;padding:14px;border-radius:8px;">Your photo is attached — formatted to passport standard with a white background.</p>' +
    '<p style="color:#8a9bb0;font-size:12px;margin-top:20px;">Questions? Contact us at info@sabtech.co.uk</p>' +
    '</div></div>';

  var adminHtml =
    '<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;">' +
    '<div style="background:#0d1b2e;padding:20px 24px;"><h2 style="color:white;margin:0;">New Order — '+orderRef+'</h2></div>' +
    '<div style="padding:24px;background:#f8f9fb;font-size:14px;">' +
    '<p><strong>Customer:</strong> '+name+'</p><p><strong>Email:</strong> '+email+'</p>' +
    '<p><strong>Phone:</strong> '+phone+'</p><p><strong>Purpose:</strong> '+purpose+'</p>' +
    '<p><strong>Centre:</strong> '+centre+'</p>' +
    (govRef ? '<p><strong>Gov Ref:</strong> '+govRef+'</p>' : '') +
    '<p style="font-size:16px;font-weight:bold;border-top:1px solid #ddd;padding-top:12px;margin-top:12px;">Amount: £6.99</p>' +
    '</div></div>';

  var attachment = { filename: 'passport_photo_'+orderRef+'.jpg', content: imgBuffer, contentType: 'image/jpeg' };

  transporter.sendMail({
    from: '"'+process.env.BUSINESS_NAME+'" <'+process.env.BUSINESS_EMAIL+'>',
    to: email, subject: 'Your Passport Photo - Order '+orderRef,
    html: customerHtml, attachments: [attachment]
  }).then(function() {
    return transporter.sendMail({
      from: '"'+process.env.BUSINESS_NAME+'" <'+process.env.BUSINESS_EMAIL+'>',
      to: process.env.ADMIN_EMAIL, subject: 'New Order '+orderRef+' - '+name,
      html: adminHtml, attachments: [attachment]
    });
  }).then(function() {
    updateOrder(orderRef, { emailSent: true });
    res.json({ success: true, orderRef: orderRef });
  }).catch(function(err) {
    console.error('Email error:', err.message);
    updateOrder(orderRef, { emailSent: false, emailError: err.message });
    res.status(500).json({ error: err.message });
  });
});

// ════════════════════════════════════════════════════════
// ── ADMIN API ────────────────────────────────────────────
// ════════════════════════════════════════════════════════

// Login
app.post('/api/admin/login', function(req, res) {
  var password = req.body.password;
  if (password === process.env.ADMIN_PASSWORD) {
    res.json({ success: true, token: process.env.ADMIN_TOKEN });
  } else {
    res.status(401).json({ error: 'Invalid password' });
  }
});

// Get all orders with filters
app.get('/api/admin/orders', adminAuth, function(req, res) {
  var orders = readOrders();
  var search   = (req.query.search || '').toLowerCase();
  var status   = req.query.status || '';
  var dateFrom = req.query.dateFrom || '';
  var dateTo   = req.query.dateTo || '';
  var country  = req.query.country || '';

  if (search) {
    orders = orders.filter(function(o) {
      return (o.name||'').toLowerCase().includes(search) ||
             (o.email||'').toLowerCase().includes(search) ||
             (o.orderRef||'').toLowerCase().includes(search) ||
             (o.govRef||'').toLowerCase().includes(search);
    });
  }
  if (status)   orders = orders.filter(function(o) { return o.status === status; });
  if (country)  orders = orders.filter(function(o) { return (o.country||'').toLowerCase().includes(country.toLowerCase()); });
  if (dateFrom) orders = orders.filter(function(o) { return new Date(o.date) >= new Date(dateFrom); });
  if (dateTo)   orders = orders.filter(function(o) { return new Date(o.date) <= new Date(dateTo + 'T23:59:59'); });

  // Stats
  var allOrders = readOrders();
  var today = new Date().toISOString().split('T')[0];
  var todayOrders = allOrders.filter(function(o) { return o.date && o.date.startsWith(today); });
  var thisMonth = new Date().toISOString().slice(0, 7);
  var monthOrders = allOrders.filter(function(o) { return o.date && o.date.startsWith(thisMonth); });

  res.json({
    orders: orders,
    stats: {
      total:        allOrders.length,
      totalRevenue: allOrders.reduce(function(s,o){ return s + (o.amount||0); }, 0),
      todayCount:   todayOrders.length,
      todayRevenue: todayOrders.reduce(function(s,o){ return s + (o.amount||0); }, 0),
      monthCount:   monthOrders.length,
      monthRevenue: monthOrders.reduce(function(s,o){ return s + (o.amount||0); }, 0),
    }
  });
});

// Export CSV
app.get('/api/admin/export', adminAuth, function(req, res) {
  var orders = readOrders();
  var dateFrom = req.query.dateFrom || '';
  var dateTo   = req.query.dateTo || '';
  if (dateFrom) orders = orders.filter(function(o) { return new Date(o.date) >= new Date(dateFrom); });
  if (dateTo)   orders = orders.filter(function(o) { return new Date(o.date) <= new Date(dateTo + 'T23:59:59'); });

  var headers = ['Order Ref','Date','Time','Customer Name','Email','Phone','Country','Application Centre','Photo Purpose','Gov Reference','Amount (GBP)','Currency','Status','Email Sent'];
  var rows = orders.map(function(o) {
    var d = o.date ? new Date(o.date) : new Date();
    return [
      o.orderRef, d.toLocaleDateString('en-GB'), d.toLocaleTimeString('en-GB'),
      o.name, o.email, o.phone, o.country, o.centre, o.purpose,
      o.govRef||'', o.amount||6.99, o.currency||'GBP',
      o.status, o.emailSent ? 'Yes' : 'No'
    ].map(function(v) { return '"'+(v||'').toString().replace(/"/g,'""')+'"'; }).join(',');
  });

  var csv = [headers.join(',')].concat(rows).join('\n');
  var filename = 'photobooth_orders_' + new Date().toISOString().split('T')[0] + '.csv';
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="'+filename+'"');
  res.send(csv);
});

// Resend email
app.post('/api/admin/resend-email', adminAuth, function(req, res) {
  var orderRef = req.body.orderRef;
  var orders = readOrders();
  var order = orders.find(function(o) { return o.orderRef === orderRef; });
  if (!order) return res.status(404).json({ error: 'Order not found' });

  var html = '<div style="font-family:Arial,sans-serif;padding:24px;">' +
    '<h2>Your Passport Photo — Order '+orderRef+'</h2>' +
    '<p>This is a resent copy of your passport photo order confirmation.</p>' +
    '<p><strong>Purpose:</strong> '+order.purpose+'</p>' +
    '<p><strong>Centre:</strong> '+order.centre+'</p>' +
    '<p>Please contact us at info@sabtech.co.uk if you need assistance.</p></div>';

  transporter.sendMail({
    from: '"'+process.env.BUSINESS_NAME+'" <'+process.env.BUSINESS_EMAIL+'>',
    to: order.email,
    subject: '[Resent] Your Passport Photo - Order '+orderRef,
    html: html
  }).then(function() {
    updateOrder(orderRef, { emailSent: true, resentAt: new Date().toISOString() });
    res.json({ success: true });
  }).catch(function(err) {
    res.status(500).json({ error: err.message });
  });
});

// Delete order
app.delete('/api/admin/orders/:ref', adminAuth, function(req, res) {
  var orders = readOrders();
  var filtered = orders.filter(function(o) { return o.orderRef !== req.params.ref; });
  fs.writeFileSync(DB_FILE, JSON.stringify(filtered, null, 2));
  res.json({ success: true });
});

app.get('/api/health', function(req, res) { res.json({ status: 'ok' }); });

var PORT = process.env.PORT || 3000;
app.listen(PORT, function() {
  console.log('Photobooth App running at http://localhost:' + PORT);
  console.log('Admin portal: http://localhost:' + PORT + '/admin.html');
});
