require('dotenv').config();
var express    = require('express');
var multer     = require('multer');
var nodemailer = require('nodemailer');
var Stripe     = require('stripe');
var axios      = require('axios');
var FormData   = require('form-data');
var cors       = require('cors');

var app    = express();
var stripe = Stripe(process.env.STRIPE_SECRET_KEY);
var upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));

var transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

app.post('/api/remove-bg', upload.single('photo'), function(req, res) {
  if (!req.file) {
    return res.status(400).json({ error: 'No photo uploaded' });
  }
  var fd = new FormData();
  fd.append('image_file', req.file.buffer, {
    filename: req.file.originalname,
    contentType: req.file.mimetype
  });
  fd.append('size', 'auto');
  axios.post('https://api.remove.bg/v1.0/removebg', fd, {
    headers: Object.assign({ 'X-Api-Key': process.env.REMOVE_BG_KEY }, fd.getHeaders()),
    responseType: 'arraybuffer'
  }).then(function(response) {
    var base64 = Buffer.from(response.data).toString('base64');
    res.json({ success: true, image: 'data:image/png;base64,' + base64 });
  }).catch(function(err) {
    var msg = err.message;
    if (err.response && err.response.data) {
      msg = Buffer.from(err.response.data).toString();
    }
    res.status(500).json({ error: msg });
  });
});

app.post('/api/create-payment-intent', function(req, res) {
  var name  = req.body.name;
  var email = req.body.email;
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

app.post('/api/confirm-order', function(req, res) {
  var name          = req.body.name;
  var email         = req.body.email;
  var phone         = req.body.phone;
  var centre        = req.body.centre;
  var purpose       = req.body.purpose;
  var govRef        = req.body.govRef;
  var passportImage = req.body.passportImage;
  var orderRef      = req.body.orderRef;

  if (!passportImage) {
    return res.status(400).json({ error: 'No image provided' });
  }

  var base64Data = passportImage.replace(/^data:image\/\w+;base64,/, '');
  var imgBuffer  = Buffer.from(base64Data, 'base64');
  var firstName  = name.split(' ')[0];

  var customerHtml =
    '<div style="font-family:Arial,sans-serif;max-width:560px;margin:0 auto;">' +
    '<div style="background:#0d1b2e;padding:28px 32px;">' +
    '<h1 style="color:white;font-size:22px;margin:0;">Photobooth App</h1>' +
    '<p style="color:#8a9bb0;font-size:12px;margin:4px 0 0;">Professional Photo Service</p>' +
    '</div>' +
    '<div style="padding:32px;">' +
    '<h2>Your photo is ready, ' + firstName + '!</h2>' +
    '<p style="color:#5a6275;">Thank you for your order. Your passport photo is attached.</p>' +
    '<div style="background:#f8f9fb;padding:20px;border-radius:10px;margin:20px 0;font-size:13px;">' +
    '<p><strong>Order Ref:</strong> ' + orderRef + '</p>' +
    '<p><strong>Photo Purpose:</strong> ' + purpose + '</p>' +
    '<p><strong>Application Centre:</strong> ' + centre + '</p>' +
    '<p><strong>Total Paid:</strong> £6.99</p>' +
    '</div>' +
    '<p style="background:#f0fdf4;color:#166534;padding:14px;border-radius:8px;">' +
    'Your photo is attached — formatted to passport standard with a white background.</p>' +
    '</div></div>';

  var adminHtml =
    '<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;">' +
    '<div style="background:#0d1b2e;padding:20px 24px;">' +
    '<h2 style="color:white;margin:0;">New Order Received</h2>' +
    '</div>' +
    '<div style="padding:24px;background:#f8f9fb;font-size:14px;">' +
    '<p><strong>Order Ref:</strong> ' + orderRef + '</p>' +
    '<p><strong>Customer:</strong> ' + name + '</p>' +
    '<p><strong>Email:</strong> ' + email + '</p>' +
    '<p><strong>Phone:</strong> ' + phone + '</p>' +
    '<p><strong>Purpose:</strong> ' + purpose + '</p>' +
    '<p><strong>Centre:</strong> ' + centre + '</p>' +
    '<p><strong>Revenue:</strong> £6.99</p>' +
    '</div></div>';

  var attachment = {
    filename: 'passport_photo_' + orderRef + '.jpg',
    content: imgBuffer,
    contentType: 'image/jpeg'
  };

  transporter.sendMail({
    from: '"' + process.env.BUSINESS_NAME + '" <' + process.env.BUSINESS_EMAIL + '>',
    to: email,
    subject: 'Your Passport Photo - Order ' + orderRef,
    html: customerHtml,
    attachments: [attachment]
  }).then(function() {
    return transporter.sendMail({
      from: '"' + process.env.BUSINESS_NAME + '" <' + process.env.BUSINESS_EMAIL + '>',
      to: process.env.ADMIN_EMAIL,
      subject: 'New Order ' + orderRef + ' - ' + name,
      html: adminHtml,
      attachments: [attachment]
    });
  }).then(function() {
    res.json({ success: true, orderRef: orderRef });
  }).catch(function(err) {
    console.error('Email error:', err.message);
    res.status(500).json({ error: err.message });
  });
});

app.get('/api/health', function(req, res) {
  res.json({ status: 'ok' });
});

var PORT = process.env.PORT || 3000;
app.listen(PORT, function() {
  console.log('Photobooth App running at http://localhost:' + PORT);
});
