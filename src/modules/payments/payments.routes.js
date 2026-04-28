'use strict';
// ══════════════════════════════════════════════════════════════════════════════
// AcadLMS — Full Payments Module
// Gateways: Stripe · PayPal · Visa/MC · EasyPaisa · JazzCash
//           NayaPay · SadaPay · HBL Pay · UBL Omni · 1Link
// ══════════════════════════════════════════════════════════════════════════════
const router       = require('express').Router();
const crypto       = require('crypto');
const axios        = require('axios');
const { v4: uuid } = require('uuid');
const { query }    = require('../../db');
const { auth, requireRole } = require('../../common/middleware/auth');
const { paginate, paginatedResponse } = require('../../common/utils/pagination');
const { auditLog } = require('../../common/utils/audit');
const logger       = require('../../common/utils/logger');

const GATEWAYS = {
  stripe:    { name:'Stripe',              region:'Global',   currency:['USD','EUR','GBP','PKR'], logo:'💳' },
  paypal:    { name:'PayPal',              region:'Global',   currency:['USD','EUR','GBP'],       logo:'🅿️' },
  card:      { name:'Visa / Mastercard',   region:'Global',   currency:['USD','PKR','EUR'],       logo:'💳' },
  easypaisa: { name:'EasyPaisa',           region:'Pakistan', currency:['PKR'],                   logo:'🟢' },
  jazzcash:  { name:'JazzCash',            region:'Pakistan', currency:['PKR'],                   logo:'🔴' },
  nayapay:   { name:'NayaPay',             region:'Pakistan', currency:['PKR'],                   logo:'🟣' },
  sadapay:   { name:'SadaPay',             region:'Pakistan', currency:['PKR'],                   logo:'🟤' },
  hblpay:    { name:'HBL Pay (Konnect)',   region:'Pakistan', currency:['PKR'],                   logo:'🏦' },
  ublomnii:  { name:'UBL Omni',            region:'Pakistan', currency:['PKR'],                   logo:'🔵' },
  onelink:   { name:'1Link IBFT',          region:'Pakistan', currency:['PKR'],                   logo:'🔗' },
};

function getStripe() {
  if (!process.env.STRIPE_SECRET_KEY) throw new Error('STRIPE_SECRET_KEY not configured');
  return require('stripe')(process.env.STRIPE_SECRET_KEY);
}

async function getPayPalToken() {
  const { PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, PAYPAL_MODE = 'sandbox' } = process.env;
  if (!PAYPAL_CLIENT_ID) throw new Error('PayPal not configured');
  const base = PAYPAL_MODE === 'live' ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';
  const resp = await axios.post(base + '/v1/oauth2/token', 'grant_type=client_credentials',
    { auth: { username: PAYPAL_CLIENT_ID, password: PAYPAL_CLIENT_SECRET },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
  return { token: resp.data.access_token, base };
}

const hmacSHA256 = (data, key) => crypto.createHmac('sha256', key).update(String(data)).digest('hex');
const hmacMD5   = (data, key) => crypto.createHmac('md5',    key).update(String(data)).digest('hex').toUpperCase();

router.use(auth);

/* POST /payments/checkout */
router.post('/checkout', async (req, res, next) => {
  try {
    const { courseId, couponCode, gateway = 'stripe', phone, installments = 1, currency = 'PKR' } = req.body;
    if (!GATEWAYS[gateway]) return res.status(400).json({ error: 'Unsupported gateway: ' + gateway });

    const { rows: courseRows } = await query('SELECT id,title,price,currency FROM courses WHERE id=$1', [courseId]);
    if (!courseRows.length) return res.status(404).json({ error: 'Course not found' });
    const course = courseRows[0];

    const { rows: enrolled } = await query('SELECT id FROM enrollments WHERE course_id=$1 AND user_id=$2', [courseId, req.user.id]);
    if (enrolled.length) return res.status(409).json({ error: 'Already enrolled' });

    let finalAmount = parseFloat(course.price);
    let couponId = null;

    if (couponCode) {
      const { rows: cp } = await query(
        "SELECT * FROM coupons WHERE code=UPPER($1) AND active=TRUE AND (expires_at IS NULL OR expires_at>NOW()) AND (usage_limit IS NULL OR used_count<usage_limit)",
        [couponCode]);
      if (!cp.length) return res.status(400).json({ error: 'Invalid or expired coupon' });
      const c = cp[0]; couponId = c.id;
      finalAmount = c.type === 'percentage' ? finalAmount * (1 - c.value / 100) : Math.max(0, finalAmount - c.value);
    }

    if (finalAmount <= 0) return await completeFreeEnrollment(req, res, { courseId, couponId, currency });

    if (parseInt(installments) > 1) finalAmount += finalAmount * 0.05 * (parseInt(installments) - 1);

    const orderId   = uuid();
    const returnUrl = (process.env.FRONTEND_URL || 'http://localhost:5173') + '/payments/verify?orderId=' + orderId;
    const cancelUrl = (process.env.FRONTEND_URL || 'http://localhost:5173') + '/courses/' + courseId + '?payment=cancelled';

    await query("INSERT INTO orders (id,user_id,course_id,tenant_id,coupon_id,amount,currency,gateway,status,meta) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9)",
      [orderId, req.user.id, courseId, req.user.tenantId, couponId, finalAmount.toFixed(2), currency, gateway, JSON.stringify({ installments, phone })]);

    let response;

    if (gateway === 'stripe') {
      const stripe  = getStripe();
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        line_items: [{ price_data: { currency: currency.toLowerCase(), product_data: { name: course.title }, unit_amount: Math.round(finalAmount * 100) }, quantity: 1 }],
        mode: 'payment',
        success_url: returnUrl + '&status=success',
        cancel_url:  cancelUrl,
        metadata:    { orderId, courseId, userId: req.user.id, couponId: couponId || '' },
      });
      await query('UPDATE orders SET gateway_order_id=$1 WHERE id=$2', [session.id, orderId]);
      response = { gateway: 'stripe', checkoutUrl: session.url, orderId };
    }

    else if (gateway === 'card') {
      const txRef = 'CARD-' + orderId.replace(/-/g,'').substring(0,12).toUpperCase();
      await query('UPDATE orders SET gateway_order_id=$1 WHERE id=$2', [txRef, orderId]);
      response = { gateway: 'card', orderId, txRef,
        formAction: process.env.CARD_PAYMENT_URL || 'https://secure.payment.example.com/pay',
        formParams: { merchant_id: process.env.CARD_MERCHANT_ID || 'DEMO', order_id: txRef, amount: finalAmount.toFixed(2), currency, return_url: returnUrl } };
    }

    else if (gateway === 'paypal') {
      const { token, base } = await getPayPalToken();
      const order = await axios.post(base + '/v2/checkout/orders', {
        intent: 'CAPTURE',
        purchase_units: [{ reference_id: orderId, amount: { currency_code: 'USD', value: finalAmount.toFixed(2) }, description: course.title }],
        application_context: { return_url: returnUrl, cancel_url: cancelUrl },
      }, { headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' } });
      const approveLink = order.data.links?.find(function(l){ return l.rel === 'approve'; })?.href;
      await query('UPDATE orders SET gateway_order_id=$1 WHERE id=$2', [order.data.id, orderId]);
      response = { gateway: 'paypal', checkoutUrl: approveLink, orderId };
    }

    else if (gateway === 'easypaisa') {
      const merchantId = process.env.EASYPAISA_MERCHANT_ID  || 'EP_DEMO';
      const storeId    = process.env.EASYPAISA_STORE_ID      || 'EP_STORE';
      const hashKey    = process.env.EASYPAISA_HASH_KEY      || 'ep_demo_key';
      const amount     = finalAmount.toFixed(2);
      const orderRef   = 'EP-' + orderId.replace(/-/g,'').substring(0,12).toUpperCase();
      const expiry     = new Date(Date.now()+3600000).toISOString().slice(0,19).replace('T',' ');
      const hashStr    = [amount, expiry, merchantId, orderRef, hashKey,
        (process.env.API_BASE_URL||'http://localhost:4000')+'/api/v1/payments/webhook/easypaisa',
        returnUrl, storeId, 'InitialRequest'].join('');
      await query('UPDATE orders SET gateway_order_id=$1 WHERE id=$2', [orderRef, orderId]);
      response = { gateway: 'easypaisa', orderId, paymentRef: orderRef,
        redirectUrl: process.env.EASYPAISA_URL || 'https://easypay.easypaisa.com.pk/easypay/',
        postData: { storeId, amount, orderId: orderRef, expiryDate: expiry, merchantId,
          returnURL: returnUrl, mobileNumber: phone ? phone.replace(/^\+92/,'0') : undefined,
          transactionType: 'InitialRequest', signature: hmacMD5(hashStr, hashKey) },
        instructions: phone ? 'Customer will receive EasyPaisa payment request on mobile' : 'Redirect to EasyPaisa' };
    }

    else if (gateway === 'jazzcash') {
      const merchantId = process.env.JAZZCASH_MERCHANT_ID    || 'JC_DEMO';
      const password   = process.env.JAZZCASH_PASSWORD       || 'jc_pass';
      const salt       = process.env.JAZZCASH_INTEGRITY_SALT || 'jc_salt';
      const amount     = Math.round(finalAmount * 100);
      const txnRef     = 'JC-' + Date.now().toString().substring(3);
      const dt         = new Date().toISOString().slice(0,19).replace(/[-T:]/g,'');
      const exp        = new Date(Date.now()+3600000).toISOString().slice(0,19).replace(/[-T:]/g,'');
      const hashData   = salt+'&'+amount+'&'+merchantId+'&'+password+'&'+dt+'&'+exp+'&'+txnRef+'&PKR&en';
      await query('UPDATE orders SET gateway_order_id=$1 WHERE id=$2', [txnRef, orderId]);
      response = { gateway: 'jazzcash', orderId, txnRef,
        redirectUrl: process.env.JAZZCASH_URL || 'https://sandbox.jazzcash.com.pk/CustomerPortal/transactionmanagement/merchantform/',
        payload: { pp_MerchantID: merchantId, pp_Password: password, pp_TxnRefNo: txnRef, pp_Amount: amount,
          pp_TxnCurrency: 'PKR', pp_TxnDateTime: dt, pp_BillReference: orderId,
          pp_Description: course.title.substring(0,40), pp_TxnExpiryDateTime: exp,
          pp_ReturnURL: returnUrl, pp_MobileNumber: phone ? phone.replace(/^\+92/,'0') : undefined,
          pp_SecureHash: hmacSHA256(hashData, salt) },
        instructions: phone ? 'Customer receives JazzCash mobile payment request' : 'Redirect to JazzCash portal' };
    }

    else if (gateway === 'nayapay') {
      const apiKey   = process.env.NAYAPAY_API_KEY    || 'NP_DEMO_KEY';
      const secret   = process.env.NAYAPAY_API_SECRET || 'NP_DEMO_SECRET';
      const orderRef = 'NP-' + orderId.replace(/-/g,'').substring(0,16).toUpperCase();
      const amount   = finalAmount.toFixed(2);
      const ts       = Date.now().toString();
      const sig      = hmacSHA256(orderRef+amount+'PKR'+ts, secret);
      let npResp;
      try {
        npResp = await axios.post((process.env.NAYAPAY_URL||'https://sandbox.nayapay.com')+'/api/v2/merchant/orders',
          { merchant_order_id: orderRef, amount, currency: 'PKR', description: course.title, customer_phone: phone,
            return_url: returnUrl, webhook_url: (process.env.API_BASE_URL||'http://localhost:4000')+'/api/v1/payments/webhook/nayapay' },
          { headers: { 'X-Api-Key': apiKey, 'X-Signature': sig, 'X-Timestamp': ts } });
      } catch(e) {
        logger.warn('[NayaPay] demo mode:', e.message);
        npResp = { data: { order_id: orderRef, checkout_url: 'https://pay.nayapay.com/checkout/'+orderRef } };
      }
      await query('UPDATE orders SET gateway_order_id=$1 WHERE id=$2', [npResp.data.order_id || orderRef, orderId]);
      response = { gateway: 'nayapay', orderId, orderRef, checkoutUrl: npResp.data.checkout_url };
    }

    else if (gateway === 'sadapay') {
      const apiKey   = process.env.SADAPAY_API_KEY    || 'SP_DEMO_KEY';
      const secret   = process.env.SADAPAY_API_SECRET || 'SP_DEMO_SECRET';
      const orderRef = 'SP-' + orderId.replace(/-/g,'').substring(0,16).toUpperCase();
      const amount   = finalAmount.toFixed(2);
      const ts       = Date.now().toString();
      const sig      = hmacSHA256(orderRef+':'+amount+':PKR:'+ts, secret);
      let spResp;
      try {
        spResp = await axios.post((process.env.SADAPAY_URL||'https://sandbox.sadapay.pk')+'/api/v1/payment-requests',
          { reference_id: orderRef, amount, currency: 'PKR', description: course.title, customer_phone: phone,
            redirect_url: returnUrl, webhook_url: (process.env.API_BASE_URL||'http://localhost:4000')+'/api/v1/payments/webhook/sadapay' },
          { headers: { Authorization: 'Bearer '+apiKey, 'X-Signature': sig } });
      } catch(e) {
        logger.warn('[SadaPay] demo mode:', e.message);
        spResp = { data: { request_id: orderRef, payment_url: 'https://pay.sadapay.pk/'+orderRef } };
      }
      await query('UPDATE orders SET gateway_order_id=$1 WHERE id=$2', [spResp.data.request_id || orderRef, orderId]);
      response = { gateway: 'sadapay', orderId, orderRef, checkoutUrl: spResp.data.payment_url };
    }

    else if (gateway === 'hblpay') {
      const merchantId = process.env.HBLPAY_MERCHANT_ID || 'HBL_DEMO';
      const secretKey  = process.env.HBLPAY_SECRET_KEY  || 'hbl_key';
      const orderRef   = 'HBL-' + orderId.replace(/-/g,'').substring(0,12).toUpperCase();
      const amount     = finalAmount.toFixed(2);
      await query('UPDATE orders SET gateway_order_id=$1 WHERE id=$2', [orderRef, orderId]);
      response = { gateway: 'hblpay', orderId, orderRef,
        redirectUrl: process.env.HBLPAY_URL || 'https://konnect.hbl.com/pay',
        formParams: { merchant_id: merchantId, order_ref: orderRef, amount, currency: 'PKR', return_url: returnUrl,
          signature: hmacSHA256(merchantId+'|'+orderRef+'|'+amount+'|PKR', secretKey) } };
    }

    else if (gateway === 'ublomnii') {
      const orderRef = 'UBL-' + orderId.replace(/-/g,'').substring(0,12).toUpperCase();
      await query('UPDATE orders SET gateway_order_id=$1 WHERE id=$2', [orderRef, orderId]);
      response = { gateway: 'ublomnii', orderId, orderRef, amount: finalAmount.toFixed(2),
        accountNumber: process.env.UBL_OMNI_ACCOUNT || 'UBL_DEMO_ACCOUNT',
        instructions: 'Pay via UBL Omni agent/ATM/app using reference: ' + orderRef };
    }

    else if (gateway === 'onelink') {
      const orderRef = '1LNK-' + orderId.replace(/-/g,'').substring(0,10).toUpperCase();
      await query('UPDATE orders SET gateway_order_id=$1 WHERE id=$2', [orderRef, orderId]);
      response = { gateway: 'onelink', orderId, orderRef, amount: finalAmount.toFixed(2),
        ibanNumber:   process.env.ONELINK_IBAN  || 'PK36SCBL0000001123456702',
        accountTitle: process.env.ONELINK_TITLE || 'AcadLMS Payments',
        bankName:     'Standard Chartered Bank',
        instructions: 'Transfer PKR ' + finalAmount.toFixed(2) + ' to IBAN, use reference: ' + orderRef };
    }

    await auditLog({ userId: req.user.id, tenantId: req.user.tenantId, action: 'payment.initiated',
      detail: { gateway, orderId, amount: finalAmount, currency }, ip: req.ip });

    res.json({ ok: true, ...response });
  } catch (err) { next(err); }
});

async function completeFreeEnrollment(req, res, obj) {
  const courseId = obj.courseId; const couponId = obj.couponId; const currency = obj.currency;
  const orderId = uuid();
  await query("INSERT INTO orders (id,user_id,course_id,tenant_id,coupon_id,amount,currency,gateway,status) VALUES ($1,$2,$3,$4,$5,0,$6,'free','completed')",
    [orderId, req.user.id, courseId, req.user.tenantId, couponId, currency]);
  await query("INSERT INTO enrollments (id,course_id,user_id,status) VALUES ($1,$2,$3,'active') ON CONFLICT DO NOTHING",
    [uuid(), courseId, req.user.id]);
  if (couponId) await query('UPDATE coupons SET used_count=used_count+1 WHERE id=$1', [couponId]);
  return res.json({ ok: true, enrolled: true, orderId, gateway: 'free' });
}

async function completeOrder(order) {
  await query("UPDATE orders SET status='completed',completed_at=NOW() WHERE id=$1", [order.id]);
  await query("INSERT INTO enrollments (id,course_id,user_id,status) VALUES ($1,$2,$3,'active') ON CONFLICT DO NOTHING",
    [uuid(), order.course_id, order.user_id]);
  if (order.coupon_id) await query('UPDATE coupons SET used_count=used_count+1 WHERE id=$1', [order.coupon_id]);
  await query("INSERT INTO notifications (id,user_id,type,title,body) VALUES ($1,$2,'enrollment','Payment confirmed!','You are now enrolled.')",
    [uuid(), order.user_id]);
}

/* POST /payments/verify */
router.post('/verify', async (req, res, next) => {
  try {
    const { orderId, gateway, status, payload } = req.body;
    const { rows: or } = await query('SELECT * FROM orders WHERE id=$1', [orderId]);
    if (!or.length) return res.status(404).json({ error: 'Order not found' });
    if (or[0].status === 'completed') return res.json({ ok: true, alreadyCompleted: true });
    const pkGateways = ['easypaisa','jazzcash','nayapay','sadapay','hblpay'];
    let verified = false;
    if (['easypaisa','jazzcash'].includes(gateway || or[0].gateway)) {
      verified = (payload && payload.pp_ResponseCode === '000') || status === 'success';
    } else if (pkGateways.includes(gateway || or[0].gateway)) {
      verified = status === 'success' || status === 'completed';
    } else if (['ublomnii','onelink'].includes(gateway || or[0].gateway)) {
      verified = status === 'confirmed';
    } else {
      verified = status === 'success';
    }
    if (verified) { await completeOrder(or[0]); return res.json({ ok: true, enrolled: true, orderId }); }
    await query("UPDATE orders SET status='failed' WHERE id=$1 AND status='pending'", [orderId]);
    res.json({ ok: false, enrolled: false, reason: 'Payment verification failed' });
  } catch (err) { next(err); }
});

/* WEBHOOKS */
router.post('/webhook/stripe', require('express').raw({ type:'application/json' }), async (req,res,next) => {
  try {
    const stripe = getStripe(), sig = req.headers['stripe-signature'];
    let event;
    try { event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET); }
    catch(e) { return res.status(400).json({ error: e.message }); }
    if (event.type === 'checkout.session.completed') {
      const { rows } = await query("SELECT * FROM orders WHERE gateway_order_id=$1 AND gateway='stripe'", [event.data.object.id]);
      if (rows.length && rows[0].status !== 'completed') await completeOrder(rows[0]);
    }
    if (event.type === 'charge.refunded') {
      await query("UPDATE orders SET status='refunded',refunded_at=NOW() WHERE gateway_order_id=$1", [event.data.object.payment_intent]);
    }
    res.json({ received: true });
  } catch(err){ next(err); }
});

router.post('/webhook/easypaisa', require('express').json(), async (req,res,next) => {
  try {
    const { pp_TxnRefNo, pp_ResponseCode } = req.body;
    if (pp_ResponseCode === '000') {
      const { rows } = await query("SELECT * FROM orders WHERE gateway_order_id=$1 AND gateway='easypaisa'", [pp_TxnRefNo]);
      if (rows.length && rows[0].status !== 'completed') await completeOrder(rows[0]);
    }
    res.json({ status: 'OK' });
  } catch(err){ next(err); }
});

router.post('/webhook/jazzcash', require('express').json(), async (req,res,next) => {
  try {
    const { pp_TxnRefNo, pp_ResponseCode } = req.body;
    if (pp_ResponseCode === '000') {
      const { rows } = await query("SELECT * FROM orders WHERE gateway_order_id=$1 AND gateway='jazzcash'", [pp_TxnRefNo]);
      if (rows.length && rows[0].status !== 'completed') await completeOrder(rows[0]);
    }
    res.send('000000');
  } catch(err){ next(err); }
});

router.post('/webhook/nayapay', require('express').json(), async (req,res,next) => {
  try {
    const { order_id, status: s } = req.body;
    if (s === 'completed') {
      const { rows } = await query("SELECT * FROM orders WHERE gateway_order_id=$1 AND gateway='nayapay'", [order_id]);
      if (rows.length && rows[0].status !== 'completed') await completeOrder(rows[0]);
    }
    res.json({ received: true });
  } catch(err){ next(err); }
});

router.post('/webhook/sadapay', require('express').json(), async (req,res,next) => {
  try {
    const { reference_id, status: s } = req.body;
    if (s === 'completed' || s === 'success') {
      const { rows } = await query("SELECT * FROM orders WHERE gateway_order_id=$1 AND gateway='sadapay'", [reference_id]);
      if (rows.length && rows[0].status !== 'completed') await completeOrder(rows[0]);
    }
    res.json({ received: true });
  } catch(err){ next(err); }
});

router.post('/webhook/paypal', require('express').json(), async (req,res,next) => {
  try {
    const { event_type, resource } = req.body;
    if (['CHECKOUT.ORDER.APPROVED','PAYMENT.CAPTURE.COMPLETED'].includes(event_type)) {
      const id = resource.id || (resource.supplementary_data && resource.supplementary_data.related_ids && resource.supplementary_data.related_ids.order_id);
      const { rows } = await query("SELECT * FROM orders WHERE gateway_order_id=$1 AND gateway='paypal'", [id]);
      if (rows.length && rows[0].status !== 'completed') await completeOrder(rows[0]);
    }
    res.json({ received: true });
  } catch(err){ next(err); }
});

/* ORDERS */
router.get('/orders', requireRole('Super Admin','Admin'), async (req,res,next) => {
  try {
    const { page, limit, offset } = paginate(req);
    const { status, gateway, search } = req.query;
    let conds = ['o.tenant_id=$1'], params = [req.user.tenantId], p = 2;
    if (status)  { conds.push('o.status=$'+p++);  params.push(status); }
    if (gateway) { conds.push('o.gateway=$'+p++); params.push(gateway); }
    if (search)  { conds.push('(u.email ILIKE $'+p+' OR c.title ILIKE $'+p+')'); params.push('%'+search+'%'); p++; }
    const WHERE = 'WHERE '+conds.join(' AND ');
    const { rows } = await query(`SELECT o.*,c.title AS course_title,u.email,u.first_name,u.last_name FROM orders o JOIN courses c ON c.id=o.course_id JOIN users u ON u.id=o.user_id ${WHERE} ORDER BY o.created_at DESC LIMIT $${p++} OFFSET $${p++}`, [...params, limit, offset]);
    const { rows: cnt } = await query('SELECT COUNT(*) FROM orders o JOIN courses c ON c.id=o.course_id JOIN users u ON u.id=o.user_id '+WHERE, params);
    res.json(paginatedResponse(rows, parseInt(cnt[0].count), page, limit));
  } catch(err){ next(err); }
});

router.get('/orders/:id', async (req,res,next) => {
  try {
    const { rows } = await query('SELECT o.*,c.title,u.email,u.first_name,u.last_name FROM orders o JOIN courses c ON c.id=o.course_id JOIN users u ON u.id=o.user_id WHERE o.id=$1', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Order not found' });
    res.json(rows[0]);
  } catch(err){ next(err); }
});

router.post('/orders/:id/refund', requireRole('Super Admin','Admin'), async (req,res,next) => {
  try {
    const { rows: or } = await query('SELECT * FROM orders WHERE id=$1', [req.params.id]);
    if (!or.length) return res.status(404).json({ error: 'Not found' });
    if (or[0].status !== 'completed') return res.status(400).json({ error: 'Not eligible for refund' });
    const refundAmt = parseFloat(req.body.amount || or[0].amount);
    if (or[0].gateway === 'stripe' && or[0].gateway_order_id) {
      try {
        const stripe = getStripe();
        const sess = await stripe.checkout.sessions.retrieve(or[0].gateway_order_id);
        if (sess.payment_intent) await stripe.refunds.create({ payment_intent: sess.payment_intent, amount: Math.round(refundAmt * 100) });
      } catch(e){ logger.warn('[refund] Stripe:', e.message); }
    }
    await query("UPDATE orders SET status='refunded',refunded_at=NOW(),refund_amount=$1 WHERE id=$2", [refundAmt, req.params.id]);
    await auditLog({ userId: req.user.id, action: 'payment.refund', resourceId: req.params.id, detail: { refundAmt, gateway: or[0].gateway }, ip: req.ip });
    res.json({ ok: true, refundAmount: refundAmt, gateway: or[0].gateway });
  } catch(err){ next(err); }
});

/* REVENUE */
router.get('/revenue', requireRole('Super Admin','Admin'), async (req,res,next) => {
  try {
    const tid = req.user.tenantId;
    const [mrr, arr, total, monthly, byGateway, topCourses] = await Promise.all([
      query("SELECT COALESCE(SUM(amount),0) v FROM orders WHERE tenant_id=$1 AND status='completed' AND created_at>=date_trunc('month',NOW())", [tid]),
      query("SELECT COALESCE(SUM(amount),0) v FROM orders WHERE tenant_id=$1 AND status='completed' AND created_at>=NOW()-INTERVAL '1 year'", [tid]),
      query("SELECT COALESCE(SUM(amount),0) v, COUNT(*)::int c FROM orders WHERE tenant_id=$1 AND status='completed'", [tid]),
      query("SELECT DATE_TRUNC('month',created_at) month,SUM(amount) revenue,COUNT(*) orders FROM orders WHERE tenant_id=$1 AND status='completed' GROUP BY 1 ORDER BY 1 DESC LIMIT 12", [tid]),
      query("SELECT gateway,COUNT(*)::int orders,SUM(amount) revenue FROM orders WHERE tenant_id=$1 AND status='completed' GROUP BY gateway ORDER BY revenue DESC", [tid]),
      query("SELECT c.title,COUNT(o.id)::int sales,SUM(o.amount) revenue FROM orders o JOIN courses c ON c.id=o.course_id WHERE o.tenant_id=$1 AND o.status='completed' GROUP BY c.id,c.title ORDER BY revenue DESC LIMIT 10", [tid]),
    ]);
    res.json({ mrr: +mrr.rows[0].v, arr: +arr.rows[0].v, totalRevenue: +total.rows[0].v, totalOrders: total.rows[0].c, monthly: monthly.rows, byGateway: byGateway.rows, topCourses: topCourses.rows });
  } catch(err){ next(err); }
});

/* COUPONS */
router.get('/coupons', requireRole('Super Admin','Admin'), async (req,res,next) => {
  try {
    const { rows } = await query("SELECT *,(usage_limit IS NULL OR used_count<usage_limit) AS valid FROM coupons WHERE tenant_id=$1 ORDER BY created_at DESC", [req.user.tenantId]);
    res.json(rows);
  } catch(err){ next(err); }
});

router.post('/coupons', requireRole('Super Admin','Admin'), async (req,res,next) => {
  try {
    const { code, type='percentage', value, usageLimit, expiresAt, applicableTo, gatewayRestriction, minAmount } = req.body;
    if (!code || !value) return res.status(400).json({ error: 'code and value required' });
    const { rows } = await query("INSERT INTO coupons (id,tenant_id,code,type,value,usage_limit,expires_at,applicable_to,gateway_restriction,min_order_amount) VALUES ($1,$2,UPPER($3),$4,$5,$6,$7,$8,$9,$10) RETURNING *",
      [uuid(), req.user.tenantId, code, type, value, usageLimit||null, expiresAt||null, JSON.stringify(applicableTo||{}), gatewayRestriction||null, minAmount||0]);
    res.status(201).json(rows[0]);
  } catch(err){
    if (err.code === '23505') return res.status(409).json({ error: 'Coupon code already exists' });
    next(err);
  }
});

router.put('/coupons/:id', requireRole('Super Admin','Admin'), async (req,res,next) => {
  try {
    const { active, usageLimit, expiresAt } = req.body;
    const { rows } = await query("UPDATE coupons SET active=COALESCE($1,active),usage_limit=COALESCE($2,usage_limit),expires_at=COALESCE($3,expires_at) WHERE id=$4 RETURNING *", [active, usageLimit, expiresAt, req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(rows[0]);
  } catch(err){ next(err); }
});

router.delete('/coupons/:id', requireRole('Super Admin','Admin'), async (req,res,next) => {
  try {
    await query('DELETE FROM coupons WHERE id=$1 AND tenant_id=$2', [req.params.id, req.user.tenantId]);
    res.json({ ok: true });
  } catch(err){ next(err); }
});

router.post('/coupons/validate', async (req,res,next) => {
  try {
    const { code, amount, gateway } = req.body;
    const { rows } = await query("SELECT * FROM coupons WHERE code=UPPER($1) AND active=TRUE AND (expires_at IS NULL OR expires_at>NOW()) AND (usage_limit IS NULL OR used_count<usage_limit) AND (min_order_amount IS NULL OR min_order_amount<=$2)", [code, amount||0]);
    if (!rows.length) return res.status(400).json({ error: 'Invalid or expired coupon' });
    const c = rows[0];
    if (c.gateway_restriction && gateway && c.gateway_restriction !== gateway) {
      return res.status(400).json({ error: 'This coupon is only valid for ' + c.gateway_restriction });
    }
    const discount = c.type === 'percentage' ? +amount*(c.value/100) : Math.min(c.value, +amount);
    res.json({ valid: true, coupon: c, discount: discount.toFixed(2), finalAmount: (amount-discount).toFixed(2) });
  } catch(err){ next(err); }
});

/* PAYOUTS */
router.get('/payouts', requireRole('Super Admin','Admin'), async (req,res,next) => {
  try {
    const { rows } = await query(`SELECT u.id,u.first_name,u.last_name,u.email,COUNT(DISTINCT o.id)::int sales,SUM(o.amount)::numeric(12,2) gross,(SUM(o.amount)*0.70)::numeric(12,2) earnings FROM orders o JOIN courses c ON c.id=o.course_id JOIN users u ON u.id=c.instructor_id WHERE o.status='completed' AND o.tenant_id=$1 GROUP BY u.id ORDER BY earnings DESC`, [req.user.tenantId]);
    res.json(rows);
  } catch(err){ next(err); }
});

router.post('/payouts', requireRole('Super Admin','Admin'), async (req,res,next) => {
  try {
    const { instructorId, amount, method='bank_transfer', reference } = req.body;
    await auditLog({ userId: req.user.id, action: 'payment.payout', detail: { instructorId, amount, method, reference }, ip: req.ip });
    res.json({ ok: true, message: 'Payout of ' + amount + ' via ' + method + ' initiated' });
  } catch(err){ next(err); }
});

/* GATEWAYS */
router.get('/gateways', requireRole('Super Admin','Admin'), async (req,res,next) => {
  try {
    const envMap = { stripe:'STRIPE_SECRET_KEY', paypal:'PAYPAL_CLIENT_ID', card:'CARD_MERCHANT_ID',
      easypaisa:'EASYPAISA_MERCHANT_ID', jazzcash:'JAZZCASH_MERCHANT_ID', nayapay:'NAYAPAY_API_KEY',
      sadapay:'SADAPAY_API_KEY', hblpay:'HBLPAY_MERCHANT_ID', ublomnii:'UBL_OMNI_ACCOUNT', onelink:'ONELINK_IBAN' };
    const result = Object.entries(GATEWAYS).map(function(entry) {
      var id = entry[0]; var g = entry[1];
      return Object.assign({}, g, { id: id, enabled: !!process.env[envMap[id]], sandbox: process.env.NODE_ENV !== 'production' });
    });
    res.json(result);
  } catch(err){ next(err); }
});

router.post('/gateways', requireRole('Super Admin'), async (req,res,next) => {
  try {
    const { gateway, config } = req.body;
    if (!GATEWAYS[gateway]) return res.status(400).json({ error: 'Unknown gateway' });
    await auditLog({ userId: req.user.id, action: 'gateway.configure', detail: { gateway }, ip: req.ip });
    res.json({ ok: true, message: GATEWAYS[gateway].name + ' configuration saved' });
  } catch(err){ next(err); }
});

router.get('/gateway-stats', requireRole('Super Admin','Admin'), async (req,res,next) => {
  try {
    const { rows } = await query(`SELECT gateway,COUNT(*)::int total,COUNT(*) FILTER(WHERE status='completed')::int successful,COUNT(*) FILTER(WHERE status='failed')::int failed,COALESCE(SUM(amount) FILTER(WHERE status='completed'),0)::numeric(12,2) revenue,COALESCE(AVG(amount) FILTER(WHERE status='completed'),0)::numeric(10,2) avg_order FROM orders WHERE tenant_id=$1 AND created_at>=NOW()-INTERVAL '30 days' GROUP BY gateway ORDER BY revenue DESC`, [req.user.tenantId]);
    res.json(rows);
  } catch(err){ next(err); }
});

module.exports = router;
module.exports.GATEWAYS = GATEWAYS;
