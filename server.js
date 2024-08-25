require('dotenv').config();

const express = require('express');
const admin = require('firebase-admin');
const serviceAccount = require('./config/serviceAccountKey.json');
const Flutterwave = require('flutterwave-node-v3');
const crypto = require('crypto');
const Joi = require('joi');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const winston = require('winston');
const { v4: uuidv4 } = require('uuid');

const app = express();

// Middleware
app.use(express.json());
app.use(helmet());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Logging
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  defaultMeta: { service: 'user-service' },
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

// Initialize Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: 'https://ride-62540.firebaseio.com'
});

const db = admin.firestore();

// Initialize Flutterwave
const flw = new Flutterwave(process.env.FLW_PUBLIC_KEY, process.env.FLW_SECRET_KEY);

// Webhook secret (should be set in environment variables)
const webhookSecret = process.env.WEBHOOK_SECRET;

// Middleware to verify Flutterwave webhook
function verifyWebhook(req, res, next) {
  const signature = req.headers['verif-hash'];
  if (!signature || signature !== webhookSecret) {
    return res.status(401).send('Invalid signature');
  }
  next();
}

// Middleware to verify Firebase Auth token
async function verifyAuthToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'No authorization token provided' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decodedToken = await admin.auth().verifyIdToken(token);
    req.user = decodedToken;
    next();
  } catch (error) {
    logger.error('Error verifying auth token:', error);
    res.status(403).json({ error: 'Invalid or expired token' });
  }
}

// Helper function to update user's account balance
async function updateUserBalance(userId, amount) {
  const userRef = db.collection('users').doc(userId);
  await db.runTransaction(async (transaction) => {
    const userDoc = await transaction.get(userRef);
    if (!userDoc.exists) {
      throw new Error('User not found');
    }
    const userData = userDoc.data();
    const currentBalance = userData.account?.amount || 0;
    const newBalance = currentBalance + amount;
    transaction.update(userRef, { 'account.amount': newBalance });
  });
}

// Input validation schemas
const createVirtualAccountSchema = Joi.object({
  email: Joi.string().email().required(),
  bvn: Joi.string().length(11).required(),
  fullName: Joi.string().required()
});

const withdrawSchema = Joi.object({
  amount: Joi.number().positive().required(),
  accountNumber: Joi.string().required(),
  bankCode: Joi.string().required()
});

const bookRideSchema = Joi.object({
  rideId: Joi.string().required(),
  amount: Joi.number().positive().required()
});

const completeRideSchema = Joi.object({
  rideId: Joi.string().required(),
  driverId: Joi.string().required()
});

const cancelRideSchema = Joi.object({
  rideId: Joi.string().required(),
  refundAmount: Joi.number().min(0).required()
});

// 1. Create static virtual account for user
app.post('/api/create-virtual-account', verifyAuthToken, async (req, res) => {
  try {
    const { error, value } = createVirtualAccountSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { email, bvn, fullName } = value;
    const userId = req.user.uid;

    // Create virtual account on Flutterwave
    const virtualAccount = await flw.VirtualAcct.create({
      email: email,
      is_permanent: true,
      bvn: bvn,
      tx_ref: `VA-${userId}-${Date.now()}`,
      narration: fullName
    });

    // Update user document in Firestore
    await db.collection('users').doc(userId).update({
      account: {
        accountNumber: virtualAccount.data.account_number,
        bankName: virtualAccount.data.bank_name,
        amount: 0
      }
    });

    res.json({ success: true, virtualAccount: virtualAccount.data });
  } catch (error) {
    logger.error('Error creating virtual account:', error);
    res.status(500).json({ error: 'Failed to create virtual account' });
  }
});

// 2. Webhook to handle deposits
app.post('/api/flutterwave-webhook', verifyWebhook, async (req, res) => {
  try {
    const { event, data } = req.body;

    if (event === 'charge.completed' && data.status === 'successful') {
      const userId = data.tx_ref.split('-')[1]; // Assuming tx_ref format: VA-userId-timestamp
      const amount = data.amount;

      await updateUserBalance(userId, amount);

      // Add to account history
      await db.collection('users').doc(userId).update({
        accountHistory: admin.firestore.FieldValue.arrayUnion({
          id: uuidv4(),
          timestamp: admin.firestore.Timestamp.now(),
          amount: amount,
          transactionType: 'deposit'
        })
      });

      res.sendStatus(200);
    } else {
      res.sendStatus(400);
    }
  } catch (error) {
    logger.error('Error processing webhook:', error);
    res.sendStatus(500);
  }
});

// 3. Withdraw funds
app.post('/api/withdraw', verifyAuthToken, async (req, res) => {
  try {
    const { error, value } = withdrawSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { amount, accountNumber, bankCode } = value;
    const userId = req.user.uid;

    // Check user balance
    const userDoc = await db.collection('users').doc(userId).get();
    const userData = userDoc.data();
    if (!userData || userData.account.amount < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Initiate transfer via Flutterwave
    const transfer = await flw.Transfer.initiate({
      account_bank: bankCode,
      account_number: accountNumber,
      amount: amount,
      currency: "NGN",
      narration: "Withdrawal from wallet",
      reference: `WD-${userId}-${Date.now()}`
    });

    if (transfer.status === 'success') {
      // Update user balance
      await updateUserBalance(userId, -amount);

      // Add to account history
      await db.collection('users').doc(userId).update({
        accountHistory: admin.firestore.FieldValue.arrayUnion({
          id: uuidv4(),
          timestamp: admin.firestore.Timestamp.now(),
          amount: -amount,
          transactionType: 'withdrawal'
        })
      });

      res.json({ success: true, message: 'Withdrawal initiated successfully' });
    } else {
      res.status(400).json({ error: 'Failed to initiate withdrawal' });
    }
  } catch (error) {
    logger.error('Error processing withdrawal:', error);
    res.status(500).json({ error: 'Failed to process withdrawal' });
  }
});

// 4. Escrow system for ride booking
app.post('/api/book-ride', verifyAuthToken, async (req, res) => {
  try {
    const { error, value } = bookRideSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { rideId, amount } = value;
    const userId = req.user.uid;

    // Check user balance
    const userDoc = await db.collection('users').doc(userId).get();
    const userData = userDoc.data();
    if (!userData || userData.account.amount < amount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    // Hold funds in escrow
    await db.runTransaction(async (transaction) => {
      const userRef = db.collection('users').doc(userId);
      const user = await transaction.get(userRef);
      const currentBalance = user.data().account.amount;
      
      transaction.update(userRef, { 
        'account.amount': currentBalance - amount,
        escrowAmount: admin.firestore.FieldValue.increment(amount)
      });

      // Create escrow record
      const escrowRef = db.collection('escrow').doc();
      transaction.set(escrowRef, {
        userId: userId,
        rideId: rideId,
        amount: amount,
        status: 'held',
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        releaseAt: admin.firestore.Timestamp.fromMillis(Date.now() + 24 * 60 * 60 * 1000) // 24 hours from now
      });
    });

    res.json({ success: true, message: 'Ride booked and funds held in escrow' });
  } catch (error) {
    logger.error('Error booking ride:', error);
    res.status(500).json({ error: 'Failed to book ride' });
  }
});

// 5. Release escrow after ride completion
app.post('/api/complete-ride', verifyAuthToken, async (req, res) => {
  try {
    const { error, value } = completeRideSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { rideId, driverId } = value;

    await db.runTransaction(async (transaction) => {
      const escrowRef = db.collection('escrow').where('rideId', '==', rideId).limit(1);
      const escrowDocs = await transaction.get(escrowRef);
      
      if (escrowDocs.empty) {
        throw new Error('Escrow record not found');
      }

      const escrowDoc = escrowDocs.docs[0];
      const escrowData = escrowDoc.data();

      if (escrowData.status !== 'held') {
        throw new Error('Invalid escrow status');
      }

      const userRef = db.collection('users').doc(escrowData.userId);
      const driverRef = db.collection('users').doc(driverId);

      // Release escrow
      transaction.update(userRef, {
        escrowAmount: admin.firestore.FieldValue.increment(-escrowData.amount)
      });

      // Pay driver
      transaction.update(driverRef, {
        'account.amount': admin.firestore.FieldValue.increment(escrowData.amount)
      });

      // Update escrow status
      transaction.update(escrowDoc.ref, { status: 'released' });

      // Add to account history for both user and driver
      const historyEntry = {
        id: uuidv4(),
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
        amount: escrowData.amount,
        transactionType: 'ride_payment',
        rideId: rideId
      };

      transaction.update(userRef, {
        accountHistory: admin.firestore.FieldValue.arrayUnion({
          ...historyEntry,
          amount: -escrowData.amount
        })
      });

      transaction.update(driverRef, {
        accountHistory: admin.firestore.FieldValue.arrayUnion(historyEntry)
      });
    });

    res.json({ success: true, message: 'Ride completed and payment processed' });
  } catch (error) {
    logger.error('Error completing ride:', error);
    res.status(500).json({ error: 'Failed to complete ride' });
  }
});

// 6. Cancel ride and refund user
app.post('/api/cancel-ride', verifyAuthToken, async (req, res) => {
  try {
    const { error, value } = cancelRideSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { rideId, refundAmount } = value;

    await db.runTransaction(async (transaction) => {
      const escrowRef = db.collection('escrow').where('rideId', '==', rideId).limit(1);
      const escrowDocs = await transaction.get(escrowRef);
      
      if (escrowDocs.empty) {
        throw new Error('Escrow record not found');
      }

      const escrowDoc = escrowDocs.docs[0];
      const escrowData = escrowDoc.data();

      if (escrowData.status !== 'held') {
        throw new Error('Invalid escrow status');
      }

      if (refundAmount > escrowData.amount) {
        throw new Error('Refund amount exceeds escrow amount');
      }

      const userRef = db.collection('users').doc(escrowData.userId);

      // Refund user
      transaction.update(userRef, {
        'account.amount': admin.firestore.FieldValue.increment(refundAmount),
        escrowAmount: admin.firestore.FieldValue.increment(-escrowData.amount)
      });

      // Update escrow status
      transaction.update(escrowDoc.ref, { 
        status: 'cancelled',
        refundAmount: refundAmount,
        cancelledAt: admin.firestore.FieldValue.serverTimestamp()
      });

      // Add to account history
      transaction.update(userRef, {
        accountHistory: admin.firestore.FieldValue.arrayUnion({
          id: uuidv4(),
          timestamp: admin.firestore.Timestamp.now(),
          amount: refundAmount,
          transactionType: 'ride_cancellation_refund',
          rideId: rideId
        })
      });
    });

    res.json({ success: true, message: 'Ride cancelled and refund processed' });
  } catch (error) {
    logger.error('Error cancelling ride:', error);
    res.status(500).json({ error: 'Failed to cancel ride' });
  }
});

// 7. Automatic escrow release (to be run as a scheduled function)
async function releaseExpiredEscrows() {
  const now = admin.firestore.Timestamp.now();
  const expiredEscrows = await db.collection('escrow')
    .where('status', '==', 'held')
    .where('releaseAt', '<=', now)
    .get();

  const batch = db.batch();

  for (const doc of expiredEscrows.docs) {
    const escrowData = doc.data();
    const userRef = db.collection('users').doc(escrowData.userId);
    const driverRef = db.collection('users').doc(escrowData.driverId);

    // Release escrow to driver
    batch.update(userRef, {
      escrowAmount: admin.firestore.FieldValue.increment(-escrowData.amount)
    });

    batch.update(driverRef, {
      'account.amount': admin.firestore.FieldValue.increment(escrowData.amount)
    });

    // Update escrow status
    batch.update(doc.ref, { 
      status: 'auto_released',
      releasedAt: now
    });

    // Add to account history for both user and driver
    const historyEntry = {
      id: uuidv4(),
      timestamp: now,
      amount: escrowData.amount,
      transactionType: 'auto_released_ride_payment',
      rideId: escrowData.rideId
    };

    batch.update(userRef, {
      accountHistory: admin.firestore.FieldValue.arrayUnion({
        ...historyEntry,
        amount: -escrowData.amount
      })
    });

    batch.update(driverRef, {
      accountHistory: admin.firestore.FieldValue.arrayUnion(historyEntry)
    });
  }

  await batch.commit();
  logger.info(`Auto-released ${expiredEscrows.size} expired escrows`);
}

// 8. Get user balance
app.get('/api/balance', verifyAuthToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    const userDoc = await db.collection('users').doc(userId).get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userData = userDoc.data();
    const balance = userData.account?.amount || 0;
    const escrowAmount = userData.escrowAmount || 0;

    res.json({ 
      balance, 
      escrowAmount,
      availableBalance: balance - escrowAmount
    });
  } catch (error) {
    logger.error('Error fetching balance:', error);
    res.status(500).json({ error: 'Failed to fetch balance' });
  }
});

// 9. Get transaction history
app.get('/api/transaction-history', verifyAuthToken, async (req, res) => {
  try {
    const userId = req.user.uid;
    const limit = parseInt(req.query.limit) || 20;
    const page = parseInt(req.query.page) || 1;

    const userDoc = await db.collection('users').doc(userId).get();
    
    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userData = userDoc.data();
    const history = userData.accountHistory || [];

    const startIndex = (page - 1) * limit;
    const endIndex = page * limit;

    const paginatedHistory = history.slice(startIndex, endIndex);

    res.json({
      transactions: paginatedHistory,
      currentPage: page,
      totalPages: Math.ceil(history.length / limit),
      totalTransactions: history.length
    });
  } catch (error) {
    logger.error('Error fetching transaction history:', error);
    res.status(500).json({ error: 'Failed to fetch transaction history' });
  }
});

// 10. Initiate a dispute
const disputeSchema = Joi.object({
  rideId: Joi.string().required(),
  reason: Joi.string().required(),
  description: Joi.string().required()
});

app.post('/api/initiate-dispute', verifyAuthToken, async (req, res) => {
  try {
    const { error, value } = disputeSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { rideId, reason, description } = value;
    const userId = req.user.uid;

    const escrowDoc = await db.collection('escrow')
      .where('rideId', '==', rideId)
      .where('userId', '==', userId)
      .limit(1)
      .get();

    if (escrowDoc.empty) {
      return res.status(404).json({ error: 'Escrow record not found' });
    }

    const escrowData = escrowDoc.docs[0].data();

    if (escrowData.status !== 'held' && escrowData.status !== 'released') {
      return res.status(400).json({ error: 'Cannot initiate dispute for this escrow status' });
    }

    const disputeRef = db.collection('disputes').doc();
    await disputeRef.set({
      rideId,
      userId,
      driverId: escrowData.driverId,
      amount: escrowData.amount,
      reason,
      description,
      status: 'open',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ success: true, message: 'Dispute initiated successfully', disputeId: disputeRef.id });
  } catch (error) {
    logger.error('Error initiating dispute:', error);
    res.status(500).json({ error: 'Failed to initiate dispute' });
  }
});

// 11. Resolve dispute (admin only)
const resolveDisputeSchema = Joi.object({
  disputeId: Joi.string().required(),
  resolution: Joi.string().valid('refund', 'release', 'partial_refund').required(),
  refundAmount: Joi.when('resolution', {
    is: 'partial_refund',
    then: Joi.number().positive().required(),
    otherwise: Joi.forbidden()
  })
});

app.post('/api/resolve-dispute', verifyAuthToken, async (req, res) => {
  try {
    // Check if the user is an admin
    if (!req.user.admin) {
      return res.status(403).json({ error: 'Unauthorized. Admin access required.' });
    }

    const { error, value } = resolveDisputeSchema.validate(req.body);
    if (error) {
      return res.status(400).json({ error: error.details[0].message });
    }

    const { disputeId, resolution, refundAmount } = value;

    await db.runTransaction(async (transaction) => {
      const disputeRef = db.collection('disputes').doc(disputeId);
      const disputeDoc = await transaction.get(disputeRef);

      if (!disputeDoc.exists) {
        throw new Error('Dispute not found');
      }

      const disputeData = disputeDoc.data();

      if (disputeData.status !== 'open') {
        throw new Error('Dispute is not open');
      }

      const escrowRef = db.collection('escrow').where('rideId', '==', disputeData.rideId).limit(1);
      const escrowDocs = await transaction.get(escrowRef);

      if (escrowDocs.empty) {
        throw new Error('Escrow record not found');
      }

      const escrowDoc = escrowDocs.docs[0];
      const escrowData = escrowDoc.data();

      const userRef = db.collection('users').doc(disputeData.userId);
      const driverRef = db.collection('users').doc(disputeData.driverId);

      let userRefundAmount = 0;
      let driverPaymentAmount = 0;

      switch (resolution) {
        case 'refund':
          userRefundAmount = escrowData.amount;
          break;
        case 'release':
          driverPaymentAmount = escrowData.amount;
          break;
        case 'partial_refund':
          userRefundAmount = refundAmount;
          driverPaymentAmount = escrowData.amount - refundAmount;
          break;
      }

      // Update user balance
      if (userRefundAmount > 0) {
        transaction.update(userRef, {
          'account.amount': admin.firestore.FieldValue.increment(userRefundAmount),
          escrowAmount: admin.firestore.FieldValue.increment(-userRefundAmount)
        });
      }

      // Update driver balance
      if (driverPaymentAmount > 0) {
        transaction.update(driverRef, {
          'account.amount': admin.firestore.FieldValue.increment(driverPaymentAmount)
        });
      }

      // Update escrow status
      transaction.update(escrowDoc.ref, { 
        status: 'dispute_resolved',
        resolvedAt: admin.firestore.FieldValue.serverTimestamp()
      });

      // Update dispute status
      transaction.update(disputeRef, {
        status: 'resolved',
        resolution,
        refundAmount: userRefundAmount,
        driverPaymentAmount,
        resolvedAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      });

      // Add to account history for both user and driver
      const historyEntry = {
        id: uuidv4(),
        timestamp: admin.firestore.FieldValue.serverTimestamp(),
        transactionType: 'dispute_resolution',
        rideId: disputeData.rideId,
        disputeId
      };

      if (userRefundAmount > 0) {
        transaction.update(userRef, {
          accountHistory: admin.firestore.FieldValue.arrayUnion({
            ...historyEntry,
            amount: userRefundAmount
          })
        });
      }

      if (driverPaymentAmount > 0) {
        transaction.update(driverRef, {
          accountHistory: admin.firestore.FieldValue.arrayUnion({
            ...historyEntry,
            amount: driverPaymentAmount
          })
        });
      }
    });

    res.json({ success: true, message: 'Dispute resolved successfully' });
  } catch (error) {
    logger.error('Error resolving dispute:', error);
    res.status(500).json({ error: 'Failed to resolve dispute' });
  }
});

// Schedule the automatic escrow release function
const schedule = require('node-schedule');

// Run every hour
schedule.scheduleJob('0 * * * *', releaseExpiredEscrows);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`);
});