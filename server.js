import express from 'express';
import pool from './db/db_spmpp.js';
import { sendOTP } from './nodemailer.js';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import cloudinary from './cloudinary.js';
import { ethers } from 'ethers';
import dotenv from 'dotenv';
dotenv.config();

// Load compiled contract ABI
const contractPath = "./artifacts/contracts/Voting.sol/Voting.json";
const contractJson = JSON.parse(fs.readFileSync(contractPath, "utf8"));

// Select RPC endpoint: prefer INFURA, fallback to local Hardhat
const rpcUrl = process.env.INFURA_URL || "http://127.0.0.1:8000";
const provider = new ethers.JsonRpcProvider(rpcUrl);

// Create signer
let signer;
if (process.env.PRIVATE_KEY) {
  signer = new ethers.Wallet(process.env.PRIVATE_KEY, provider);
} else {
  signer = provider.getSigner(); // use first local account
}

// Initialize contract
export async function getContractFromDB(pool) {
  const [rows] = await pool.query(`
    SELECT contract_address FROM voting_session 
    WHERE status IN ('UPCOMING', 'ONGOING', 'ENDED') ORDER BY session_id DESC LIMIT 1
  `);

  if (!rows.length) {
    throw new Error('No active voting session');
  }

  const contractAddress = rows[0].contract_address;
  return new ethers.Contract(contractAddress, contractJson.abi, signer);
}

// Confirm connection
(async () => {
  try {
    const network = await provider.getNetwork();
    const address = await signer.getAddress();
    console.log(`✅ Connected to network: ${network.name}`);
    console.log(`👤 Using signer: ${address}`);
  } catch (err) {
    console.error("❌ Blockchain connection failed:", err);
  }
})();

const app = express();
app.use(express.json({ limit: '10mb' })); 

// Automatically update voting session status based on time
async function updateVotingStatus() {
  try {
    const [rows] = await pool.query(`
      SELECT session_id, start_time, end_time, status 
      FROM voting_session
      ORDER BY session_id DESC LIMIT 1
    `);

    if (!rows || rows.length === 0) return null;

    const session = rows[0];
    const now = new Date();
    const start = new Date(session.start_time);
    const end = new Date(session.end_time);

    let newStatus = session.status;

    if (now < start) {
      newStatus = 'UPCOMING';
    } else if (now >= start && now <= end) {
      newStatus = 'ONGOING';
    } else if (now > end) {
      newStatus = 'ENDED';
    }

    // Only update the database if the status actually changed
    if (newStatus !== session.status) {
      await pool.query(
        `UPDATE voting_session SET status = ? WHERE session_id = ?`,
        [newStatus, session.session_id]
      );
      console.log(`Voting session ${session.session_id} status updated → ${newStatus}`);
    }

    return newStatus;
  } catch (err) {
    console.error('❌ updateVotingStatus Error:', err);
    return null;
  }
}

// Test route: check DB connection
app.get('/test-db', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT NOW() AS time');
    res.json({ success: true, serverTime: rows[0].time });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Test route: fetch all users
app.get('/users', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM users');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ✅ Convert ES module paths into __dirname (since __dirname doesn't exist in ESM by default)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ✅ Tell Express: "Serve everything in /public as a static website"
app.use(express.static(path.join(__dirname, 'public')));

// Request OTP
app.post('/auth/request-otp', async (req, res) => {
  const { email } = req.body;
  console.log("📩 OTP requested for:", email);

  if (!email.endsWith('@alfateh.upnm.edu.my')) {
    return res.status(400).json({ success: false, error: 'Must use Alfateh email' });
  }

  const [records] = await pool.query(
    'SELECT locked_until FROM otps WHERE email = ? ORDER BY created_on DESC LIMIT 1',
    [email]
  );

  if (records.length > 0) {
    const locked = records[0].locked_until;
    if (locked && new Date(locked) > new Date()) {
      const wait = Math.ceil((new Date(locked) - new Date()) / 60000);

      console.log(`⛔ ${email} is temporarily locked. Try again in ${wait} minute(s).`);
      
      return res.status(429).json({
        success: false,
        error: `Too many failed attempts. Please wait ${wait} minute(s) before requesting a new OTP.`
      });
    }
  }

  // Generate OTP
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const hashedOtp = await bcrypt.hash(otp, 10);
  const expiresAt = new Date(Date.now() + 5 * 60000);

  try {
    // Ensure user exists - auto register new email
    await pool.query(
      'INSERT IGNORE INTO users (email, role) VALUES (?, "VOTER")',
      [email]
    );

    await pool.query(
      'INSERT INTO otps (email, code, expires_at) VALUES (?, ?, ?)',
      [email, hashedOtp, expiresAt]
    );

    // Send OTP email
    await sendOTP(email, otp);

    res.json({ success: true, message: 'OTP sent to your email!' });
  } catch (err) {
    console.error("❌ OTP Request Error:", err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// OTP Verification
app.post('/auth/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  // Check for email lock
  const [records] = await pool.query(
    'SELECT locked_until FROM otps WHERE email = ? ORDER BY created_on DESC LIMIT 1',
    [email]
  );

  if (records.length > 0) {
    const locked = records[0].locked_until;
    if (locked && new Date(locked) > new Date()) {
      const wait = Math.ceil((new Date(locked) - new Date()) / 60000);
      return res.status(429).json({
        success: false,
        error: `Too many failed attempts. Please wait ${wait} minute(s) before requesting a new OTP.`
      });
    }
  }

  try {
    // Get the latest OTP for this email
    const [rows] = await pool.query(
      'SELECT * FROM otps WHERE email = ? ORDER BY expires_at DESC LIMIT 1',
      [email]
    );

    if (rows.length === 0) {
      return res.status(400).json({ success: false, error: 'OTP not found' });
    }

    const otpRecord = rows[0];

    // ✅ Check if currently locked
    if (otpRecord.locked_until && new Date(otpRecord.locked_until) > new Date()) {
      const waitMin = Math.ceil((new Date(otpRecord.locked_until) - new Date()) / 60000);
      return res.status(429).json({
        success: false,
        error: `Too many failed attempts. Try again in ${waitMin} minute(s).`
      });
    }

    // Check if expired
    if (new Date(otpRecord.expires_at) < new Date()) {
      return res.status(400).json({ success: false, error: 'OTP has expired' });
    }

    // Compare OTP
    const isMatch = await bcrypt.compare(otp, otpRecord.code);
    if (!isMatch) {
      const newAttempt = otpRecord.attempt_no + 1;
      const maxAttempts = 3;

      let lockedUntil = null;
      if (newAttempt >= maxAttempts) {
        lockedUntil = new Date(Date.now() + 5 * 60000); // lock for 5 mins
      }

      await pool.query(
        'UPDATE otps SET attempt_no = ?, locked_until = ? WHERE otp_id = ?',
        [newAttempt, lockedUntil, otpRecord.otp_id]
      );

      return res.status(400).json({
        success: false,
        error: newAttempt >= 3
          ? 'Too many incorrect attempts. Please try again in 5 minutes.'
          : 'Incorrect OTP'
      });
    }

    // ✅ OTP is valid → reset attempts
    await pool.query(
      'UPDATE otps SET attempt_no = 1, locked_until = NULL, used_at = NOW() WHERE otp_id = ?',
      [otpRecord.otp_id]
    );

    // ✅ OTP is valid
    const no_matric = email.split('@')[0];

    // Insert into `users` if not exists
    await pool.query(
      'INSERT IGNORE INTO users (email, role) VALUES (?, "VOTER")',
      [email]
    );

    console.log('✅ USER INSERT RAN FOR:', email);


    // Optionally insert into `verification` to prepare for selfie upload
    await pool.query(
      'INSERT IGNORE INTO verification (email) VALUES (?)',
      [email]
    );

     // 🔍 Fetch role from DB
    const [userRow] = await pool.query('SELECT role FROM users WHERE email = ?', [email]);
    const role = userRow[0]?.role || 'VOTER';

    console.log(`✅ OTP verified & user saved: ${email}`);

    res.json({ success: true, message: 'OTP verified successfully!', role });

  } catch (err) {
    console.error('❌ OTP Verify Error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Voter Status Check
app.post('/voter/status', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ success: false, error: 'Missing email' });

  try {
    const [rows] = await pool.query(
      'SELECT status, matric_card_url, selfie_url FROM verification WHERE email = ?',
      [email]
    );

    // No verification row yet → user hasn’t started eKYC
    if (!rows.length) {
      return res.json({ success: true, next: 'NOT_SUBMITTED' });
    }

    const { status, matric_card_url, selfie_url } = rows[0];

    if (status === 'VERIFIED') {
      return res.json({ success: true, next: 'VOTING_ALLOWED' });
    }

    if (status === 'VOTED') {
      return res.json({ success: true, next: 'ALREADY_VOTED' });
    }

    if (status === 'REJECTED') {
      return res.json({ success: true, next: 'ACCESS_DENIED' });
    }

    // status === 'PENDING'
    const hasUploaded = Boolean(matric_card_url) || Boolean(selfie_url);
    if (hasUploaded) {
      return res.json({ success: true, next: 'EKYC_PENDING' });
    }
    // Pending but no files yet → treat as not submitted
    return res.json({ success: true, next: 'NOT_SUBMITTED' });

  } catch (err) {
    console.error('❌ Voter Status Error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

//eKYC1 stored in Cloudinary
app.post('/upload/matric_card', async (req, res) => {
  const { email, image } = req.body;

  console.log('📩 Matric Card request received for:', email);

  try {
    const uploadResult = await cloudinary.uploader.upload(image, {
      folder: 'eKYC/matric',
      public_id: email.split('@')[0] + '_matric'
    });

    const url = uploadResult.secure_url;

    await pool.query(
      'UPDATE verification SET matric_card_url = ? WHERE email = ?',
      [url, email]
    );

    res.json({ success: true, message: 'Matric card uploaded!', url });

  } catch (err) {
    console.error("❌ Matric Upload Error:", err);
    res.status(500).json({ success: false, error: 'Matric upload failed' });
  }
});

//eKYC2 stored in Cloudinary
app.post('/upload/selfie', async (req, res) => {
  const { email, image } = req.body;

  console.log('📩 Selfie request received for:', email);

  if (!email || !image) {
    return res.status(400).json({ success: false, error: 'Missing email or image' });
  }

  try {
    const uploadResult = await cloudinary.uploader.upload(image, {
      folder: 'eKYC/selfie',
      public_id: email.split('@')[0] + '_selfie',
    });

    const imageUrl = uploadResult.secure_url;

    await pool.query(
      'UPDATE verification SET selfie_url = ?, status = "PENDING" WHERE email = ?',
      [imageUrl, email]
    );

    res.json({ success: true, message: 'Selfie uploaded successfully!', imageUrl });

  } catch (err) {
    console.error("❌ Selfie Upload Error:", err);
    res.status(500).json({ success: false, error: 'Selfie upload failed' });
  }
});


// Admin Dashboard
app.use('/uploads', express.static('uploads'));

app.get('/admin/pending-voters', async (req, res) => {
  const [rows] = await pool.query('SELECT email, status, matric_card_url, selfie_url FROM verification WHERE status = "PENDING"');
  res.json(rows);
});

// Admin approves or rejects voter
app.post('/admin/verify-voter', async (req, res) => {
  const { email, status } = req.body;

  try {
    await pool.query(
      'UPDATE verification SET status = ?, verified_on = NOW() WHERE email = ?',
      [status, email]
    );

    console.log(`✅ ${email} marked as ${status}`);
    res.json({ success: true, message: `Voter marked as ${status}` });
  } catch (err) {
    console.error('❌ Verify Voter Error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Admin: Get user list with optional role/search filter
app.get('/admin/users', async (req, res) => {
  const { role, search } = req.query;
  let query = 'SELECT email, role FROM users';
  const params = [];

  if (role || search) {
    query += ' WHERE ';
    const conditions = [];

    if (role) {
      conditions.push('role = ?');
      params.push(role);
    }

    if (search) {
      conditions.push('email LIKE ?');
      params.push(`%${search}%`);
    }

    query += conditions.join(' AND ');
  }

  try {
    const [rows] = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    console.error('❌ Fetch users error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Admin: Update a user's role
app.patch('/admin/users/:email/role', async (req, res) => {
  const email = decodeURIComponent(req.params.email);
  const { role } = req.body;

  if (!['ADMIN', 'CANDIDATE', 'VOTER'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role specified' });
  }

  try {
    const [result] = await pool.query(
      'UPDATE users SET role = ? WHERE email = ?',
      [role, email]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ message: `Role updated to ${role}` });
  } catch (err) {
    console.error('❌ Update role error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Admin: Remove candidate
app.delete('/admin/remove-candidate/:no_matric', async (req, res) => {
  const no_matric = parseInt(req.params.no_matric);

  try {
    // Delete candidate record
    const [candidateRow] = await pool.query(
      'SELECT candidate_id FROM candidates WHERE no_matric = ?',
      [no_matric]
    );

    if (candidateRow.length === 0) {
      return res.status(404).json({ success: false, error: 'Candidate not found.' });
    }

    const candidateId = candidateRow[0].candidate_id;

    await pool.query('DELETE FROM votes WHERE candidate_id = ?', [candidateId]);

    await pool.query('DELETE FROM candidates WHERE no_matric = ?', [no_matric]);

    // Optional: revert their user role to VOTER (assuming same email pattern)
    const email = `${no_matric}@alfateh.upnm.edu.my`;
    await pool.query(
      'UPDATE users SET role = "VOTER" WHERE email = ?',
      [email]
    );

    res.json({ success: true, message: 'Candidate removed successfully.' });
  } catch (err) {
    console.error('❌ Remove candidate error:', err);
    res.status(500).json({ success: false, error: 'Failed to remove candidate.' });
  }
});

app.post('/admin/add-candidate', async (req, res) => {
  const { no_matric, name, course, profileImage, manifestoImage } = req.body;
  const email = `${no_matric}@alfateh.upnm.edu.my`;

  try {
    let profileUrl = null;
    let manifestoUrl = null;

    if (profileImage) {
      const result = await cloudinary.uploader.upload(profileImage, {
        folder: 'candidates/profile',
        public_id: `${no_matric}_profile`,
        overwrite: true
      });
      profileUrl = result.secure_url;
    }

    if (manifestoImage) {
      const result = await cloudinary.uploader.upload(manifestoImage, {
        folder: 'candidates/manifesto',
        public_id: `${no_matric}_manifesto`,
        overwrite: true
      });
      manifestoUrl = result.secure_url;
    }

    // ✅ Insert into MySQL
    await pool.query(
      `INSERT INTO candidates (no_matric, email, name, course, profile_pic_url, manifesto_url)
       VALUES (?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
       name = VALUES(name),
       email = VALUES(email),
       course = VALUES(course),
       profile_pic_url = VALUES(profile_pic_url),
       manifesto_url = VALUES(manifesto_url),
       updated_on = NOW()`,
      [no_matric, email, name, course, profileUrl, manifestoUrl]
    );

    // ✅ Set role = CANDIDATE in user table
    await pool.query(
      'UPDATE users SET role = "CANDIDATE" WHERE email = ?',
      [email]
    );

    // ✅ Add to Blockchain
    try {
      const contract = await getContractFromDB(pool);
      const tx = await contract.addCandidate(name);
      await tx.wait();

       // Get latest count to determine blockchain ID (1-based)
      const count = await contract.candidateCount();
      const blockchainIndex = Number(count);

      // Save blockchain_id to MySQL
      await pool.query(
        'UPDATE candidates SET blockchain_id = ? WHERE no_matric = ?',
        [blockchainIndex, no_matric]
      );

      console.log(`✅ Blockchain: Added ${name} with ID ${blockchainIndex}`);
    } catch (err) {
      console.error(`⚠️ Blockchain addCandidate failed:`, err);
    }

    res.json({ success: true, message: 'Candidate added successfully!' });

  } catch (err) {
    console.error('❌ Admin add-candidate error:', err);
    res.status(500).json({ success: false, error: 'Failed to add candidate' });
  }
});

// Create Voting Session
app.post('/admin/create-voting', async (req, res) => {
  try {
    const { title, start, end, contract_address, admin_email } = req.body;

    // Validate inputs
    if (!title || !start || !end || !contract_address) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing required fields (title, start, end, contract_address)' 
      });
    }

    const formatToJS = (dateStr) => {
      const [date, time] = dateStr.split(' ');
      const [day, month, year] = date.split('/');
      return `${year}-${month}-${day}T${time}:00`;
    };

    const startTime = new Date(formatToJS(start));
    const endTime = new Date(formatToJS(end));
    const now = new Date();

    // Block past start time
    if (startTime <= now) {
      return res.status(400).json({
        success: false,
        error: 'Start time must be in the future'
      });
    }

    // End must be after start
    if (endTime <= startTime) {
      return res.status(400).json({
        success: false,
        error: 'End time must be after start time'
      });
    }

    // Clear votes table
    await pool.query("DELETE FROM votes");
    // Clear candidates table
    await pool.query("DELETE FROM candidates");
    // Update all users with role CANDIDATE to VOTER
    await pool.query("UPDATE users SET role = 'VOTER' WHERE role = 'CANDIDATE'");
    // Reset verification statuses from VOTED to VERIFIED
    await pool.query("UPDATE verification SET status = 'VERIFIED' WHERE status = 'VOTED'");
    // Clear previous voting sessions
    await pool.query("UPDATE voting_session SET status = 'ENDED' WHERE status != 'ONGOING' OR status = 'UPCOMING'");
    
    const initialStatus = 'UPCOMING';

    await pool.query(
      `INSERT INTO voting_session (title, start_time, end_time, contract_address, status, created_by)
      VALUES (?, ?, ?, ?, ?, ?)`,
      [title, start, end, contract_address, initialStatus, admin_email]
    );

    console.log('✅ Voting session created as UPCOMING');

    // Update status immediately
    await updateVotingStatus();
    res.json({ success: true, message: 'New Voting Session Created. All Candidates Reset to Voters!' });

  } catch (err) {
    console.error("❌ Create Voting Error:", err);
    res.status(500).json({ success: false, error: "Failed to create voting session" });
  }  
});

// Deploy Contract Address
app.post('/admin/deploy-contract', async (req, res) => {
  try {
    console.log("🚀 Starting contract deployment...");

    // 1. Create a Contract Factory using your compiled ABI and Bytecode
    const factory = new ethers.ContractFactory(
      contractJson.abi,
      contractJson.bytecode,
      signer // This uses the signer created from your PRIVATE_KEY
    );

    // 2. Send the deployment transaction
    const contract = await factory.deploy();

    // 3. Wait for the transaction to be mined on the blockchain
    await contract.waitForDeployment();

    const newAddress = await contract.getAddress();
    console.log(`✅ Contract deployed successfully to: ${newAddress}`);

    res.json({ success: true, address: newAddress });
  } catch (err) {
    console.error("❌ Deployment failed:", err);
    res.status(500).json({ success: false, error: "Deployment failed: " + err.message });
  }
});

// Extend voting end time
app.post('/admin/extend-voting', async (req, res) => {
  try {
    const { newEndTime } = req.body;

    // Reformat DD/MM/YYYY HH:mm to YYYY-MM-DD HH:mm for JS
    const [date, time] = newEndTime.split(' ');
    const [day, month, year] = date.split('/');
    const validDateString = `${year}-${month}-${day}T${time}:00`; 

    // Only update latest session
    const [rows] = await pool.query(`
      SELECT session_id 
      FROM voting_session 
      ORDER BY session_id DESC 
      LIMIT 1
    `);

    if (rows.length === 0) {
      return res.status(400).json({ success: false, error: 'No voting session exists' });
    }

    const votingId = rows[0].session_id;
    const startTime = new Date(rows[0].start_time);
    const endTime = new Date(validDateString);
    const now = new Date();

    let newStatus = 'UPCOMING';
    if (now >= startTime && now <= endTime) {
      newStatus = 'ONGOING';
    } else if (now > endTime) {
      newStatus = 'ENDED';
    }

    // Update end_time and status
    await pool.query(
      'UPDATE voting_session SET end_time = ?, status = ? WHERE session_id = ?',
      [newEndTime, newStatus, votingId]
    );

    res.json({ success: true, message: `Voting time extended. New status: ${newStatus}` });

  } catch (err) {
    console.error('❌ Extend voting error:', err);
    res.status(500).json({ success: false, error: 'Failed to update end time' });
  }
});

// Admin: Get results only after voting has ended
app.get('/admin/results', async (req, res) => {
  try {
    // Get latest voting session
    const [sessionRows] = await pool.query(
      'SELECT end_time, status FROM voting_session ORDER BY session_id DESC LIMIT 1'
    );

    if (sessionRows.length === 0) {
      return res.status(400).json({ error: 'No voting session found' });
    }

    // Use Numeric Timestamps for accurate comparison
    const endTime = new Date(sessionRows[0].end_time);
    const endTS = endTime.getTime();
    const nowTS = Date.now();

    // Ensure only show results if status is ENDED
    if (sessionRows[0].status !== 'ENDED' && nowTS < endTS) {
      return res.status(403).json({ error: 'Voting is still ongoing. Results are locked.' });
    }

    // Fetch candidates and blockchain results
    const [candidates] = await pool.query(
      'SELECT candidate_id, no_matric, name, course, blockchain_id FROM candidates ORDER BY name'
    );

    // Load contract from DB
    const contract = await getContractFromDB(pool);

    const results = await Promise.all(
      candidates.map(async (c) => {
        let count = 0;
        try {
          if (c.blockchain_id) {
            // Check if blockchain_id is correct
            const votes = await contract.getVotes(c.blockchain_id);
            count = votes.toString();
          }
        } catch (err) {
          console.error(`❌ Failed to fetch blockchain votes for ${c.name}`, err);
        }
        return {
          no_matric: c.no_matric,
          name: c.name,
          course: c.course,
          votes: count,
        };
      })
    );

    res.json(results);
  } catch (err) {
    console.error('❌ Failed to load results:', err);
    res.status(500).json({ error: 'Blockchain result error' });
  }
});

// Candidate Registration + Edit Profile
app.post('/candidate/submit', async (req, res) => {
  const { email, name, course, profileImage, manifestoImage } = req.body;
  const no_matric = parseInt(email.split('@')[0]);

  try {
    let profileUrl = null;
    let manifestoUrl = null;

    if (profileImage) {
      const result = await cloudinary.uploader.upload(profileImage, {
        folder: 'candidates/profile',
        public_id: `${no_matric}_profile`,
        overwrite: true
      });
      profileUrl = result.secure_url;
    }

    if (manifestoImage) {
      const result = await cloudinary.uploader.upload(manifestoImage, {
        folder: 'candidates/manifesto',
        public_id: `${no_matric}_manifesto`,
        overwrite: true
      });
      manifestoUrl = result.secure_url;
    }

    // Check if candidate already exists
    const [rows] = await pool.query(
      'SELECT blockchain_id FROM candidates WHERE no_matric = ?',
      [no_matric]
    );

    const exists = rows.length > 0;
    const candidate = rows[0];

    if (exists) {
      // UPDATE existing candidate
      await pool.query(`
        UPDATE candidates 
        SET name = ?, course = ?, 
            ${profileUrl ? 'profile_pic_url = ?, ' : ''}
            ${manifestoUrl ? 'manifesto_url = ?, ' : ''}
            updated_on = NOW()
        WHERE no_matric = ?`,
      [
        name,
        course,
        ...(profileUrl ? [profileUrl] : []),
        ...(manifestoUrl ? [manifestoUrl] : []),
        no_matric
      ]);
    } else {
      // INSERT new candidate
      await pool.query(
        `INSERT INTO candidates (no_matric, name, course, profile_pic_url, manifesto_url)
         VALUES (?, ?, ?, ?, ?)`,
        [no_matric, name, course, profileUrl, manifestoUrl]
      );
    }

    // Determine if blockchain registration is needed
    const needsBlockchain =
      !exists || !candidate.blockchain_id || candidate.blockchain_id === 0;

    if (needsBlockchain) {
      try {
        const contract = await getContractFromDB(pool);
        const tx = await contract.addCandidate(name);
        await tx.wait();

        const count = await contract.candidateCount();
        const blockchainIndex = Number(count);

        await pool.query(
          'UPDATE candidates SET blockchain_id = ? WHERE no_matric = ?',
          [blockchainIndex, no_matric]
        );

        console.log(`✅ Blockchain updated → ID ${blockchainIndex}`);
      } catch (err) {
        console.error("❌ Blockchain addCandidate failed:", err);
      }
    }

    res.json({ success: true, message: 'Candidate profile updated!' });

  } catch (err) {
    console.error('❌ Candidate Upload Error:', err);
    res.status(500).json({ success: false, error: 'Upload failed.' });
  }
});

// Get all candidates
app.get('/candidates', async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT candidate_id, no_matric, name, course, profile_pic_url, manifesto_url FROM candidates ORDER BY name'
    );
    res.json(rows);
  } catch (err) {
    console.error('❌ Fetch candidates error:', err);
    res.status(500).json({ success: false, error: 'Failed to load candidates' });
  }
});

// Submit Vote
app.post('/vote/submit', async (req, res) => {
  const { email, candidate_id } = req.body;

  try {
    const statusNow = await updateVotingStatus();
    const [latestSession] = await pool.query(`
      SELECT session_id, start_time, end_time, status FROM voting_session
      ORDER BY session_id DESC LIMIT 1
    `);

    if (!latestSession.length || latestSession[0].status !== 'ONGOING') {
      return res.status(400).json({ success: false, error: 'Voting is not active' });
    }

    const { session_id: votingSessionId } = latestSession[0];

    if (statusNow !== 'ONGOING') {
      return res.status(400).json({ success: false, error: 'Voting is not active' });
    }

    const [rows] = await pool.query(
      'SELECT blockchain_id FROM candidates WHERE candidate_id = ?',
      [candidate_id]
    );

    if (!rows.length || !rows[0].blockchain_id) {
      return res.status(400).json({ success: false, error: 'Candidate not found or missing blockchain ID' });
    }

    const blockchainId = rows[0].blockchain_id;

    if (blockchainId <= 0) {
      return res.status(400).json({ success: false, error: 'Invalid candidate ID' });
    }

    // Mark voter as VOTED
    await pool.query(
      'UPDATE verification SET status = "VOTED", voted_on = NOW() WHERE email = ?',
      [email]
    );

    // Cast the vote on blockchain
    const contract = await getContractFromDB(pool);
    const tx = await contract.voteAsAdmin(email, blockchainId);
    await tx.wait();
    const txHash = tx.hash;

    // Generate secure, anonymous ballot token
    const ballot_token = crypto.randomUUID();

    // Save to MySQL `votes` table
    await pool.query(
      'INSERT INTO votes (session_id, ballot_token, candidate_id, transaction_hash) VALUES (?, ?, ?, ?)',
      [votingSessionId, ballot_token, candidate_id, txHash]
    );

    console.log(`✅ Vote saved: ${email}, Blockchain ID: ${blockchainId}, TxHash: ${txHash}`);

    // Return confirmation to frontend
    res.json({
      success: true,
      message: 'Vote recorded on blockchain!',
      txHash,
      ballot_token
    });

  } catch (err) {
    console.error('❌ Vote error:', err);
    res.status(500).json({ success: false, error: 'Vote Denied' });
  }
});

// Check Candidate Count
app.get('/debug/candidate-count', async (req, res) => {
  try {
    const count = await contract.candidateCount();
    res.json({ success: true, count: count.toString() });
  } catch (err) {
    console.error('❌ Error fetching candidate count:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// 🕒 Auto update voting session status every 1 sec
setInterval(async () => {
  try {
    await updateVotingStatus();
  } catch (err) {
    console.error('❌ Periodic status update failed:', err);
  }
}, 1 * 1000); // 1 minute

app.listen(8000, () => {
  console.log('Server running on https://localhost');
});

  


