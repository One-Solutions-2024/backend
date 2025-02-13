// Import required modules
const express = require("express");
const { Pool } = require("pg");
const cors = require("cors");
const helmet = require("helmet");
const { body, validationResult } = require("express-validator");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
const fs = require("fs").promises;
const bcrypt = require("bcrypt");
const WebSocket = require("ws"); // Add WebSocket support
require("dotenv").config(); // Load environment variables

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "MY_SECRET_TOKEN"; // JWT secret from environment variables

// Initialize PostgreSQL pool using environment variable
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // This bypasses certificate verification
  },
});
// Initialize Express app
const app = express();

// Create WebSocket server
const wss = new WebSocket.Server({ noServer: true });

// Backend WebSocket handling
wss.on('connection', (ws, req) => {
  console.log("New WebSocket connection");
  const token = req.headers.authorization?.split(' ')[1];

  if (token) {
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (!err) {
        ws.userPhone = user.phone; // Attach phone instead of ID
      }
    });
  }

  ws.on('message', (message) => {
    const data = JSON.parse(message);
    switch (data.type) {
      case 'register_phone':
        ws.userPhone = data.phone;
        break;
      case 'direct_message':
        handleDirectMessage(data);
        break;
    }
  });
});

// Middleware
app.use(express.json());
app.use(cors());
app.use(helmet()); // Basic security headers
app.use(morgan("combined")); // Logging
// Configure CORS for external access
const corsOptions = {
  origin: "*", // Replace "*" with specific domains for production
};
app.use(cors(corsOptions));


const getClientIp = (req) => {
  const ip = req.headers["x-forwarded-for"] || req.connection.remoteAddress;
  return ip.split(",")[0].trim(); // Handles proxies and IPv6
};

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: "Token required" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user; // Save decoded token data (e.g., user id and role)
    next();
  });
};
const authorizeAdmin = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
};


// Modified admin registration route
app.post(
  "/api/admin/register",
  [
    body("adminname").notEmpty(),
    body("username").notEmpty(),
    body("password").isLength({ min: 6 }),
    body("phone").isMobilePhone(),
    body("admin_image_link").isURL(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { adminname, username, password, phone, admin_image_link } = req.body;

    try {
      // Check if any admin exists
      const adminCount = await pool.query("SELECT COUNT(*) FROM admin;");
      const isFirstAdmin = adminCount.rows[0].count === '0'; // Check if it's the first admin

      // Check if username or phone exists
      const existingAdmin = await pool.query(
        "SELECT * FROM admin WHERE username = $1 OR phone = $2;",
        [username, phone]
      );
      if (existingAdmin.rows.length) {
        return res.status(400).json({ error: "Username or phone already exists" });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Determine status, is_approved, and created_by
      const status = isFirstAdmin ? "approved" : "pending";
      const isApproved = isFirstAdmin;
      const createdBy = isFirstAdmin ? null : req.user?.id; // First admin has no creator

      const insertAdminQuery = `
        INSERT INTO admin (adminname, username, password, phone, admin_image_link, status, is_approved, created_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id, status, is_approved;
      `;

      const newAdmin = await pool.query(insertAdminQuery, [
        adminname,
        username,
        hashedPassword,
        phone,
        admin_image_link || null,
        status,
        isApproved,
        createdBy
      ]);

      const responseData = {
        message: isFirstAdmin
          ? "First admin registered successfully"
          : "Registration submitted for approval",
        adminId: newAdmin.rows[0].id,
        status: newAdmin.rows[0].status,
        is_approved: newAdmin.rows[0].is_approved
      };

      res.status(201).json(responseData);
    } catch (error) {
      console.error(`Error registering admin: ${error.message}`);
      res.status(500).json({ error: "Registration failed" });
    }
  }
);


// Modified admin login route
// Update the login route to include phone in JWT
app.post("/api/admin/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const adminResult = await pool.query(
      "SELECT * FROM admin WHERE username = $1;",
      [username]
    );

    if (!adminResult.rows.length) {
      return res.status(401).json({ error: "Invalid credentials or Please Register" });
    }

    const admin = adminResult.rows[0];

    if (admin.status !== 'approved') {
      return res.status(403).json({ error: "Account pending approval" });
    }

    const passwordMatch = await bcrypt.compare(password, admin.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid Passward" });
    }

    // Include phone in JWT
    const token = jwt.sign(
      {
        id: admin.id,
        username: admin.username,
        phone: admin.phone,  // Add this line
        role: "admin"
      },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login successful",
      token,
      admin: {
        adminname: admin.adminname,
        username: admin.username,
        phone: admin.phone,
        admin_image_link: admin.admin_image_link,
        status: admin.status
      }
    });
  } catch (error) {
    console.error(`Login error: ${error.message}`);
    res.status(500).json({ error: "Login failed" });
  }
});

// New route to get pending admins (admin access only)
app.get("/api/admin/pending", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const pendingAdmins = await pool.query(
      "SELECT id, adminname, username, phone, admin_image_link, createdat FROM admin WHERE status = 'pending';"
    );
    res.json(pendingAdmins.rows);
  } catch (error) {
    console.error(`Error fetching pending admins: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve pending admins" });
  }
});

// New route to approve admins (admin access only)
app.put("/api/admin/approve/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;

  // Validate ID (Ensure it's a positive number)
  if (isNaN(id) || id <= 0) {
    return res.status(400).json({ error: "Invalid admin ID" });
  }

  try {
    // Check if the admin exists and is still pending approval
    const checkAdmin = await pool.query(
      "SELECT * FROM admin WHERE id = $1 AND status = 'pending';",
      [id]
    );

    if (checkAdmin.rows.length === 0) {
      return res.status(404).json({ error: "Admin not found or already approved" });
    }

    // Approve admin and set created_by (who approved them)
    const result = await pool.query(
      "UPDATE admin SET status = 'approved', is_approved = TRUE, created_by = $1 WHERE id = $2 RETURNING *;",
      [req.user.id, id]
    );

    res.json({
      message: "Admin approved successfully",
      admin: result.rows[0],
    });
  } catch (error) {
    console.error(`Approval error: ${error.message}`);
    res.status(500).json({ error: "Approval failed" });
  }
});


// New route to reject admins (admin access only)
app.put("/api/admin/reject/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      "DELETE FROM admin WHERE id = $1 RETURNING *;",
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    res.json({ message: "Admin rejected and removed from the system" });
  } catch (error) {
    console.error(`Rejection error: ${error.message}`);
    res.status(500).json({ error: "Rejection failed" });
  }
});

// ... (rest of the code remains the same)

// Initialize DB and start server
const initializeDbAndServer = async () => {
  try {
    // Update the admin table creation to include 'status' and 'created_by'
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin (
        id SERIAL PRIMARY KEY,
        adminname TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        phone TEXT UNIQUE NOT NULL,
        admin_image_link TEXT,
        is_approved BOOLEAN DEFAULT FALSE,
        status TEXT NOT NULL DEFAULT 'pending',
        created_by INT REFERENCES admin(id), -- This should work as long as 'id' is a primary key
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS job (
        id SERIAL PRIMARY KEY,
        companyname TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        apply_link TEXT NOT NULL,
        image_link TEXT NOT NULL,
        url TEXT NOT NULL,
        salary TEXT NOT NULL,
        location TEXT NOT NULL,
        job_type TEXT NOT NULL,
        experience TEXT NOT NULL,
        batch TEXT NOT NULL,
        job_uploader TEXT NOT NULL,
        approved_by INT REFERENCES admin(id),
        created_by INT REFERENCES admin(id), -- This field references the admin who created the job
        status VARCHAR(20) DEFAULT 'pending',
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS job_viewers (
        id SERIAL PRIMARY KEY,
        job_id INT NOT NULL REFERENCES job(id),
        ip_address TEXT NOT NULL,
        viewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (job_id, ip_address)
    );
    `);
    // Create popup_content table
    await pool.query(`
          CREATE TABLE IF NOT EXISTS popup_content (
          id SERIAL PRIMARY KEY,
          popup_heading TEXT NOT NULL,
          popup_text TEXT NOT NULL,
          popup_link TEXT NOT NULL,
          popup_belowtext TEXT NOT NULL,
          popup_routing_link TEXT NOT NULL,
          created_by INT REFERENCES admin(id),
          approved_by INT REFERENCES admin(id),
          status VARCHAR(20) DEFAULT 'pending',
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Add tables for chat functionality
    await pool.query(`
      CREATE TABLE IF NOT EXISTS chat_rooms (
        id SERIAL PRIMARY KEY,
        room_name TEXT NOT NULL UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS chat_messages (
        id SERIAL PRIMARY KEY,
        room_id INT NOT NULL REFERENCES chat_rooms(id),
        sender_id INT NOT NULL REFERENCES admin(id),
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Create table for direct messages (one-to-one chats)
    await pool.query(`
        CREATE TABLE IF NOT EXISTS direct_messages (
          id SERIAL PRIMARY KEY,
          sender_phone TEXT NOT NULL REFERENCES admin(phone),
          recipient_phone TEXT NOT NULL REFERENCES admin(phone),
          message TEXT NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);

            // Add new tables
      await pool.query(`
        CREATE TABLE IF NOT EXISTS admin_sessions (
          id SERIAL PRIMARY KEY,
          admin_id INT REFERENCES admin(id),
          start_time TIMESTAMP NOT NULL,
          end_time TIMESTAMP,
          duration INTERVAL
        );
      `);

      await pool.query(`
        CREATE TABLE IF NOT EXISTS monthly_reports (
          id SERIAL PRIMARY KEY,
          admin_id INT REFERENCES admin(id),
          month INT,
          year INT,
          total_time BIGINT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `);


    const popUpCountResult = await pool.query("SELECT COUNT(*) as count FROM popup_content");
    const popupCount = popUpCountResult.rows[0].count;

    if (popupCount == 0) {
      try {
        const data = await fs.readFile("pops.json", "utf8");
        const popList = JSON.parse(data); // popList should be an array

        if (!Array.isArray(popList)) {
          throw new Error("pops.json content is not an array");
        }
        const insertPopQuery = `
          INSERT INTO popup_content (popup_heading, popup_text, popup_link, popup_belowtext, popup_routing_link)
          VALUES ($1, $2, $3, $4, $5);
        `;
        for (const popup_content of popList) {
          await pool.query(insertPopQuery, [
            popup_content.popup_heading,
            popup_content.popup_text,
            popup_content.popup_link,
            popup_content.popup_belowtext,
            popup_content.popup_routing_link,
          ]);
        }
        console.log("Pop Data Imported Successfully");
      } catch (error) {
        console.error("Error reading or processing pops.json:", error.message);
        throw error; // rethrow the error to prevent the server from starting
      }
    }
    // Insert jobs if table is empty
    const jobsCountResult = await pool.query("SELECT COUNT(*) as count FROM job;");
    const jobsCount = jobsCountResult.rows[0].count;

    if (jobsCount == 0) {
      const data = await fs.readFile("jobs.json", "utf8");
      const jobList = JSON.parse(data);

      const insertJobQuery = `
         INSERT INTO job (companyname, title, description, apply_link, image_link, url, salary, location, job_type, experience, batch, job_uploader)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);
       `;

      for (const job of jobList) {
        await pool.query(insertJobQuery, [
          job.companyname,
          job.title,
          job.description,
          job.apply_link,
          job.image_link,
          job.url,
          job.salary,
          job.location,
          job.job_type,
          job.experience,
          job.batch,
          job.job_uploader,
        ]);
      }
      console.log("Job data has been imported successfully.");
    }


    // Check if there are any admins in the table
    const adminCountResult = await pool.query("SELECT COUNT(*) as count FROM admin;");
    const adminCount = adminCountResult.rows[0].count;
    if (adminCount == 0) {
      const data = await fs.readFile("admin.json", "utf8");
      const adminList = JSON.parse(data);
      const insertAdminQuery = `
         INSERT INTO admin (adminname, username, password, phone, admin_image_link)
         VALUES ($1, $2, $3, $4, $5);
       `;

      for (const admin of adminList) {
        await pool.query(insertAdminQuery, [
          admin.adminname,
          admin.username,
          admin.password,
          admin.phone,
          admin.admin_image_link,
        ]);
      }
      console.log("Admin data has been imported successfully.");
    }


    // Start server
    const server = app.listen(PORT, () => {
      console.log(`Server is running on http://localhost:${PORT}/`);
    });

    // Upgrade HTTP server to WebSocket
    server.on("upgrade", (request, socket, head) => {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit("connection", ws, request);
      });
    });

  } catch (error) {
    console.error(`Error initializing the database: ${error.message}`);
    process.exit(1);
  }
};

// Session endpoints
app.get('/api/session/status', authenticateToken, async (req, res) => {
  try {
    const adminId = req.user.id;
    const now = new Date();
    const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());

    // Get current session
    const activeSession = await pool.query(
      `SELECT * FROM admin_sessions 
       WHERE admin_id = $1 AND end_time IS NULL`,
      [adminId]
    );

    // Calculate today's total
    const todayTotal = await pool.query(
      `SELECT SUM(EXTRACT(EPOCH FROM duration)) as total 
       FROM admin_sessions 
       WHERE admin_id = $1 AND start_time >= $2`,
      [adminId, todayStart]
    );

    res.json({
      isOnline: activeSession.rows.length > 0,
      todayTotal: todayTotal.rows[0].total || 0,
      currentSessionStart: activeSession.rows[0]?.start_time
    });
  } catch (error) {
    console.error('Error getting session status:', error);
    res.status(500).json({ error: 'Failed to get session status' });
  }
});

app.post('/api/session/start', authenticateToken, async (req, res) => {
  try {
    const adminId = req.user.id;
    const existingSession = await pool.query(
      'SELECT * FROM admin_sessions WHERE admin_id = $1 AND end_time IS NULL',
      [adminId]
    );

    if (existingSession.rows.length > 0) {
      return res.status(400).json({ error: 'Session already active' });
    }

    const startTime = new Date();
    await pool.query(
      'INSERT INTO admin_sessions (admin_id, start_time) VALUES ($1, $2)',
      [adminId, startTime]
    );

    res.json({ message: 'Session started', startTime });
  } catch (error) {
    console.error('Error starting session:', error);
    res.status(500).json({ error: 'Failed to start session' });
  }
});

app.post('/api/session/end', authenticateToken, async (req, res) => {
  try {
    const adminId = req.user.id;
    const activeSession = await pool.query(
      'SELECT * FROM admin_sessions WHERE admin_id = $1 AND end_time IS NULL',
      [adminId]
    );

    if (activeSession.rows.length === 0) {
      return res.status(400).json({ error: 'No active session' });
    }

    const endTime = new Date();
    const startTime = activeSession.rows[0].start_time;
    const duration = Math.floor((endTime - startTime) / 1000);

    await pool.query(
      `UPDATE admin_sessions 
       SET end_time = $1, duration = $2 * INTERVAL '1 second'
       WHERE id = $3`,
      [endTime, duration, activeSession.rows[0].id]
    );

    res.json({ message: 'Session ended', duration });
  } catch (error) {
    console.error('Error ending session:', error);
    res.status(500).json({ error: 'Failed to end session' });
  }
});

// Monthly report job
const schedule = require('node-schedule');
schedule.scheduleJob('59 23 L * *', async () => {
  try {
    const now = new Date();
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
    const monthEnd = new Date(now.getFullYear(), now.getMonth() + 1, 0);

    const result = await pool.query(
      `SELECT admin_id, SUM(EXTRACT(EPOCH FROM duration)) as total
       FROM admin_sessions
       WHERE start_time BETWEEN $1 AND $2
       GROUP BY admin_id`,
      [monthStart, monthEnd]
    );

    for (const row of result.rows) {
      await pool.query(
        `INSERT INTO monthly_reports (admin_id, month, year, total_time)
         VALUES ($1, $2, $3, $4)`,
        [row.admin_id, now.getMonth() + 1, now.getFullYear(), row.total]
      );
    }
  } catch (error) {
    console.error('Error generating monthly report:', error);
  }
});

// Chat Routes
app.post("/api/chat/rooms", authenticateToken, authorizeAdmin, async (req, res) => {
  const { room_name } = req.body;

  try {
    const insertRoomQuery = `
      INSERT INTO chat_rooms (room_name)
      VALUES ($1)
      RETURNING *;
    `;
    const newRoom = await pool.query(insertRoomQuery, [room_name]);
    res.status(201).json(newRoom.rows[0]);
  } catch (error) {
    console.error(`Error creating chat room: ${error.message}`);
    res.status(500).json({ error: "Failed to create chat room" });
  }
});

app.get("/api/chat/rooms", authenticateToken, async (req, res) => {
  try {
    const roomsQuery = "SELECT * FROM chat_rooms ORDER BY created_at DESC;";
    const rooms = await pool.query(roomsQuery);
    res.json(rooms.rows);
  } catch (error) {
    console.error(`Error fetching chat rooms: ${error.message}`);
    res.status(500).json({ error: "Failed to fetch chat rooms" });
  }
});

app.post("/api/chat/messages", authenticateToken, async (req, res) => {
  const { room_id, message } = req.body;
  const sender_id = req.user.id;

  try {
    const insertMessageQuery = `
      INSERT INTO chat_messages (room_id, sender_id, message)
      VALUES ($1, $2, $3)
      RETURNING *;
    `;
    const newMessage = await pool.query(insertMessageQuery, [room_id, sender_id, message]);
    res.status(201).json(newMessage.rows[0]);
  } catch (error) {
    console.error(`Error sending message: ${error.message}`);
    res.status(500).json({ error: "Failed to send message" });
  }
});

app.get("/api/chat/messages/:room_id", authenticateToken, async (req, res) => {
  const { room_id } = req.params;

  try {
    const messagesQuery = `
      SELECT cm.*, a.adminname, a.admin_image_link
      FROM chat_messages cm
      JOIN admin a ON cm.sender_id = a.id
      WHERE cm.room_id = $1
      ORDER BY cm.created_at ASC;
    `;
    const messages = await pool.query(messagesQuery, [room_id]);
    res.json(messages.rows);
  } catch (error) {
    console.error(`Error fetching messages: ${error.message}`);
    res.status(500).json({ error: "Failed to fetch messages" });
  }
});
// GET direct messages endpoint 
// In your backend routes (replace ID-based with phone-based)
// Get direct messages between two users
app.get(
  "/api/chat/direct-messages/:senderPhone/:recipientPhone",
  authenticateToken,
  async (req, res) => {
    const { senderPhone, recipientPhone } = req.params;

    try {
      const messagesQuery = `
        SELECT dm.*, a.adminname, a.admin_image_link
        FROM direct_messages dm
        JOIN admin a ON dm.sender_phone = a.phone
        WHERE (dm.sender_phone = $1 AND dm.recipient_phone = $2)
           OR (dm.sender_phone = $2 AND dm.recipient_phone = $1)
        ORDER BY dm.created_at ASC;
      `;
      const result = await pool.query(messagesQuery, [senderPhone, recipientPhone]);
      res.json(result.rows);
    } catch (error) {
      console.error("Error fetching direct messages:", error.message);
      res.status(500).json({ error: "Failed to fetch direct messages" });
    }
  }
);

// Send direct message
// Update direct message handler with validation
app.post("/api/chat/direct-messages", authenticateToken, async (req, res) => {
  const { recipient_phone, message } = req.body;
  const sender_phone = req.user.phone;
  // Enhanced validation
  if (!recipient_phone?.match(/^\d{10}$/)) {
    return res.status(400).json({ error: "Invalid recipient phone format" });
  }

  if (!message?.trim() || message.length > 500) {
    return res.status(400).json({
      error: "Message must be between 1-500 characters"
    });
  }


  try {
    // Check if recipient exists
    const recipientCheck = await pool.query(
      "SELECT * FROM admin WHERE phone = $1",
      [recipient_phone]
    );

    if (recipientCheck.rows.length === 0) {
      return res.status(404).json({ error: "Recipient not found" });
    }

    const insertQuery = `
      INSERT INTO direct_messages (sender_phone, recipient_phone, message)
      VALUES ($1, $2, $3)
      RETURNING *;
    `;

    const result = await pool.query(insertQuery, [
      sender_phone,
      recipient_phone,
      message
    ]);

    // Get sender details for real-time update
    const senderResult = await pool.query(
      "SELECT adminname, admin_image_link FROM admin WHERE phone = $1",
      [sender_phone]
    );

    const messageWithDetails = {
      ...result.rows[0],
      adminname: senderResult.rows[0].adminname,
      admin_image_link: senderResult.rows[0].admin_image_link
    };

    // Broadcast to both sender and recipient
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN &&
        (client.userPhone === sender_phone || client.userPhone === recipient_phone)) {
        client.send(JSON.stringify({
          type: 'direct_message',
          message: messageWithDetails
        }));
      }
    });

    res.status(201).json(messageWithDetails);
  } catch (error) {
    console.error("Error sending direct message:", error.message);
    res.status(500).json({
      error: "Failed to send direct message",
      details: error.message
    });
  }
});

// Route to get all admins approved only (admin access only)
app.get("/api/admins/approved", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const adminsQuery = `
      SELECT 
        id, 
        adminname, 
        username, 
        phone, 
        admin_image_link, 
        createdat AS "createdAt"
      FROM admin 
      WHERE is_approved = TRUE
      ORDER BY createdat DESC;
    `;
    const result = await pool.query(adminsQuery);
    res.json(result.rows);
  } catch (error) {
    console.error(`Error fetching admins: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve admins" });
  }
});


// Route to get all admins (admin access only)
app.get("/api/admins", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const adminsQuery = `
      SELECT 
        id, 
        adminname, 
        username, 
        phone, 
        admin_image_link, 
        createdat AS "createdAt"
      FROM admin 
      ORDER BY createdat DESC;
    `;
    const result = await pool.query(adminsQuery);
    res.json(result.rows);
  } catch (error) {
    console.error(`Error fetching admins: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve admins" });
  }
});

// Route to fetch admin's own details after login
app.get("/api/admin/me", authenticateToken, async (req, res) => {
  try {
    const { id } = req.user; // The ID is embedded in the token during login
    const adminQuery = "SELECT * FROM admin WHERE id = $1";
    const adminResult = await pool.query(adminQuery, [id]);

    if (!adminResult.rows.length) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const admin = adminResult.rows[0];
    res.json({
      adminname: admin.adminname,
      username: admin.username,
      phone: admin.phone,
      admin_image_link: admin.admin_image_link,
      createdAt: admin.createdAt,
    });
  } catch (error) {
    console.error(`Error fetching admin details: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve admin details" });
  }
});

// Route to update admin details
app.put(
  "/api/admin/update",
  authenticateToken, // Ensure the user is authenticated
  [
    body("adminname"),
    body("username"),
    body("phone"),
    body("admin_image_link"),
    body("password"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { adminname, username, phone, admin_image_link, password } = req.body;
    const adminId = req.user.id; // Get admin ID from the token

    try {
      // Check if the username or phone already exists for another admin
      if (username || phone) {
        const existingAdmin = await pool.query(
          "SELECT * FROM admin WHERE (username = $1 OR phone = $2) AND id != $3;",
          [username, phone, adminId]
        );

        if (existingAdmin.rows.length) {
          return res.status(400).json({ error: "Username or phone already in use by another admin" });
        }
      }

      // Prepare fields for update
      const updates = [];
      const values = [];
      let index = 1;

      if (adminname) {
        updates.push(`adminname = $${index++}`);
        values.push(adminname);
      }
      if (username) {
        updates.push(`username = $${index++}`);
        values.push(username);
      }
      if (phone) {
        updates.push(`phone = $${index++}`);
        values.push(phone);
      }
      if (admin_image_link) {
        updates.push(`admin_image_link = $${index++}`);
        values.push(admin_image_link);
      }
      if (password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        updates.push(`password = $${index++}`);
        values.push(hashedPassword);
      }

      if (updates.length === 0) {
        return res.status(400).json({ error: "No fields to update" });
      }

      values.push(adminId); // Add admin ID as the last parameter

      const updateQuery = `
        UPDATE admin
        SET ${updates.join(", ")}
        WHERE id = $${index};
      `;

      await pool.query(updateQuery, values);
      res.json({ message: "Admin details updated successfully" });
    } catch (error) {
      console.error(`Error updating admin details: ${error.message}`);
      res.status(500).json({ error: "Failed to update admin details" });
    }
  }
);


// Route to reset password
app.post("/api/admin/forgot-password", async (req, res) => {
  const { username, newPassword } = req.body;

  // Validate input
  if (!username || !newPassword) {
    return res.status(400).json({ error: "Username and new password are required" });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters long" });
  }

  try {
    // Check if the admin exists
    const adminQuery = `SELECT id FROM admin WHERE username = $1;`;
    const adminResult = await pool.query(adminQuery, [username]);

    if (!adminResult.rows.length) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const adminId = adminResult.rows[0].id;

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the password in the database
    const updatePasswordQuery = `
      UPDATE admin 
      SET password = $1 
      WHERE id = $2;
    `;
    await pool.query(updatePasswordQuery, [hashedPassword, adminId]);

    res.json({ message: "Password reset successfully" });
  } catch (error) {
    console.error(`Error resetting password: ${error.message}`);
    res.status(500).json({ error: "Failed to reset password" });
  }
});

// Route to get all jobs with pagination
app.get("/api/jobs", async (req, res) => {
  const { page = 1, limit = 8 } = req.query;

  try {
    const offset = (page - 1) * parseInt(limit);
    const currentTime = new Date();
    const sevenDaysAgo = new Date(currentTime.setDate(currentTime.getDate() - 7));

    const getAllJobsQuery = `
      SELECT *, 
      CASE 
        WHEN createdAt >= $1 THEN 1 
        ELSE 0 
      END as isNew 
      FROM job 
      ORDER BY isNew DESC, createdAt DESC 
      LIMIT $2 OFFSET $3;
    `;

    const jobs = await pool.query(getAllJobsQuery, [sevenDaysAgo.toISOString(), limit, offset]);

    if (jobs.rows.length > 0) {
      res.json(jobs.rows);
    } else {
      res.status(404).json({ error: "No jobs found" });
    }
  } catch (error) {
    console.error(`Error fetching all jobs: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve jobs" });
  }
});

// Admin Panel: Get all jobs (admin access only)
app.get("/api/jobs/adminpanel", authenticateToken, authorizeAdmin, async (req, res) => {
  const getAllJobsQuery = `SELECT j.*, 
      creator.adminname as creator_name,
      approver.adminname as approver_name
      FROM job j
      LEFT JOIN admin creator ON j.created_by = creator.id
      LEFT JOIN admin approver ON j.approved_by = approver.id
  `;

  try {
    const jobsArray = await pool.query(getAllJobsQuery);
    res.send(jobsArray.rows);
  } catch (error) {
    console.error("Error retrieving jobs:", error);
    res.status(500).send("An error occurred while retrieving jobs.");
  }
});


// Route to delete a job (admin access only)
app.delete("/api/jobs/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    const existingJob = await pool.query("SELECT * FROM job WHERE id = $1;", [id]);

    if (!existingJob.rows.length) {
      return res.status(404).json({ error: "Job not found" });
    }
    const deleteJobQuery = `DELETE FROM job WHERE id = $1;`;
    await pool.query(deleteJobQuery, [id]);
    res.json({ message: "Job deleted successfully" });
  } catch (error) {
    console.error(`Error deleting job: ${error.message}`);
    res.status(500).json({ error: "Failed to delete job" });
  }
});

// Route to add a new job (admin access only, with validation)
app.post(
  "/api/jobs",
  authenticateToken,
  authorizeAdmin,
  [
    body("companyname").notEmpty(),
    body("title").notEmpty(),
    body("description").notEmpty(),
    body("apply_link").isURL(),
    body("image_link").isURL(),
    body("url").notEmpty(),
    body("salary").notEmpty(),
    body("location").notEmpty(),
    body("job_type").notEmpty(),
    body("experience").notEmpty(),
    body("batch").notEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { companyname, title, description, apply_link, image_link, url, salary, location, job_type, experience, batch } = req.body;
    const adminId = req.user.id; // Get admin ID from the token

    try {
      // Fetch admin's full name from the database
      const adminQuery = `SELECT adminname FROM admin WHERE id = $1`;
      const adminResult = await pool.query(adminQuery, [adminId]);

      if (adminResult.rows.length === 0) {
        return res.status(404).json({ error: "Admin not found" });
      }

      const adminName = adminResult.rows[0].adminname; // Get admin's full name

      const insertJobQuery = `
        INSERT INTO job (companyname, title, description, apply_link, image_link, url, salary, location, job_type, experience, batch, job_uploader, created_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13);
      `;

      await pool.query(insertJobQuery, [companyname, title, description, apply_link, image_link, url, salary, location, job_type, experience, batch, adminName, adminId]);

      res.status(201).json({ message: "Job added successfully" });
    } catch (error) {
      console.error(`Error adding job: ${error.message}`);
      res.status(500).json({ error: "Failed to add job" });
    }
  }
);


//jobs Modify Approval
app.put("/api/jobs/:id/approve", authenticateToken, authorizeAdmin, async (req, res) => {
  const jobId = req.params.id;
  const approverId = req.user.id;

  await pool.query(`
    UPDATE job SET 
      status = 'approved',
      approved_by = $1
    WHERE id = $2
  `, [approverId, jobId]);
});

// Route to update a job (admin access only)
app.put("/api/jobs/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  const { companyname, title, description, apply_link, image_link, url, salary, location, job_type, experience, batch } = req.body;

  try {
    const existingJob = await pool.query("SELECT * FROM job WHERE id = $1;", [id]);

    if (!existingJob.rows.length) {
      return res.status(404).json({ error: "Job not found" });
    }

    // Fetch admin details to get adminname
    const adminId = req.user.id; // Get admin ID from the token
    const adminQuery = "SELECT adminname FROM admin WHERE id = $1;";
    const adminResult = await pool.query(adminQuery, [adminId]);
    const admin = adminResult.rows[0];

    if (!admin) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const jobUploader = admin.adminname; // Use adminname as job uploader

    const updateJobQuery = `
      UPDATE job
      SET companyname = $1, title = $2, description = $3, apply_link = $4, image_link = $5, url = $6, salary = $7, location = $8, job_type = $9, experience = $10, batch = $11, job_uploader = $12
      WHERE id = $13;
    `;
    await pool.query(updateJobQuery, [companyname, title, description, apply_link, image_link, url, salary, location, job_type, experience, batch, jobUploader, id]);
    res.json({ message: "Job updated successfully" });
  } catch (error) {
    console.error(`Error updating job: ${error.message}`);
    res.status(500).json({ error: "Failed to update job" });
  }
});

// Fetch job by company name and job URL
app.get('/api/jobs/company/:companyname/:url', async (req, res) => {
  const { companyname, url } = req.params;

  const getJobByCompanyNameQuery = `
    SELECT * FROM job WHERE LOWER(companyname) = LOWER($1) AND LOWER(url) = LOWER($2);
  `;

  try {
    const job = await pool.query(getJobByCompanyNameQuery, [companyname, url]);

    if (job.rows.length) {
      res.json(job.rows[0]);
    } else {
      res.status(404).json({ error: "Job not found" });
    }
  } catch (error) {
    console.error(`Error fetching job by company name and URL: ${error.message}`);
    res.status(500).json({ error: "Failed to fetch job" });
  }
});
app.post("/api/jobs/:id/view", async (req, res) => {
  const { id } = req.params;
  const ipAddress = getClientIp(req);

  try {
    const query = `
          INSERT INTO job_viewers (job_id, ip_address, viewed_at)
          VALUES ($1, $2, CURRENT_TIMESTAMP)
          ON CONFLICT (job_id, ip_address)
          DO UPDATE SET viewed_at = CURRENT_TIMESTAMP;
      `;
    await pool.query(query, [id, ipAddress]);
    res.status(200).json({ message: "View recorded successfully" });
  } catch (error) {
    console.error(`Error recording job view: ${error.message}`);
    res.status(500).json({ error: "Failed to record view" });
  }
});

app.get("/api/jobs/:id/viewers", async (req, res) => {
  const { id } = req.params;

  try {
    const query = `
          SELECT COUNT(DISTINCT ip_address) AS viewer_count
          FROM job_viewers
          WHERE job_id = $1;
      `;
    const result = await pool.query(query, [id]);
    res.json({ viewer_count: result.rows[0].viewer_count });
  } catch (error) {
    console.error(`Error fetching viewers count: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve viewer count" });
  }
});
// Fetch the latest popup content
app.get("/api/popup", async (req, res) => {
  try {
    const popupResult = await pool.query("SELECT * FROM popup_content ORDER BY created_at DESC LIMIT 1;");
    const popup = popupResult.rows[0];
    if (popup) {
      res.json({ popup });
    } else {
      res.json({ popup: null });
    }
  } catch (error) {
    console.error(`Error fetching popup content: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve popup content" });
  }
});
// Admin Panel: Get all popup content
app.get("/api/popup/adminpanel", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const popupResult = await pool.query("SELECT * FROM popup_content ORDER BY created_at DESC;");
    res.json(popupResult.rows);
  } catch (error) {
    console.error(`Error fetching all popup content: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve popup content" });
  }
});

app.post(
  "/api/popup/adminpanel",
  authenticateToken, authorizeAdmin,
  [
    body("popup_heading").notEmpty(),
    body("popup_text").notEmpty(),
    body("popup_link").isURL(),
    body("popup_routing_link").isURL(),
    body("popup_belowtext").notEmpty(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    const { popup_heading, popup_text, popup_link, popup_routing_link, popup_belowtext } = req.body;
    try {
      const insertPopQuery = `
      INSERT INTO popup_content (popup_heading, popup_text, popup_link, popup_belowtext, popup_routing_link)
      VALUES ($1, $2, $3, $4, $5);
    `; await pool.query(insertPopQuery, [popup_heading, popup_text, popup_link, popup_belowtext, popup_routing_link]);
      res.status(201).json({ message: "Pop added successfully" });
    } catch (error) {
      console.error(`Error adding Pop: ${error.message}`);
      res.status(500).json({ error: "Failed to add Pop" });
    }

  }
)
// Admin Panel: Update specific popup content
app.put("/api/popup/adminpanel/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  const { popup_heading, popup_text, popup_link, popup_routing_link, popup_belowtext } = req.body;

  try {
    const existingPopup = await pool.query("SELECT * FROM popup_content WHERE id = $1;", [id]);

    if (!existingPopup.rows.length) {
      return res.status(404).json({ error: "Popup not found" });
    }

    const updatePopupQuery = `
      UPDATE popup_content
      SET popup_heading = $1,
          popup_text = $2,
          popup_link = $3,
          popup_routing_link = $4,
          popup_belowtext = $5
      WHERE id = $6;
    `;
    await pool.query(updatePopupQuery, [popup_heading, popup_text, popup_link, popup_routing_link, popup_belowtext, id]);
    res.json({ message: "Popup content updated successfully" });
  } catch (error) {
    console.error(`Error updating popup content: ${error.message}`);
    res.status(500).json({ error: "Failed to update popup content" });
  }
});

// Admin Panel: Delete specific popup content by ID
app.delete("/api/popup/adminpanel/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    const existingPopup = await pool.query("SELECT * FROM popup_content WHERE id = $1;", [id]);

    if (!existingPopup.rows.length) {
      return res.status(404).json({ error: "Popup not found" });
    }

    const deletePopupQuery = `DELETE FROM popup_content WHERE id = $1;`;
    await pool.query(deletePopupQuery, [id]);
    res.json({ message: "Popup content deleted successfully" });
  } catch (error) {
    console.error(`Error deleting popup content: ${error.message}`);
    res.status(500).json({ error: "Failed to delete popup content" });
  }
});
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

pool.connect()
  .then(() => console.log('Connected to PostgreSQL database'))
  .catch((err) => console.error('Database connection error:', err.stack));

// Root route
app.get("/", (req, res) => {
  res.send("Welcome to the Job Card Details API!");
});

// Middleware for error handling
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Something went wrong!" });
});

// Connect to the database and start the server
initializeDbAndServer();