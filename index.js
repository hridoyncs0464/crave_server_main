import mysql from "mysql2/promise";
import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());
app.use(cors());

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: parseInt(process.env.DB_PORT) || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

console.log("✅ Database connection pool created");

const JWT_SECRET = process.env.JWT_SECRET || "crave-secret-key-2026";

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token)
    return res
      .status(401)
      .json({ success: false, message: "No token provided" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res
      .status(401)
      .json({ success: false, message: "Invalid or expired token" });
  }
};

const requireRole =
  (...roles) =>
  (req, res, next) => {
    if (!roles.includes(req.user?.role)) {
      return res.status(403).json({ success: false, message: "Access denied" });
    }
    next();
  };

app.get("/", (_req, res) => {
  res.json({
    message: "🔥 Crave Restaurant API is running!",
    version: "2.0.0",
  });
});

app.get("/api/categories", async (_req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT id, category_name, display_order FROM categories ORDER BY display_order ASC",
    );
    res.json({ success: true, data: rows });
  } catch (error) {
    res
      .status(500)
      .json({
        success: false,
        message: "Failed to fetch categories",
        error: error.message,
      });
  }
});

app.get("/api/menu", async (req, res) => {
  try {
    const { category, sortPrice } = req.query;
    let query = `
      SELECT m.id, m.item_name, c.category_name, c.id as category_id,
        CAST(m.price_bdt AS DECIMAL(10,2)) as price_bdt,
        m.ingredients, m.is_unique, m.display_order,
        COALESCE(m.is_available, TRUE) as is_available
      FROM menu_items m
      JOIN categories c ON m.category_id = c.id
      WHERE 1=1
    `;
    const params = [];
    if (category && category !== "all") {
      query += " AND c.id = ?";
      params.push(parseInt(category));
    }
    if (sortPrice === "low-to-high")
      query +=
        " ORDER BY m.price_bdt ASC, c.display_order ASC, m.display_order ASC";
    else if (sortPrice === "high-to-low")
      query +=
        " ORDER BY m.price_bdt DESC, c.display_order ASC, m.display_order ASC";
    else query += " ORDER BY c.display_order ASC, m.display_order ASC";

    const [rows] = await pool.query(query, params);
    res.json({ success: true, data: rows, count: rows.length });
  } catch (error) {
    res
      .status(500)
      .json({
        success: false,
        message: "Failed to fetch menu",
        error: error.message,
      });
  }
});

app.put(
  "/api/admin/menu/:id",
  verifyToken,
  requireRole("admin"),
  async (req, res) => {
    const { id } = req.params;
    const { price_bdt, is_available } = req.body;
    try {
      const updates = [];
      const params = [];
      if (price_bdt !== undefined) {
        updates.push("price_bdt = ?");
        params.push(parseFloat(price_bdt));
      }
      if (is_available !== undefined) {
        updates.push("is_available = ?");
        params.push(is_available ? 1 : 0);
      }
      if (updates.length === 0)
        return res
          .status(400)
          .json({ success: false, message: "Nothing to update" });
      params.push(parseInt(id));
      await pool.query(
        `UPDATE menu_items SET ${updates.join(", ")} WHERE id = ?`,
        params,
      );
      res.json({ success: true, message: "Menu item updated" });
    } catch (error) {
      res
        .status(500)
        .json({
          success: false,
          message: "Failed to update menu item",
          error: error.message,
        });
    }
  },
);

app.post("/api/staff/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res
      .status(400)
      .json({ success: false, message: "Email and password required" });
  try {
    const [rows] = await pool.query(
      "SELECT id, name, email, password_hash, role FROM staff WHERE email = ? AND is_active = TRUE",
      [email],
    );
    if (rows.length === 0)
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials" });
    const staff = rows[0];
    const valid = await bcrypt.compare(password, staff.password_hash);
    if (!valid)
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials" });
    const token = jwt.sign(
      { id: staff.id, name: staff.name, email: staff.email, role: staff.role },
      JWT_SECRET,
      { expiresIn: "12h" },
    );
    res.json({
      success: true,
      token,
      staff: {
        id: staff.id,
        name: staff.name,
        email: staff.email,
        role: staff.role,
      },
    });
  } catch (error) {
    res
      .status(500)
      .json({ success: false, message: "Login failed", error: error.message });
  }
});

app.get("/api/staff/me", verifyToken, async (req, res) => {
  res.json({
    success: true,
    staff: {
      id: req.user.id,
      name: req.user.name,
      email: req.user.email,
      role: req.user.role,
    },
  });
});

app.get(
  "/api/admin/staff",
  verifyToken,
  requireRole("admin"),
  async (_req, res) => {
    try {
      const [rows] = await pool.query(
        "SELECT id, name, email, role, is_active, created_at FROM staff ORDER BY created_at DESC",
      );
      res.json({ success: true, data: rows });
    } catch (error) {
      res
        .status(500)
        .json({
          success: false,
          message: "Failed to fetch staff",
          error: error.message,
        });
    }
  },
);

app.post(
  "/api/admin/staff",
  verifyToken,
  requireRole("admin"),
  async (req, res) => {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password || !role) {
      return res
        .status(400)
        .json({ success: false, message: "All fields required" });
    }
    if (!["chef", "waiter"].includes(role)) {
      return res
        .status(400)
        .json({ success: false, message: "Role must be 'chef' or 'waiter'" });
    }
    try {
      const hash = await bcrypt.hash(password, 10);
      const [result] = await pool.query(
        "INSERT INTO staff (name, email, password_hash, role) VALUES (?, ?, ?, ?)",
        [name, email, hash, role],
      );
      res
        .status(201)
        .json({
          success: true,
          message: "Staff added successfully",
          id: result.insertId,
        });
    } catch (error) {
      if (error.code === "ER_DUP_ENTRY")
        return res
          .status(409)
          .json({ success: false, message: "Email already exists" });
      res
        .status(500)
        .json({
          success: false,
          message: "Failed to add staff",
          error: error.message,
        });
    }
  },
);

app.put(
  "/api/admin/staff/:id/toggle",
  verifyToken,
  requireRole("admin"),
  async (req, res) => {
    const { id } = req.params;
    try {
      await pool.query(
        "UPDATE staff SET is_active = NOT is_active WHERE id = ?",
        [id],
      );
      res.json({ success: true, message: "Staff status updated" });
    } catch (error) {
      res
        .status(500)
        .json({
          success: false,
          message: "Failed to update staff",
          error: error.message,
        });
    }
  },
);

app.delete(
  "/api/admin/staff/:id",
  verifyToken,
  requireRole("admin"),
  async (req, res) => {
    const { id } = req.params;
    try {
      await pool.query("DELETE FROM staff WHERE id = ?", [id]);
      res.json({ success: true, message: "Staff deleted" });
    } catch (error) {
      res
        .status(500)
        .json({
          success: false,
          message: "Failed to delete staff",
          error: error.message,
        });
    }
  },
);

app.post("/api/orders/create", async (req, res) => {
  const { table_number, items, customer_note } = req.body;
  if (!table_number || !items || items.length === 0) {
    return res
      .status(400)
      .json({ success: false, message: "Table number and items are required" });
  }
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    let totalAmount = 0;
    for (const item of items)
      totalAmount += item.price_per_unit * item.quantity;
    const orderId = `ORD-${Date.now().toString().slice(-8)}`;

    const [orderResult] = await conn.query(
      `INSERT INTO orders (order_id, table_number, customer_note, total_amount, status)
       VALUES (?, ?, ?, ?, 'pending')`,
      [orderId, table_number, customer_note || null, totalAmount],
    );
    const orderId_db = orderResult.insertId;

    for (const item of items) {
      await conn.query(
        `INSERT INTO order_items (order_id, menu_item_id, item_name, category_name, quantity, price_per_unit, subtotal, special_notes)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          orderId_db,
          item.menu_item_id,
          item.item_name,
          item.category_name || "",
          item.quantity,
          item.price_per_unit,
          item.price_per_unit * item.quantity,
          item.special_notes || null,
        ],
      );
    }

    await conn.query(
      "INSERT INTO order_tracking (order_id, status, message) VALUES (?, 'pending', 'Order placed from table')",
      [orderId_db],
    );
    await conn.commit();

    res.status(201).json({
      success: true,
      message: "Order placed successfully",
      order: {
        order_id: orderId,
        db_id: orderId_db,
        table_number,
        total_amount: totalAmount,
        status: "pending",
      },
    });
  } catch (error) {
    await conn.rollback();
    res
      .status(500)
      .json({
        success: false,
        message: "Failed to create order",
        error: error.message,
      });
  } finally {
    conn.release();
  }
});

app.get("/api/orders", verifyToken, async (req, res) => {
  const { status, table_number, date } = req.query;
  try {
    let query = `
      SELECT o.id, o.order_id, o.table_number, o.customer_note,
        o.total_amount, o.status, o.created_at, o.updated_at,
        COUNT(oi.id) as item_count
      FROM orders o
      LEFT JOIN order_items oi ON o.id = oi.order_id
      WHERE 1=1
    `;
    const params = [];
    if (status && status !== "all") {
      query += " AND o.status = ?";
      params.push(status);
    }
    if (table_number) {
      query += " AND o.table_number = ?";
      params.push(table_number);
    }
    if (date) {
      query += " AND DATE(o.created_at) = ?";
      params.push(date);
    }
    query += " GROUP BY o.id ORDER BY o.created_at DESC LIMIT 200";
    const [rows] = await pool.query(query, params);
    res.json({ success: true, data: rows, count: rows.length });
  } catch (error) {
    res
      .status(500)
      .json({
        success: false,
        message: "Failed to fetch orders",
        error: error.message,
      });
  }
});

app.get("/api/orders/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [orders] = await pool.query("SELECT * FROM orders WHERE id = ?", [
      id,
    ]);
    if (orders.length === 0)
      return res
        .status(404)
        .json({ success: false, message: "Order not found" });
    const [items] = await pool.query(
      "SELECT * FROM order_items WHERE order_id = ?",
      [id],
    );
    const [tracking] = await pool.query(
      "SELECT * FROM order_tracking WHERE order_id = ? ORDER BY timestamp DESC",
      [id],
    );
    res.json({ success: true, data: { order: orders[0], items, tracking } });
  } catch (error) {
    res
      .status(500)
      .json({
        success: false,
        message: "Failed to fetch order",
        error: error.message,
      });
  }
});

app.put("/api/orders/:id/status", verifyToken, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  const validStatuses = [
    "pending",
    "preparing",
    "ready",
    "served",
    "cancelled",
  ];
  if (!status || !validStatuses.includes(status)) {
    return res.status(400).json({ success: false, message: "Invalid status" });
  }

  const role = req.user.role;
  if (role === "chef" && !["preparing", "ready"].includes(status)) {
    return res
      .status(403)
      .json({
        success: false,
        message: "Chefs can only set preparing or ready",
      });
  }
  if (role === "waiter" && !["served"].includes(status)) {
    return res
      .status(403)
      .json({ success: false, message: "Waiters can only set served" });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [result] = await conn.query(
      "UPDATE orders SET status = ?, updated_at = NOW() WHERE id = ?",
      [status, id],
    );
    if (result.affectedRows === 0) {
      await conn.rollback();
      return res
        .status(404)
        .json({ success: false, message: "Order not found" });
    }
    await conn.query(
      "INSERT INTO order_tracking (order_id, status, message, changed_by) VALUES (?, ?, ?, ?)",
      [id, status, `Status changed to ${status}`, req.user.name],
    );
    await conn.commit();
    res.json({
      success: true,
      message: "Order status updated",
      new_status: status,
    });
  } catch (error) {
    await conn.rollback();
    res
      .status(500)
      .json({
        success: false,
        message: "Failed to update order",
        error: error.message,
      });
  } finally {
    conn.release();
  }
});

app.get(
  "/api/admin/dashboard",
  verifyToken,
  requireRole("admin"),
  async (_req, res) => {
    try {
      const [todayOrders] = await pool.query(
        "SELECT COUNT(*) as count FROM orders WHERE DATE(created_at) = CURDATE()",
      );
      const [todayRevenue] = await pool.query(
        "SELECT SUM(total_amount) as total FROM orders WHERE DATE(created_at) = CURDATE() AND status != 'cancelled'",
      );
      const [byStatus] = await pool.query(
        "SELECT status, COUNT(*) as count FROM orders GROUP BY status",
      );
      const [recentOrders] = await pool.query(
        "SELECT id, order_id, table_number, total_amount, status, created_at FROM orders ORDER BY created_at DESC LIMIT 10",
      );
      const [staffCount] = await pool.query(
        "SELECT role, COUNT(*) as count FROM staff WHERE is_active = TRUE GROUP BY role",
      );

      res.json({
        success: true,
        data: {
          total_orders_today: todayOrders[0].count,
          total_revenue_today: todayRevenue[0].total || 0,
          orders_by_status: byStatus.reduce((acc, r) => {
            acc[r.status] = r.count;
            return acc;
          }, {}),
          recent_orders: recentOrders,
          staff_by_role: staffCount.reduce((acc, r) => {
            acc[r.role] = r.count;
            return acc;
          }, {}),
        },
      });
    } catch (error) {
      res
        .status(500)
        .json({
          success: false,
          message: "Failed to fetch dashboard stats",
          error: error.message,
        });
    }
  },
);

app.get("/api/tables", async (_req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT * FROM restaurant_tables WHERE is_active = TRUE ORDER BY table_number",
    );
    res.json({ success: true, data: rows });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to fetch tables" });
  }
});

app.post("/api/reservations", async (req, res) => {
  const {
    customer_name,
    customer_email,
    customer_phone,
    number_of_guests,
    reservation_date,
    reservation_time,
    special_requests,
  } = req.body;
  if (
    !customer_name ||
    !customer_phone ||
    !number_of_guests ||
    !reservation_date ||
    !reservation_time
  ) {
    return res
      .status(400)
      .json({ success: false, message: "Required fields missing" });
  }
  try {
    const [result] = await pool.query(
      `INSERT INTO reservations (customer_name, customer_email, customer_phone, number_of_guests, reservation_date, reservation_time, special_requests)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        customer_name,
        customer_email || null,
        customer_phone,
        number_of_guests,
        reservation_date,
        reservation_time,
        special_requests || null,
      ],
    );
    res
      .status(201)
      .json({
        success: true,
        message: "Reservation submitted!",
        reservation_id: result.insertId,
      });
  } catch (error) {
    res
      .status(500)
      .json({ success: false, message: "Failed to create reservation" });
  }
});

app.get("/api/reservations", verifyToken, async (req, res) => {
  const { status, date } = req.query;
  try {
    let query = "SELECT * FROM reservations WHERE 1=1";
    const params = [];
    if (status) {
      query += " AND status = ?";
      params.push(status);
    }
    if (date) {
      query += " AND DATE(reservation_date) = ?";
      params.push(date);
    }
    query += " ORDER BY reservation_date ASC, reservation_time ASC";
    const [rows] = await pool.query(query, params);
    res.json({ success: true, data: rows });
  } catch (error) {
    res
      .status(500)
      .json({ success: false, message: "Failed to fetch reservations" });
  }
});

app.post("/api/register", async (req, res) => {
  const { name, email, firebase_uid } = req.body;
  try {
    const [result] = await pool.query(
      "INSERT INTO users (name, email, firebase_uid, created_at, last_login) VALUES (?, ?, ?, NOW(), NOW())",
      [name, email, firebase_uid],
    );
    res
      .status(201)
      .json({ success: true, message: "User registered", id: result.insertId });
  } catch (error) {
    if (error.code === "ER_DUP_ENTRY")
      return res
        .status(409)
        .json({ success: false, message: "Email already registered" });
    res
      .status(500)
      .json({ success: false, message: "Failed to register user" });
  }
});

// 1. Admin: Confirm or Cancel a reservation
app.put(
  "/api/admin/reservations/:id/status",
  verifyToken,
  requireRole("admin"),
  async (req, res) => {
    const { id } = req.params;
    const { status } = req.body;

    if (!["confirmed", "cancelled"].includes(status)) {
      return res
        .status(400)
        .json({
          success: false,
          message: "Status must be 'confirmed' or 'cancelled'",
        });
    }

    try {
      const [result] = await pool.query(
        "UPDATE reservations SET status = ? WHERE id = ?",
        [status, id],
      );

      if (result.affectedRows === 0) {
        return res
          .status(404)
          .json({ success: false, message: "Reservation not found" });
      }

      // Fetch the updated reservation to return full details
      const [rows] = await pool.query(
        "SELECT * FROM reservations WHERE id = ?",
        [id],
      );

      res.json({
        success: true,
        message: `Reservation ${status}`,
        reservation: rows[0],
      });
    } catch (error) {
      res
        .status(500)
        .json({
          success: false,
          message: "Failed to update reservation",
          error: error.message,
        });
    }
  },
);

// 2. Customer: Get my reservations by email (uses Firebase email)
app.get("/api/my-reservations", async (req, res) => {
  const { email } = req.query;

  if (!email) {
    return res
      .status(400)
      .json({ success: false, message: "Email is required" });
  }

  try {
    const [rows] = await pool.query(
      `SELECT id, customer_name, customer_phone, number_of_guests,
              reservation_date, reservation_time, special_requests,
              status, assigned_table_number, created_at
       FROM reservations
       WHERE customer_email = ?
       ORDER BY reservation_date DESC, reservation_time DESC`,
      [email],
    );

    res.json({ success: true, data: rows });
  } catch (error) {
    res
      .status(500)
      .json({
        success: false,
        message: "Failed to fetch reservations",
        error: error.message,
      });
  }
});

app.get("/api/setup-admin", async (_req, res) => {
  try {
    const hash = await bcrypt.hash("admin123", 10);
    await pool.query("DELETE FROM staff WHERE email = 'admin@crave.com'");
    await pool.query(
      "INSERT INTO staff (name, email, password_hash, role, is_active) VALUES (?, ?, ?, 'admin', 1)",
      ["Admin", "admin@crave.com", hash],
    );
    res.json({ success: true, message: "Admin created successfully!" });
  } catch (error) {
    res.json({ success: false, error: error.message });
  }
});

process.on("uncaughtException", (err) =>
  console.error("Uncaught exception:", err.message),
);
process.on("unhandledRejection", (err) =>
  console.error("Unhandled rejection:", err?.message),
);

app.listen(PORT, () =>
  console.log(`✅ Server running on http://localhost:${PORT}`),
);
