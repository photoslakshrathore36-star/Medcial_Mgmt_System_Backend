const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { getPool } = require('./database');

// ─── MIDDLEWARE ──────────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'secret123');
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
}
function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin only' });
  next();
}
function notWorker(req, res, next) {
  if (req.user.role === 'worker') return res.status(403).json({ message: 'Access denied' });
  next();
}

// ─── ORG HELPER — get org_id for current user ──────────────────────────────────
async function getOrgId(userId) {
  const db = await getPool();
  const [[row]] = await db.query(
    `SELECT org_id FROM org_users WHERE user_id=? LIMIT 1`,
    [userId]
  );
  return row ? row.org_id : null;
}

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════════════════════════════════
router.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const db = await getPool();
  try {
    const [[user]] = await db.query('SELECT * FROM users WHERE username=? AND is_active=1', [username]);
    if (!user || !bcrypt.compareSync(password, user.password))
      return res.status(401).json({ message: 'Invalid credentials' });
    const token = jwt.sign(
      { id: user.id, name: user.name, username: user.username, role: user.role },
      process.env.JWT_SECRET || 'secret123',
      { expiresIn: '24h' }
    );
    // Get departments if worker
    let departments = [];
    if (user.role === 'worker') {
      const [depts] = await db.query(
        `SELECT d.* FROM departments d JOIN worker_departments wd ON wd.department_id=d.id WHERE wd.worker_id=?`,
        [user.id]
      );
      departments = depts;
    }
    // Get areas if field_worker
    let areas = [];
    if (user.role === 'field_worker') {
      const [ar] = await db.query(
        `SELECT a.* FROM areas a JOIN field_worker_areas fwa ON fwa.area_id=a.id WHERE fwa.worker_id=?`,
        [user.id]
      );
      areas = ar;
    }
    res.json({ token, user: { id: user.id, name: user.name, username: user.username, role: user.role, departments, areas } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Login failed' });
  }
});

router.put('/auth/change-password', auth, async (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    const db = await getPool();
    const [[user]] = await db.query('SELECT * FROM users WHERE id=?', [req.user.id]);
    if (!bcrypt.compareSync(current_password, user.password))
      return res.status(400).json({ message: 'Current password is incorrect' });
    const hashed = bcrypt.hashSync(new_password, 10);
    await db.query('UPDATE users SET password=? WHERE id=?', [hashed, req.user.id]);
    res.json({ message: 'Password updated' });
  } catch (err) {
    console.error('PUT /auth/change-password error:', err.message);
    res.status(500).json({ message: 'Failed to change password', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// DEPARTMENTS
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/departments', auth, async (req, res) => {
  try {
    const db = await getPool();
    const where = req.query.active_only === '1' ? 'WHERE is_active=1' : 'WHERE 1=1';
    const [rows] = await db.query(`SELECT * FROM departments ${where} ORDER BY stage_order, name`);
    res.json(rows);
  } catch (err) {
    console.error('GET /departments error:', err.message);
    res.status(500).json({ message: 'Failed to fetch departments', error: err.message });
  }
});

router.post('/departments', auth, adminOnly, async (req, res) => {
  try {
    const { name, description, color, stage_order } = req.body;
    const db = await getPool();
    const [r] = await db.query(
      'INSERT INTO departments (name,description,color,stage_order) VALUES (?,?,?,?)',
      [name, description, color || '#3B82F6', stage_order || 999]
    );
    res.json({ id: r.insertId, name, description, color, stage_order });
  } catch (err) {
    console.error('POST /departments error:', err.message);
    res.status(500).json({ message: 'Failed to create department', error: err.message });
  }
});

router.put('/departments/:id', auth, adminOnly, async (req, res) => {
  try {
    const { name, description, color, stage_order, is_active } = req.body;
    const db = await getPool();
    const [result] = await db.query(
      'UPDATE departments SET name=?,description=?,color=?,stage_order=?,is_active=? WHERE id=?',
      [name, description, color, stage_order, is_active, req.params.id]
    );
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Department not found' });
    res.json({ message: 'Updated' });
  } catch (err) {
    console.error('PUT /departments/:id error:', err.message);
    res.status(500).json({ message: 'Failed to update department', error: err.message });
  }
});

router.delete('/departments/:id', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const [result] = await db.query('UPDATE departments SET is_active=0 WHERE id=?', [req.params.id]);
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Department not found' });
    res.json({ message: 'Deactivated' });
  } catch (err) {
    console.error('DELETE /departments/:id error:', err.message);
    res.status(500).json({ message: 'Failed to delete department', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// USERS / WORKERS
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/workers', auth, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const role = req.query.role || null;
    let where = "WHERE u.role != 'admin' AND u.role != 'super_admin'";
    const params = [];
    // Org filter — show only this org's workers
    if (orgId) { where += ' AND ou.org_id=?'; params.push(orgId); }
    if (role) { where += ' AND u.role=?'; params.push(role); }
    const [workers] = await db.query(
      `SELECT u.id,u.name,u.username,u.phone,u.role,u.hourly_rate,u.is_active,u.created_at
       FROM users u
       LEFT JOIN org_users ou ON ou.user_id=u.id
       ${where} ORDER BY u.name`, params);
    for (const w of workers) {
      if (w.role === 'worker') {
        const [depts] = await db.query(
          `SELECT d.id,d.name,d.color FROM departments d JOIN worker_departments wd ON wd.department_id=d.id WHERE wd.worker_id=?`,
          [w.id]
        );
        w.departments = depts;
      } else if (w.role === 'field_worker') {
        const [areas] = await db.query(
          `SELECT a.id,a.name,a.city FROM areas a JOIN field_worker_areas fwa ON fwa.area_id=a.id WHERE fwa.worker_id=?`,
          [w.id]
        );
        w.areas = areas;
      }
    }
    res.json(workers);
  } catch (err) {
    console.error('GET /workers error:', err.message);
    res.status(500).json({ message: 'Failed to fetch workers', error: err.message });
  }
});

router.post('/workers', auth, adminOnly, async (req, res) => {
  try {
    const { name, username, password, phone, role, hourly_rate, department_ids, area_ids } = req.body;
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const hashed = bcrypt.hashSync(password, 10);
    const [r] = await db.query(
      'INSERT INTO users (name,username,password,role,phone,hourly_rate) VALUES (?,?,?,?,?,?)',
      [name, username, hashed, role || 'worker', phone, hourly_rate || 0]
    );
    const uid = r.insertId;
    // Link worker to same org as admin
    if (orgId) {
      await db.query('INSERT IGNORE INTO org_users (org_id,user_id) VALUES (?,?)', [orgId, uid]);
    }
    if (department_ids?.length && role === 'worker') {
      for (const did of department_ids) {
        await db.query('INSERT IGNORE INTO worker_departments (worker_id,department_id) VALUES (?,?)', [uid, did]);
      }
    }
    if (area_ids?.length && role === 'field_worker') {
      for (const aid of area_ids) {
        await db.query('INSERT IGNORE INTO field_worker_areas (worker_id,area_id) VALUES (?,?)', [uid, aid]);
      }
    }
    res.json({ id: uid, name, username, role });
  } catch (err) {
    console.error('POST /workers error:', err.message);
    res.status(500).json({ message: 'Failed to create worker', error: err.message });
  }
});

router.put('/workers/:id', auth, adminOnly, async (req, res) => {
  try {
    const { name, phone, hourly_rate, is_active, department_ids, area_ids, role } = req.body;
    const db = await getPool();
    const [result] = await db.query(
      'UPDATE users SET name=?,phone=?,hourly_rate=?,is_active=? WHERE id=?',
      [name, phone, hourly_rate || 0, is_active, req.params.id]
    );
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Worker not found' });
    if (department_ids !== undefined && role === 'worker') {
      await db.query('DELETE FROM worker_departments WHERE worker_id=?', [req.params.id]);
      for (const did of department_ids || []) {
        await db.query('INSERT IGNORE INTO worker_departments (worker_id,department_id) VALUES (?,?)', [req.params.id, did]);
      }
    }
    if (area_ids !== undefined && role === 'field_worker') {
      await db.query('DELETE FROM field_worker_areas WHERE worker_id=?', [req.params.id]);
      for (const aid of area_ids || []) {
        await db.query('INSERT IGNORE INTO field_worker_areas (worker_id,area_id) VALUES (?,?)', [req.params.id, aid]);
      }
    }
    res.json({ message: 'Updated' });
  } catch (err) {
    console.error('PUT /workers/:id error:', err.message);
    res.status(500).json({ message: 'Failed to update worker', error: err.message });
  }
});

router.delete('/workers/:id', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    // Remove department and area links first
    await db.query('DELETE FROM worker_departments WHERE worker_id=?', [req.params.id]);
    await db.query('DELETE FROM field_worker_areas WHERE worker_id=?', [req.params.id]);
    await db.query('DELETE FROM org_users WHERE user_id=?', [req.params.id]);
    const [result] = await db.query('DELETE FROM users WHERE id=? AND role != "super_admin"', [req.params.id]);
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Worker not found' });
    res.json({ message: 'Worker deleted' });
  } catch (err) {
    console.error('DELETE /workers/:id error:', err.message);
    res.status(500).json({ message: 'Failed to delete worker', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// PRODUCT CATEGORIES
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/product-categories', auth, async (req, res) => {
  try {
    const db = await getPool();
    const [rows] = await db.query('SELECT * FROM product_categories WHERE is_active=1 ORDER BY name');
    res.json(rows);
  } catch (err) {
    console.error('GET /product-categories error:', err.message);
    res.status(500).json({ message: 'Failed to fetch categories', error: err.message });
  }
});
router.post('/product-categories', auth, adminOnly, async (req, res) => {
  try {
    const { name, description } = req.body;
    const db = await getPool();
    const [r] = await db.query('INSERT INTO product_categories (name,description) VALUES (?,?)', [name, description]);
    res.status(201).json({ id: r.insertId, name, description });
  } catch (err) {
    console.error('POST /product-categories error:', err.message);
    res.status(500).json({ message: 'Failed to create category', error: err.message });
  }
});
router.put('/product-categories/:id', auth, adminOnly, async (req, res) => {
  const { name, description, is_active } = req.body;
  const db = await getPool();
  await db.query('UPDATE product_categories SET name=?,description=?,is_active=? WHERE id=?', [name, description, is_active, req.params.id]);
  res.json({ message: 'Updated' });
});

// ═══════════════════════════════════════════════════════════════════════════════
// PRODUCTION ORDERS
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/orders', auth, async (req, res) => {
  const db = await getPool();
  const { status, search } = req.query;
  let where = "WHERE o.status != 'deleted'";
  const params = [];
  if (status && status !== 'all') { where += ' AND o.status=?'; params.push(status); }
  if (search) { where += ' AND (o.name LIKE ? OR o.order_no LIKE ? OR o.client_name LIKE ?)'; params.push(`%${search}%`, `%${search}%`, `%${search}%`); }
  const [rows] = await db.query(
    `SELECT o.*, pc.name as category_name,
     (SELECT COUNT(*) FROM production_items WHERE order_id=o.id) as item_count,
     (SELECT COUNT(*) FROM task_assignments WHERE order_id=o.id) as task_count,
     (SELECT COUNT(*) FROM task_assignments WHERE order_id=o.id AND status='completed') as tasks_done
     FROM production_orders o
     LEFT JOIN product_categories pc ON pc.id=o.category_id
     ${where} ORDER BY o.created_at DESC`,
    params
  );
  res.json(rows);
});

router.post('/orders', auth, adminOnly, async (req, res) => {
  try {
    const { order_no, name, category_id, client_name, client_phone, description, priority, order_date, deadline, total_amount, notes } = req.body;
    const db = await getPool();
    let finalOrderNo = order_no;
    if (!finalOrderNo || finalOrderNo.trim() === '') {
      const [[{ cnt }]] = await db.query('SELECT COUNT(*) as cnt FROM production_orders');
      finalOrderNo = `MO-${String(cnt + 1).padStart(4, '0')}`;
    }
    const safeOrderDate = (order_date && order_date !== '') ? order_date : null;
    const safeDeadline = (deadline && deadline !== '') ? deadline : null;
    const [r] = await db.query(
      'INSERT INTO production_orders (order_no,name,category_id,client_name,client_phone,description,priority,order_date,deadline,total_amount,notes,created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
      [finalOrderNo, name, category_id, client_name, client_phone, description, priority || 'medium', safeOrderDate, safeDeadline, total_amount || 0, notes, req.user.id]
    );
    res.status(201).json({ id: r.insertId, order_no: finalOrderNo, name });
  } catch (err) {
    console.error('POST /orders error:', err.message);
    res.status(500).json({ message: 'Failed to create order', error: err.message });
  }
});

router.get('/orders/:id', auth, async (req, res) => {
  try {
    const db = await getPool();
    const [[order]] = await db.query(
      `SELECT o.*, pc.name as category_name FROM production_orders o LEFT JOIN product_categories pc ON pc.id=o.category_id WHERE o.id=?`,
      [req.params.id]
    );
    if (!order) return res.status(404).json({ message: 'Order not found' });
    const [items] = await db.query('SELECT * FROM production_items WHERE order_id=? ORDER BY id', [req.params.id]);
    const [tasks] = await db.query(
      `SELECT t.*, u.name as worker_name, d.name as dept_name, d.color as dept_color
       FROM task_assignments t
       LEFT JOIN users u ON u.id=t.worker_id
       LEFT JOIN departments d ON d.id=t.department_id
       WHERE t.order_id=? ORDER BY t.stage_order, t.id`,
      [req.params.id]
    );
    const [chain] = await db.query(
      `SELECT pc.*, d.name as dept_name, d.color FROM production_chains pc JOIN departments d ON d.id=pc.department_id WHERE pc.order_id=? ORDER BY pc.stage_order`,
      [req.params.id]
    );
    res.json({ ...order, items, tasks, chain });
  } catch (err) {
    console.error('GET /orders/:id error:', err.message);
    res.status(500).json({ message: 'Failed to fetch order', error: err.message });
  }
});

router.put('/orders/:id', auth, adminOnly, async (req, res) => {
  try {
    const { name, category_id, client_name, client_phone, description, status, priority, order_date, deadline, total_amount, notes } = req.body;
    const db = await getPool();
    const safeOrderDate = (order_date && order_date !== '') ? order_date : null;
    const safeDeadline = (deadline && deadline !== '') ? deadline : null;
    const [result] = await db.query(
      'UPDATE production_orders SET name=?,category_id=?,client_name=?,client_phone=?,description=?,status=?,priority=?,order_date=?,deadline=?,total_amount=?,notes=? WHERE id=?',
      [name, category_id, client_name, client_phone, description, status, priority, safeOrderDate, safeDeadline, total_amount, notes, req.params.id]
    );
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Order not found' });
    res.json({ message: 'Updated' });
  } catch (err) {
    console.error('PUT /orders/:id error:', err.message);
    res.status(500).json({ message: 'Failed to update order', error: err.message });
  }
});

router.delete('/orders/:id', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const [result] = await db.query("UPDATE production_orders SET status='deleted' WHERE id=?", [req.params.id]);
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Order not found' });
    res.json({ message: 'Deleted' });
  } catch (err) {
    console.error('DELETE /orders/:id error:', err.message);
    res.status(500).json({ message: 'Failed to delete order', error: err.message });
  }
});

// ─── PRODUCTION ITEMS ────────────────────────────────────────────────────────
router.post('/orders/:id/items', auth, adminOnly, async (req, res) => {
  try {
    const { item_name, item_code, description, quantity, unit, unit_price, notes } = req.body;
    const db = await getPool();
    const [r] = await db.query(
      'INSERT INTO production_items (order_id,item_name,item_code,description,quantity,unit,unit_price,notes) VALUES (?,?,?,?,?,?,?,?)',
      [req.params.id, item_name, item_code, description, quantity || 1, unit || 'pcs', unit_price || 0, notes]
    );
    res.status(201).json({ id: r.insertId, item_name });
  } catch (err) {
    console.error('POST /orders/:id/items error:', err.message);
    res.status(500).json({ message: 'Failed to add item', error: err.message });
  }
});

router.put('/orders/:orderId/items/:id', auth, adminOnly, async (req, res) => {
  try {
    const { item_name, item_code, description, quantity, unit, unit_price, status, notes } = req.body;
    const db = await getPool();
    const [result] = await db.query(
      'UPDATE production_items SET item_name=?,item_code=?,description=?,quantity=?,unit=?,unit_price=?,status=?,notes=? WHERE id=? AND order_id=?',
      [item_name, item_code, description, quantity, unit, unit_price, status, notes, req.params.id, req.params.orderId]
    );
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Item not found' });
    res.json({ message: 'Updated' });
  } catch (err) {
    console.error('PUT /orders/:orderId/items/:id error:', err.message);
    res.status(500).json({ message: 'Failed to update item', error: err.message });
  }
});

router.delete('/orders/:orderId/items/:id', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const [result] = await db.query('DELETE FROM production_items WHERE id=? AND order_id=?', [req.params.id, req.params.orderId]);
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Item not found' });
    res.json({ message: 'Deleted' });
  } catch (err) {
    console.error('DELETE /orders/:orderId/items/:id error:', err.message);
    res.status(500).json({ message: 'Failed to delete item', error: err.message });
  }
});

// ─── PRODUCTION CHAIN ────────────────────────────────────────────────────────
router.post('/orders/:id/chain', auth, adminOnly, async (req, res) => {
  try {
    const { stages, item_id } = req.body; // stages: [{department_id, stage_order}]
    const db = await getPool();
    if (item_id) {
      await db.query('DELETE FROM production_chains WHERE order_id=? AND item_id=?', [req.params.id, item_id]);
    } else {
      await db.query('DELETE FROM production_chains WHERE order_id=? AND item_id IS NULL', [req.params.id]);
    }
    for (const s of stages) {
      await db.query(
        'INSERT INTO production_chains (order_id,item_id,department_id,stage_order) VALUES (?,?,?,?)',
        [req.params.id, item_id || null, s.department_id, s.stage_order]
      );
    }
    res.json({ message: 'Chain saved' });
  } catch (err) {
    console.error('POST /orders/:id/chain error:', err.message);
    res.status(500).json({ message: 'Failed to save chain', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// TASK ASSIGNMENTS (production tasks)
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/tasks/all', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const { status, worker_id, department_id, order_id } = req.query;
    let where = 'WHERE 1=1';
    const params = [];
    if (status && status !== 'all') { where += ' AND t.status=?'; params.push(status); }
    if (worker_id) { where += ' AND t.worker_id=?'; params.push(worker_id); }
    if (department_id) { where += ' AND t.department_id=?'; params.push(department_id); }
    if (order_id) { where += ' AND t.order_id=?'; params.push(order_id); }
    const [rows] = await db.query(
      `SELECT t.*, o.order_no, o.name as order_name, pi.item_name,
       u.name as worker_name, d.name as dept_name, d.color as dept_color
       FROM task_assignments t
       JOIN production_orders o ON o.id=t.order_id
       LEFT JOIN production_items pi ON pi.id=t.item_id
       LEFT JOIN users u ON u.id=t.worker_id
       LEFT JOIN departments d ON d.id=t.department_id
       ${where} ORDER BY t.priority DESC, t.due_date ASC, t.id DESC`,
      params
    );
    res.json(rows);
  } catch (err) {
    console.error('GET /tasks/all error:', err.message);
    res.status(500).json({ message: 'Failed to fetch tasks', error: err.message });
  }
});

router.get('/tasks/my', auth, async (req, res) => {
  try {
    const db = await getPool();
    const [rows] = await db.query(
      `SELECT t.*, o.order_no, o.name as order_name, pi.item_name,
       d.name as dept_name, d.color as dept_color
       FROM task_assignments t
       JOIN production_orders o ON o.id=t.order_id
       LEFT JOIN production_items pi ON pi.id=t.item_id
       LEFT JOIN departments d ON d.id=t.department_id
       WHERE t.worker_id=? AND t.status != 'completed'
       ORDER BY t.priority DESC, t.due_date ASC`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    console.error('GET /tasks/my error:', err.message);
    res.status(500).json({ message: 'Failed to fetch my tasks', error: err.message });
  }
});

router.post('/tasks', auth, adminOnly, async (req, res) => {
  try {
    const { order_id, item_id, assign_type, worker_id, department_id, stage_order, task_title, task_description, quantity_assigned, priority, start_date, due_date, admin_notes } = req.body;
    const db = await getPool();
    const safeWorkerId = (worker_id && worker_id !== '') ? worker_id : null;
    const safeDeptId = (department_id && department_id !== '') ? department_id : null;
    const safeDueDate = (due_date && due_date !== '') ? due_date : null;
    const safeStartDate = (start_date && start_date !== '') ? start_date : null;
    const [r] = await db.query(
      'INSERT INTO task_assignments (order_id,item_id,assign_type,worker_id,department_id,stage_order,task_title,task_description,quantity_assigned,priority,start_date,due_date,admin_notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
      [order_id, item_id, assign_type || 'worker', safeWorkerId, safeDeptId, stage_order || 0, task_title, task_description, quantity_assigned || 1, priority || 'medium', safeStartDate, safeDueDate, admin_notes]
    );
    res.status(201).json({ id: r.insertId, task_title });
  } catch (err) {
    console.error('POST /tasks error:', err.message);
    res.status(500).json({ message: 'Failed to create task', error: err.message });
  }
});

router.put('/tasks/:id', auth, adminOnly, async (req, res) => {
  try {
    const { task_title, task_description, quantity_assigned, status, priority, start_date, due_date, admin_notes, worker_id, department_id } = req.body;
    const db = await getPool();
    const safeWorkerId = (worker_id && worker_id !== '') ? worker_id : null;
    const safeDeptId = (department_id && department_id !== '') ? department_id : null;
    const safeDueDate = (due_date && due_date !== '') ? due_date : null;
    const safeStartDate = (start_date && start_date !== '') ? start_date : null;
    const [result] = await db.query(
      'UPDATE task_assignments SET task_title=?,task_description=?,quantity_assigned=?,status=?,priority=?,start_date=?,due_date=?,admin_notes=?,worker_id=?,department_id=? WHERE id=?',
      [task_title, task_description, quantity_assigned, status, priority, safeStartDate, safeDueDate, admin_notes, safeWorkerId, safeDeptId, req.params.id]
    );
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Task not found' });
    res.json({ message: 'Updated' });
  } catch (err) {
    console.error('PUT /tasks/:id error:', err.message);
    res.status(500).json({ message: 'Failed to update task', error: err.message });
  }
});

router.patch('/tasks/:id/progress', auth, async (req, res) => {
  try {
    const { quantity_completed, status, worker_notes } = req.body;
    const db = await getPool();
    const updates = [];
    const vals = [];
    if (quantity_completed !== undefined) { updates.push('quantity_completed=?'); vals.push(quantity_completed); }
    if (status) { updates.push('status=?'); vals.push(status); if (status === 'completed') { updates.push('completed_date=CURDATE()'); } }
    if (worker_notes !== undefined) { updates.push('worker_notes=?'); vals.push(worker_notes); }
    vals.push(req.params.id);
    if (updates.length) { const [result] = await db.query(`UPDATE task_assignments SET ${updates.join(',')} WHERE id=?`, vals); if (result.affectedRows === 0) return res.status(404).json({ message: 'Task not found' }); }
    res.json({ message: 'Updated' });
  } catch (err) {
    console.error('PATCH /tasks/:id/progress error:', err.message);
    res.status(500).json({ message: 'Failed to update progress', error: err.message });
  }
});

router.delete('/tasks/:id', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const [result] = await db.query('DELETE FROM task_assignments WHERE id=?', [req.params.id]);
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Task not found' });
    res.json({ message: 'Deleted' });
  } catch (err) {
    console.error('DELETE /tasks/:id error:', err.message);
    res.status(500).json({ message: 'Failed to delete task', error: err.message });
  }
});

// ─── CLOCK IN/OUT ─────────────────────────────────────────────────────────────
router.post('/tasks/:id/clock-in', auth, async (req, res) => {
  try {
    const db = await getPool();
    const [[active]] = await db.query(
      "SELECT id FROM worker_time_logs WHERE worker_id=? AND clock_out IS NULL",
      [req.user.id]
    );
    if (active) return res.status(400).json({ message: 'Please clock out first' });
    await db.query('INSERT INTO worker_time_logs (task_id,worker_id,clock_in) VALUES (?,?,NOW())', [req.params.id, req.user.id]);
    await db.query("UPDATE task_assignments SET status='in_progress' WHERE id=? AND status='pending'", [req.params.id]);
    res.json({ message: 'Clocked in' });
  } catch (err) {
    console.error('POST /tasks/:id/clock-in error:', err.message);
    res.status(500).json({ message: 'Failed to clock in', error: err.message });
  }
});

router.post('/tasks/:id/clock-out', auth, async (req, res) => {
  try {
    const db = await getPool();
    const [[log]] = await db.query(
      "SELECT * FROM worker_time_logs WHERE task_id=? AND worker_id=? AND clock_out IS NULL",
      [req.params.id, req.user.id]
    );
    if (!log) return res.status(400).json({ message: 'No active session found' });
    await db.query(
      "UPDATE worker_time_logs SET clock_out=NOW(), duration_minutes=TIMESTAMPDIFF(MINUTE,clock_in,NOW()) WHERE id=?",
      [log.id]
    );
    res.json({ message: 'Clocked out' });
  } catch (err) {
    console.error('POST /tasks/:id/clock-out error:', err.message);
    res.status(500).json({ message: 'Failed to clock out', error: err.message });
  }
});

router.get('/tasks/:id/active-session', auth, async (req, res) => {
  try {
    const db = await getPool();
    const [[session]] = await db.query(
      "SELECT * FROM worker_time_logs WHERE task_id=? AND worker_id=? AND clock_out IS NULL",
      [req.params.id, req.user.id]
    );
    res.json(session || null);
  } catch (err) {
    console.error('GET /tasks/:id/active-session error:', err.message);
    res.status(500).json({ message: 'Failed to fetch active session', error: err.message });
  }
});

// ─── DAILY PROGRESS ──────────────────────────────────────────────────────────
router.post('/tasks/:id/daily-progress', auth, async (req, res) => {
  try {
    const { item_id, department_id, work_date, qty_done, notes } = req.body;
    const db = await getPool();
    await db.query(
      'INSERT INTO daily_progress (task_id,item_id,department_id,worker_id,work_date,qty_done,notes,created_by) VALUES (?,?,?,?,?,?,?,?)',
      [req.params.id, item_id, department_id, req.user.id, work_date || new Date().toISOString().split('T')[0], qty_done, notes, req.user.id]
    );
    res.status(201).json({ message: 'Progress saved' });
  } catch (err) {
    console.error('POST /tasks/:id/daily-progress error:', err.message);
    res.status(500).json({ message: 'Failed to save progress', error: err.message });
  }
});

router.get('/tasks/:id/daily-progress', auth, async (req, res) => {
  try {
    const db = await getPool();
    const [rows] = await db.query(
      `SELECT dp.*, u.name as worker_name, d.name as dept_name FROM daily_progress dp
       LEFT JOIN users u ON u.id=dp.worker_id LEFT JOIN departments d ON d.id=dp.department_id
       WHERE dp.task_id=? ORDER BY dp.work_date DESC, dp.created_at DESC`,
      [req.params.id]
    );
    res.json(rows);
  } catch (err) {
    console.error('GET /tasks/:id/daily-progress error:', err.message);
    res.status(500).json({ message: 'Failed to fetch progress', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// AREAS
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/areas', auth, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    let where = 'WHERE is_active=1';
    const params = [];
    if (orgId) { where += ' AND org_id=?'; params.push(orgId); }
    const [rows] = await db.query(`SELECT * FROM areas ${where} ORDER BY name`, params);
    res.json(rows);
  } catch (err) {
    console.error('GET /areas error:', err.message);
    res.status(500).json({ message: 'Failed to fetch areas', error: err.message });
  }
});

router.post('/areas', auth, adminOnly, async (req, res) => {
  try {
    const { name, city, state, description } = req.body;
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const [r] = await db.query('INSERT INTO areas (name,city,state,description,org_id) VALUES (?,?,?,?,?)', [name, city, state, description, orgId]);
    res.status(201).json({ id: r.insertId, name, city });
  } catch (err) {
    console.error('POST /areas error:', err.message);
    res.status(500).json({ message: 'Failed to create area', error: err.message });
  }
});

router.put('/areas/:id', auth, adminOnly, async (req, res) => {
  const { name, city, state, description, is_active } = req.body;
  const db = await getPool();
  await db.query('UPDATE areas SET name=?,city=?,state=?,description=?,is_active=? WHERE id=?', [name, city, state, description, is_active, req.params.id]);
  res.json({ message: 'Updated' });
});

router.delete('/areas/:id', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const [result] = await db.query('UPDATE areas SET is_active=0 WHERE id=?', [req.params.id]);
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Area not found' });
    res.json({ message: 'Deactivated' });
  } catch (err) {
    console.error('DELETE /areas/:id error:', err.message);
    res.status(500).json({ message: 'Failed to delete area', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// DOCTORS
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/doctors', auth, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const { area_id, search } = req.query;
    let where = 'WHERE d.is_active=1';
    const params = [];
    if (orgId) { where += ' AND d.org_id=?'; params.push(orgId); }
    if (area_id) { where += ' AND d.area_id=?'; params.push(area_id); }
    if (search) { where += ' AND (d.name LIKE ? OR d.clinic_name LIKE ? OR d.specialization LIKE ?)'; params.push(`%${search}%`, `%${search}%`, `%${search}%`); }
    const [rows] = await db.query(
      `SELECT d.*, a.name as area_name, a.city FROM doctors d LEFT JOIN areas a ON a.id=d.area_id ${where} ORDER BY d.name`,
      params
    );
    res.json(rows);
  } catch (err) {
    console.error('GET /doctors error:', err.message);
    res.status(500).json({ message: 'Failed to fetch doctors', error: err.message });
  }
});

router.post('/doctors', auth, adminOnly, async (req, res) => {
  try {
    const { name, specialization, clinic_name, phone, email, address, area_id, latitude, longitude } = req.body;
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const safeLat = (latitude && latitude !== '') ? latitude : null;
    const safeLng = (longitude && longitude !== '') ? longitude : null;
    const [r] = await db.query(
      'INSERT INTO doctors (name,specialization,clinic_name,phone,email,address,area_id,latitude,longitude,org_id) VALUES (?,?,?,?,?,?,?,?,?,?)',
      [name, specialization, clinic_name, phone, email, address, area_id, safeLat, safeLng, orgId]
    );
    res.status(201).json({ id: r.insertId, name });
  } catch (err) {
    console.error('POST /doctors error:', err.message);
    res.status(500).json({ message: 'Failed to create doctor', error: err.message });
  }
});

router.put('/doctors/:id', auth, adminOnly, async (req, res) => {
  try {
    const { name, specialization, clinic_name, phone, email, address, area_id, latitude, longitude, is_active } = req.body;
    const db = await getPool();
    const safeLat = (latitude && latitude !== '') ? latitude : null;
    const safeLng = (longitude && longitude !== '') ? longitude : null;
    const [result] = await db.query(
      'UPDATE doctors SET name=?,specialization=?,clinic_name=?,phone=?,email=?,address=?,area_id=?,latitude=?,longitude=?,is_active=? WHERE id=?',
      [name, specialization, clinic_name, phone, email, address, area_id, safeLat, safeLng, is_active, req.params.id]
    );
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Doctor not found' });
    res.json({ message: 'Updated' });
  } catch (err) {
    console.error('PUT /doctors/:id error:', err.message);
    res.status(500).json({ message: 'Failed to update doctor', error: err.message });
  }
});

router.delete('/doctors/:id', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const [result] = await db.query('UPDATE doctors SET is_active=0 WHERE id=?', [req.params.id]);
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Doctor not found' });
    res.json({ message: 'Deleted' });
  } catch (err) {
    console.error('DELETE /doctors/:id error:', err.message);
    res.status(500).json({ message: 'Failed to delete doctor', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// VISIT PLANS
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/visit-plans', auth, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const { worker_id, date, status } = req.query;
    let where = 'WHERE 1=1';
    const params = [];
    // Org filter
    if (orgId) { where += ' AND vp.org_id=?'; params.push(orgId); }
    // Field workers can only see their own plans
    const wid = req.user.role === 'field_worker' ? req.user.id : worker_id;
    if (wid) { where += ' AND vp.worker_id=?'; params.push(wid); }
    // Field worker ke liye aaj ke aur future ke plans — status filter optional rakho
    if (date) { where += ' AND vp.planned_date=?'; params.push(date); }
    else if (req.user.role === 'field_worker') {
      // Aaj aur future ke sab plans dikhao
      where += ' AND vp.planned_date >= CURDATE()';
    }
    if (status) { where += ' AND vp.status=?'; params.push(status); }
    const [rows] = await db.query(
      `SELECT vp.*, u.name as worker_name, doc.name as doctor_name, doc.clinic_name, doc.specialization, doc.phone as doctor_phone, a.name as area_name
       FROM visit_plans vp
       JOIN users u ON u.id=vp.worker_id
       JOIN doctors doc ON doc.id=vp.doctor_id
       LEFT JOIN areas a ON a.id=doc.area_id
       ${where} ORDER BY vp.planned_date ASC, vp.id DESC`,
      params
    );
    res.json(rows);
  } catch (err) {
    console.error('GET /visit-plans error:', err.message);
    res.status(500).json({ message: 'Failed to fetch visit plans', error: err.message });
  }
});

router.post('/visit-plans', auth, adminOnly, async (req, res) => {
  try {
    const { worker_id, doctor_id, planned_date, purpose, sample_products, admin_notes } = req.body;
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const [r] = await db.query(
      'INSERT INTO visit_plans (worker_id,doctor_id,planned_date,purpose,sample_products,admin_notes,created_by,org_id) VALUES (?,?,?,?,?,?,?,?)',
      [worker_id, doctor_id, planned_date, purpose, sample_products, admin_notes, req.user.id, orgId]
    );
    res.status(201).json({ id: r.insertId });
  } catch (err) {
    console.error('POST /visit-plans error:', err.message);
    res.status(500).json({ message: 'Failed to create visit plan', error: err.message });
  }
});

router.put('/visit-plans/:id', auth, adminOnly, async (req, res) => {
  try {
    const { planned_date, purpose, sample_products, status, admin_notes } = req.body;
    const db = await getPool();
    const [result] = await db.query(
      'UPDATE visit_plans SET planned_date=?,purpose=?,sample_products=?,status=?,admin_notes=? WHERE id=?',
      [planned_date, purpose, sample_products, status, admin_notes, req.params.id]
    );
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Visit plan not found' });
    res.json({ message: 'Updated' });
  } catch (err) {
    console.error('PUT /visit-plans/:id error:', err.message);
    res.status(500).json({ message: 'Failed to update visit plan', error: err.message });
  }
});

router.delete('/visit-plans/:id', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const [result] = await db.query('DELETE FROM visit_plans WHERE id=?', [req.params.id]);
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Visit plan not found' });
    res.json({ message: 'Deleted' });
  } catch (err) {
    console.error('DELETE /visit-plans/:id error:', err.message);
    res.status(500).json({ message: 'Failed to delete visit plan', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// FIELD SESSIONS (START / END)
// ═══════════════════════════════════════════════════════════════════════════════
router.post('/field/session/start', auth, async (req, res) => {
  try {
    const { latitude, longitude } = req.body;
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const safeLat = (latitude && latitude !== '') ? latitude : null;
    const safeLng = (longitude && longitude !== '') ? longitude : null;
    const [[active]] = await db.query(
      "SELECT id FROM field_sessions WHERE worker_id=? AND status='active'",
      [req.user.id]
    );
    if (active) return res.status(400).json({ message: 'Session already active', session_id: active.id });
    const [r] = await db.query(
      'INSERT INTO field_sessions (worker_id,start_time,start_location_lat,start_location_lng,org_id) VALUES (?,NOW(),?,?,?)',
      [req.user.id, safeLat, safeLng, orgId]
    );
    if (safeLat && safeLng) {
      await db.query(
        'INSERT INTO location_pings (session_id,worker_id,latitude,longitude,recorded_at) VALUES (?,?,?,?,NOW())',
        [r.insertId, req.user.id, safeLat, safeLng]
      );
    }
    res.json({ session_id: r.insertId, message: 'Session started' });
  } catch (err) {
    console.error('POST /field/session/start error:', err.message);
    res.status(500).json({ message: 'Failed to start session', error: err.message });
  }
});

router.post('/field/session/end', auth, async (req, res) => {
  try {
    const { latitude, longitude, total_distance_km, notes } = req.body;
    const db = await getPool();
    const safeLat = (latitude && latitude !== '') ? latitude : null;
    const safeLng = (longitude && longitude !== '') ? longitude : null;
    const [[session]] = await db.query(
      "SELECT * FROM field_sessions WHERE worker_id=? AND status='active'",
      [req.user.id]
    );
    if (!session) return res.status(400).json({ message: 'No active session' });
    const duration = Math.round((Date.now() - new Date(session.start_time)) / 60000);
    await db.query(
      "UPDATE field_sessions SET end_time=NOW(), end_location_lat=?, end_location_lng=?, total_distance_km=?, duration_minutes=?, status='completed', notes=? WHERE id=?",
      [safeLat, safeLng, total_distance_km || 0, duration, notes, session.id]
    );
    res.json({ message: 'Session ended', duration_minutes: duration });
  } catch (err) {
    console.error('POST /field/session/end error:', err.message);
    res.status(500).json({ message: 'Failed to end session', error: err.message });
  }
});

router.get('/field/session/active', auth, async (req, res) => {
  try {
    const db = await getPool();
    const [[session]] = await db.query(
      "SELECT * FROM field_sessions WHERE worker_id=? AND status='active'",
      [req.user.id]
    );
    res.json(session || null);
  } catch (err) {
    console.error('GET /field/session/active error:', err.message);
    res.status(500).json({ message: 'Failed to fetch active session', error: err.message });
  }
});

router.get('/field/sessions', auth, async (req, res) => {
  try {
    const db = await getPool();
    const worker_id = req.user.role === 'field_worker' ? req.user.id : (req.query.worker_id || null);
    const { date_from, date_to } = req.query;
    let where = 'WHERE 1=1';
    const params = [];
    if (worker_id) { where += ' AND fs.worker_id=?'; params.push(worker_id); }
    if (date_from) { where += ' AND DATE(fs.start_time)>=?'; params.push(date_from); }
    if (date_to) { where += ' AND DATE(fs.start_time)<=?'; params.push(date_to); }
    const [rows] = await db.query(
      `SELECT fs.*, u.name as worker_name,
       (SELECT COUNT(*) FROM doctor_visits WHERE session_id=fs.id) as visit_count
       FROM field_sessions fs JOIN users u ON u.id=fs.worker_id
       ${where} ORDER BY fs.start_time DESC`,
      params
    );
    res.json(rows);
  } catch (err) {
    console.error('GET /field/sessions error:', err.message);
    res.status(500).json({ message: 'Failed to fetch sessions', error: err.message });
  }
});

router.get('/field/sessions/:id', auth, async (req, res) => {
  try {
    const db = await getPool();
    const [[session]] = await db.query(
      `SELECT fs.*, u.name as worker_name FROM field_sessions fs JOIN users u ON u.id=fs.worker_id WHERE fs.id=?`,
      [req.params.id]
    );
    if (!session) return res.status(404).json({ message: 'Session not found' });
    const [visits] = await db.query(
      `SELECT dv.*, doc.name as doctor_name, doc.clinic_name, doc.specialization, doc.phone as doctor_phone, a.name as area_name
       FROM doctor_visits dv JOIN doctors doc ON doc.id=dv.doctor_id
       LEFT JOIN areas a ON a.id=doc.area_id
       WHERE dv.session_id=? ORDER BY dv.arrival_time`,
      [req.params.id]
    );
    const [pings] = await db.query(
      'SELECT latitude, longitude, recorded_at FROM location_pings WHERE session_id=? ORDER BY recorded_at',
      [req.params.id]
    );
    res.json({ ...session, visits, pings });
  } catch (err) {
    console.error('GET /field/sessions/:id error:', err.message);
    res.status(500).json({ message: 'Failed to fetch session', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// DOCTOR VISITS
// ═══════════════════════════════════════════════════════════════════════════════
router.post('/field/visits', auth, async (req, res) => {
  try {
    const {
      session_id, doctor_id, visit_plan_id,
      visit_type,
      arrival_lat, arrival_lng,
      product_id, samples_given,
      order_received, order_amount,
      photo_url,
      doctor_feedback, outcome, failure_reason, notes,
      distance_from_prev_km, travel_time_minutes
    } = req.body;
    const db = await getPool();
    const safeLat = (arrival_lat && arrival_lat !== '') ? parseFloat(arrival_lat) : null;
    const safeLng = (arrival_lng && arrival_lng !== '') ? parseFloat(arrival_lng) : null;

    // ── Geofencing check ──
    let geoVerified = 0;
    let distanceFromDoctorM = 0;
    if (safeLat && safeLng && doctor_id) {
      const [[doc]] = await db.query('SELECT latitude, longitude FROM doctors WHERE id=?', [doctor_id]);
      if (doc && doc.latitude && doc.longitude) {
        // Haversine formula
        const R = 6371000;
        const dLat = (safeLat - doc.latitude) * Math.PI / 180;
        const dLon = (safeLng - doc.longitude) * Math.PI / 180;
        const a = Math.sin(dLat/2)**2 + Math.cos(doc.latitude * Math.PI/180) * Math.cos(safeLat * Math.PI/180) * Math.sin(dLon/2)**2;
        distanceFromDoctorM = Math.round(R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a)));
        // Get allowed radius from settings (default 500m)
        const [[setting]] = await db.query("SELECT setting_value FROM app_settings WHERE setting_key='geofence_radius_m'");
        const allowedRadius = setting ? parseInt(setting.setting_value) : 500;
        geoVerified = distanceFromDoctorM <= allowedRadius ? 1 : 0;
      }
    }

    const orgId = await getOrgId(req.user.id);
    const [r] = await db.query(
      `INSERT INTO doctor_visits
       (session_id,worker_id,doctor_id,visit_plan_id,visit_type,arrival_time,arrival_lat,arrival_lng,
        product_id,samples_given,order_received,order_amount,photo_url,
        doctor_feedback,outcome,failure_reason,notes,
        distance_from_prev_km,travel_time_minutes,geo_verified,distance_from_doctor_m,org_id)
       VALUES (?,?,?,?,?,NOW(),?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [session_id, req.user.id, doctor_id, visit_plan_id || null,
       visit_type || 'doctor', safeLat, safeLng,
       product_id || null, samples_given,
       order_received ? 1 : 0, order_amount || 0, photo_url || null,
       doctor_feedback, outcome || 'sample_given', failure_reason || null, notes,
       distance_from_prev_km || 0, travel_time_minutes || 0,
       geoVerified, distanceFromDoctorM, orgId]
    );
    if (visit_plan_id) {
      await db.query("UPDATE visit_plans SET status='completed' WHERE id=?", [visit_plan_id]);
    }
    res.status(201).json({ id: r.insertId, message: 'Visit recorded', geo_verified: geoVerified, distance_from_doctor_m: distanceFromDoctorM });
  } catch (err) {
    console.error('POST /field/visits error:', err.message);
    res.status(500).json({ message: 'Failed to record visit', error: err.message });
  }
});

router.put('/field/visits/:id/depart', auth, async (req, res) => {
  try {
    const db = await getPool();
    const [[visit]] = await db.query('SELECT * FROM doctor_visits WHERE id=? AND worker_id=?', [req.params.id, req.user.id]);
    if (!visit) return res.status(404).json({ message: 'Visit not found' });
    const duration = Math.round((Date.now() - new Date(visit.arrival_time)) / 60000);
    await db.query(
      'UPDATE doctor_visits SET departure_time=NOW(), duration_minutes=? WHERE id=?',
      [duration, req.params.id]
    );
    res.json({ message: 'Departure recorded', duration_minutes: duration });
  } catch (err) {
    console.error('PUT /field/visits/:id/depart error:', err.message);
    res.status(500).json({ message: 'Failed to record departure', error: err.message });
  }
});

router.put('/field/visits/:id', auth, async (req, res) => {
  try {
    const { visit_type, product_id, samples_given, order_received, order_amount, photo_url, doctor_feedback, outcome, failure_reason, notes } = req.body;
    const db = await getPool();
    const [result] = await db.query(
      'UPDATE doctor_visits SET visit_type=?,product_id=?,samples_given=?,order_received=?,order_amount=?,photo_url=?,doctor_feedback=?,outcome=?,failure_reason=?,notes=? WHERE id=? AND worker_id=?',
      [visit_type || 'doctor', product_id || null, samples_given, order_received ? 1 : 0, order_amount || 0, photo_url || null, doctor_feedback, outcome, failure_reason || null, notes, req.params.id, req.user.id]
    );
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Visit not found' });
    res.json({ message: 'Updated' });
  } catch (err) {
    console.error('PUT /field/visits/:id error:', err.message);
    res.status(500).json({ message: 'Failed to update visit', error: err.message });
  }
});

router.get('/field/visits', auth, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const worker_id = req.user.role === 'field_worker' ? req.user.id : (req.query.worker_id || null);
    const { date_from, date_to, doctor_id, outcome, visit_type } = req.query;
    let where = 'WHERE 1=1';
    const params = [];
    if (orgId) { where += ' AND dv.org_id=?'; params.push(orgId); }
    if (worker_id) { where += ' AND dv.worker_id=?'; params.push(worker_id); }
    if (date_from) { where += ' AND DATE(dv.arrival_time)>=?'; params.push(date_from); }
    if (date_to) { where += ' AND DATE(dv.arrival_time)<=?'; params.push(date_to); }
    if (doctor_id) { where += ' AND dv.doctor_id=?'; params.push(doctor_id); }
    if (outcome) { where += ' AND dv.outcome=?'; params.push(outcome); }
    if (visit_type) { where += ' AND dv.visit_type=?'; params.push(visit_type); }
    const [rows] = await db.query(
      `SELECT dv.*, u.name as worker_name, u.id as staff_id,
       doc.name as doctor_name, doc.clinic_name, doc.specialization,
       a.name as area_name,
       sp.name as product_name
       FROM doctor_visits dv
       JOIN users u ON u.id=dv.worker_id
       JOIN doctors doc ON doc.id=dv.doctor_id
       LEFT JOIN areas a ON a.id=doc.area_id
       LEFT JOIN sample_products sp ON sp.id=dv.product_id
       ${where} ORDER BY dv.arrival_time DESC`,
      params
    );
    res.json(rows);
  } catch (err) {
    console.error('GET /field/visits error:', err.message);
    res.status(500).json({ message: 'Failed to fetch visits', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// LOCATION PINGS
// ═══════════════════════════════════════════════════════════════════════════════
router.post('/field/location', auth, async (req, res) => {
  try {
    const { session_id, latitude, longitude, accuracy, speed, heading } = req.body;
    const db = await getPool();
    await db.query(
      'INSERT INTO location_pings (session_id,worker_id,latitude,longitude,accuracy,speed,heading,recorded_at) VALUES (?,?,?,?,?,?,?,NOW())',
      [session_id, req.user.id, latitude, longitude, accuracy, speed, heading]
    );
    res.json({ message: 'Ping saved' });
  } catch (err) {
    console.error('POST /field/location error:', err.message);
    res.status(500).json({ message: 'Failed to save location', error: err.message });
  }
});

router.get('/field/location/live', auth, async (req, res) => {
  try {
    const db = await getPool();
    const [rows] = await db.query(
      `SELECT u.id as worker_id, u.name as worker_name, lp.latitude, lp.longitude, lp.recorded_at, fs.id as session_id
       FROM users u
       JOIN field_sessions fs ON fs.worker_id=u.id AND fs.status='active'
       JOIN location_pings lp ON lp.session_id=fs.id AND lp.id=(
         SELECT id FROM location_pings WHERE session_id=fs.id ORDER BY recorded_at DESC LIMIT 1
       )
       WHERE u.role='field_worker' AND u.is_active=1`
    );
    res.json(rows);
  } catch (err) {
    console.error('GET /field/location/live error:', err.message);
    res.status(500).json({ message: 'Failed to fetch live locations', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// SAMPLE PRODUCTS
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/samples', auth, async (req, res) => {
  try {
    const db = await getPool();
    const [rows] = await db.query("SELECT * FROM sample_products WHERE is_active=1 ORDER BY name");
    res.json(rows);
  } catch (err) {
    console.error('GET /samples error:', err.message);
    res.status(500).json({ message: 'Failed to fetch samples', error: err.message });
  }
});
router.post('/samples', auth, adminOnly, async (req, res) => {
  try {
    const { name, category, description } = req.body;
    const db = await getPool();
    const [r] = await db.query('INSERT INTO sample_products (name,category,description) VALUES (?,?,?)', [name, category, description]);
    res.status(201).json({ id: r.insertId, name });
  } catch (err) {
    console.error('POST /samples error:', err.message);
    res.status(500).json({ message: 'Failed to create sample', error: err.message });
  }
});
router.put('/samples/:id', auth, adminOnly, async (req, res) => {
  try {
    const { name, category, description, is_active } = req.body;
    const db = await getPool();
    const [result] = await db.query('UPDATE sample_products SET name=?,category=?,description=?,is_active=? WHERE id=?', [name, category, description, is_active, req.params.id]);
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Sample not found' });
    res.json({ message: 'Updated' });
  } catch (err) {
    console.error('PUT /samples/:id error:', err.message);
    res.status(500).json({ message: 'Failed to update sample', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// PHOTO UPLOAD (Base64 stored as URL / text)
// ═══════════════════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════════════════════
// PHOTO UPLOAD — Cloudinary
// ═══════════════════════════════════════════════════════════════════════════════
const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME || '';
const CLOUDINARY_API_KEY    = process.env.CLOUDINARY_API_KEY    || '';
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET || '';

// Multipart form-data upload using Node built-in https (no fetch required)
function cloudinaryUpload(cloudName, apiKey, apiSecret, base64Data, folder, publicId) {
  return new Promise((resolve, reject) => {
    const crypto    = require('crypto');
    const https     = require('https');
    const timestamp = Math.floor(Date.now() / 1000);

    // Strip data URI prefix if present (data:image/jpeg;base64,...)
    const cleanBase64 = base64Data.replace(/^data:image\/\w+;base64,/, '');

    // Signature
    const sigStr    = `folder=${folder}&public_id=${publicId}&timestamp=${timestamp}${apiSecret}`;
    const signature = crypto.createHash('sha1').update(sigStr).digest('hex');

    // Build multipart/form-data manually
    const boundary = `----CloudinaryBoundary${Date.now()}`;
    const CRLF = '\r\n';

    const fields = {
      file:       `data:image/jpeg;base64,${cleanBase64}`,
      api_key:    apiKey,
      timestamp:  String(timestamp),
      signature:  signature,
      folder:     folder,
      public_id:  publicId,
    };

    let body = '';
    for (const [key, val] of Object.entries(fields)) {
      body += `--${boundary}${CRLF}`;
      body += `Content-Disposition: form-data; name="${key}"${CRLF}${CRLF}`;
      body += `${val}${CRLF}`;
    }
    body += `--${boundary}--${CRLF}`;

    const bodyBuf = Buffer.from(body, 'utf8');

    const options = {
      hostname: 'api.cloudinary.com',
      path:     `/v1_1/${cloudName}/image/upload`,
      method:   'POST',
      headers:  {
        'Content-Type':   `multipart/form-data; boundary=${boundary}`,
        'Content-Length': bodyBuf.length,
      },
    };

    const req2 = https.request(options, (resp) => {
      let data = '';
      resp.on('data', chunk => { data += chunk; });
      resp.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.error) reject(new Error(json.error.message));
          else resolve(json);
        } catch (e) { reject(new Error('Invalid Cloudinary response')); }
      });
    });
    req2.on('error', reject);
    req2.write(bodyBuf);
    req2.end();
  });
}

router.post('/field/upload-photo', auth, async (req, res) => {
  try {
    const { image_base64 } = req.body;
    if (!image_base64) return res.status(400).json({ message: 'image_base64 is required' });

    if (!CLOUDINARY_CLOUD_NAME || !CLOUDINARY_API_KEY || !CLOUDINARY_API_SECRET) {
      return res.status(500).json({ message: 'Cloudinary is not configured. Set CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET in environment variables.' });
    }

    const timestamp = Math.floor(Date.now() / 1000);
    const folder    = 'field_visits';
    const publicId  = `visit_${req.user.id}_${timestamp}`;

    const uploadData = await cloudinaryUpload(
      CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET,
      image_base64, folder, publicId
    );

    res.json({ url: uploadData.secure_url, message: 'Photo uploaded successfully' });

  } catch (err) {
    console.error('POST /field/upload-photo error:', err.message);
    res.status(500).json({ message: 'Photo upload failed', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// DOCTOR-WISE VISIT HISTORY
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/doctors/:id/visits', auth, async (req, res) => {
  try {
    const db = await getPool();
    const { date_from, date_to } = req.query;
    let where = 'WHERE dv.doctor_id=?';
    const params = [req.params.id];
    if (date_from) { where += ' AND DATE(dv.arrival_time)>=?'; params.push(date_from); }
    if (date_to) { where += ' AND DATE(dv.arrival_time)<=?'; params.push(date_to); }
    const [visits] = await db.query(
      `SELECT dv.*, u.name as worker_name, u.id as staff_id,
       sp.name as product_name, a.name as area_name
       FROM doctor_visits dv
       JOIN users u ON u.id=dv.worker_id
       LEFT JOIN sample_products sp ON sp.id=dv.product_id
       LEFT JOIN doctors doc ON doc.id=dv.doctor_id
       LEFT JOIN areas a ON a.id=doc.area_id
       ${where} ORDER BY dv.arrival_time DESC`,
      params
    );
    const [[doctor]] = await db.query(
      `SELECT d.*, a.name as area_name FROM doctors d LEFT JOIN areas a ON a.id=d.area_id WHERE d.id=?`,
      [req.params.id]
    );
    const [[stats]] = await db.query(
      `SELECT COUNT(*) as total_visits,
       SUM(order_received=1) as orders_received,
       SUM(outcome='failed') as failed_visits,
       SUM(duration_minutes) as total_time_min
       FROM doctor_visits WHERE doctor_id=?`,
      [req.params.id]
    );
    res.json({ doctor, visits, stats });
  } catch (err) {
    console.error('GET /doctors/:id/visits error:', err.message);
    res.status(500).json({ message: 'Failed to fetch doctor visit history', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// EXCEL EXPORT
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/export/visits', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const { date_from, date_to, worker_id } = req.query;
    let where = 'WHERE 1=1';
    const params = [];
    if (date_from) { where += ' AND DATE(dv.arrival_time)>=?'; params.push(date_from); }
    if (date_to) { where += ' AND DATE(dv.arrival_time)<=?'; params.push(date_to); }
    if (worker_id) { where += ' AND dv.worker_id=?'; params.push(worker_id); }
    const [rows] = await db.query(
      `SELECT u.id as staff_id, u.name as staff_name,
       doc.name as doctor_name, doc.clinic_name,
       a.name as area_name,
       dv.visit_type,
       sp.name as product_name,
       dv.samples_given,
       dv.order_received,
       dv.order_amount,
       dv.outcome,
       dv.failure_reason,
       dv.arrival_lat, dv.arrival_lng,
       dv.arrival_time, dv.departure_time,
       dv.duration_minutes,
       dv.doctor_feedback,
       dv.notes,
       dv.photo_url,
       dv.geo_verified,
       dv.distance_from_doctor_m
       FROM doctor_visits dv
       JOIN users u ON u.id=dv.worker_id
       JOIN doctors doc ON doc.id=dv.doctor_id
       LEFT JOIN areas a ON a.id=doc.area_id
       LEFT JOIN sample_products sp ON sp.id=dv.product_id
       ${where} ORDER BY dv.arrival_time DESC`,
      params
    );

    // Build CSV
    const headers = [
      'Staff ID','Staff Name','Doctor/Chemist Name','Clinic Name','Area',
      'Visit Type','Product','Samples Given','Order Received','Order Amount',
      'Outcome','Failure Reason','Latitude','Longitude',
      'Arrival Time','Departure Time','Duration (min)',
      'Doctor Feedback','Notes','Photo URL','Geo Verified','Distance from Doctor (m)'
    ];
    const escape = v => {
      if (v === null || v === undefined) return '';
      const s = String(v);
      return s.includes(',') || s.includes('"') || s.includes('\n') ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const csvLines = [headers.join(',')];
    for (const r of rows) {
      csvLines.push([
        r.staff_id, r.staff_name, r.doctor_name, r.clinic_name || '', r.area_name || '',
        r.visit_type, r.product_name || r.samples_given || '', r.samples_given || '',
        r.order_received ? 'Yes' : 'No', r.order_amount || 0,
        r.outcome, r.failure_reason || '',
        r.arrival_lat || '', r.arrival_lng || '',
        r.arrival_time ? new Date(r.arrival_time).toLocaleString('en-IN') : '',
        r.departure_time ? new Date(r.departure_time).toLocaleString('en-IN') : '',
        r.duration_minutes || 0,
        r.doctor_feedback || '', r.notes || '', r.photo_url || '',
        r.geo_verified ? 'Yes' : 'No', r.distance_from_doctor_m || 0
      ].map(escape).join(','));
    }
    const csv = csvLines.join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="visits_export_${Date.now()}.csv"`);
    res.send(csv);
  } catch (err) {
    console.error('GET /export/visits error:', err.message);
    res.status(500).json({ message: 'Export failed', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// ALERTS — No Movement / Fake GPS Detection
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/alerts/no-movement', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    // Get active sessions where last ping was more than N minutes ago
    const [[setting]] = await db.query("SELECT setting_value FROM app_settings WHERE setting_key='no_movement_alert_minutes'");
    const thresholdMin = setting ? parseInt(setting.setting_value) : 30;
    const [stale] = await db.query(
      `SELECT fs.id as session_id, u.id as worker_id, u.name as worker_name,
       MAX(lp.recorded_at) as last_ping,
       TIMESTAMPDIFF(MINUTE, MAX(lp.recorded_at), NOW()) as minutes_since_ping
       FROM field_sessions fs
       JOIN users u ON u.id=fs.worker_id
       LEFT JOIN location_pings lp ON lp.session_id=fs.id
       WHERE fs.status='active'
       GROUP BY fs.id
       HAVING minutes_since_ping >= ? OR last_ping IS NULL`,
      [thresholdMin]
    );
    res.json({ threshold_minutes: thresholdMin, alerts: stale });
  } catch (err) {
    console.error('GET /alerts/no-movement error:', err.message);
    res.status(500).json({ message: 'Failed to check alerts', error: err.message });
  }
});

router.get('/alerts/fake-gps', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    // Detect suspicious visits: geo_verified=0 AND doctor has coordinates
    const [suspicious] = await db.query(
      `SELECT dv.id, dv.arrival_time, dv.distance_from_doctor_m,
       u.name as worker_name, u.id as staff_id,
       doc.name as doctor_name, a.name as area_name,
       dv.arrival_lat, dv.arrival_lng
       FROM doctor_visits dv
       JOIN users u ON u.id=dv.worker_id
       JOIN doctors doc ON doc.id=dv.doctor_id
       LEFT JOIN areas a ON a.id=doc.area_id
       WHERE dv.geo_verified=0
       AND doc.latitude IS NOT NULL
       AND dv.distance_from_doctor_m > 500
       AND DATE(dv.arrival_time) >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
       ORDER BY dv.arrival_time DESC`
    );
    res.json({ suspicious_visits: suspicious });
  } catch (err) {
    console.error('GET /alerts/fake-gps error:', err.message);
    res.status(500).json({ message: 'Failed to check fake GPS', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// REPORTS
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/reports/dashboard', auth, async (req, res) => {
  try {
    const db = await getPool();
    const [[orders]] = await db.query("SELECT COUNT(*) as total, SUM(status='active') as active, SUM(status='completed') as completed FROM production_orders WHERE status!='deleted'");
    const [[tasks]] = await db.query("SELECT COUNT(*) as total, SUM(status='in_progress') as in_progress, SUM(status='completed') as completed, SUM(status='pending') as pending FROM task_assignments");
    const [[workers]] = await db.query("SELECT COUNT(*) as production, 0 as field FROM users WHERE role='worker' AND is_active=1");
    const [[field_workers]] = await db.query("SELECT COUNT(*) as cnt FROM users WHERE role='field_worker' AND is_active=1");
    const [[visits_today]] = await db.query("SELECT COUNT(*) as cnt FROM doctor_visits WHERE DATE(arrival_time)=CURDATE()");
    const [[active_sessions]] = await db.query("SELECT COUNT(*) as cnt FROM field_sessions WHERE status='active'");
    const [[doctors]] = await db.query("SELECT COUNT(*) as cnt FROM doctors WHERE is_active=1");
    res.json({
      orders, tasks,
      workers: { production: workers.production, field: field_workers.cnt },
      visits_today: visits_today.cnt,
      active_sessions: active_sessions.cnt,
      doctors: doctors.cnt,
    });
  } catch (err) {
    console.error('GET /reports/dashboard error:', err.message);
    res.status(500).json({ message: 'Failed to fetch dashboard', error: err.message });
  }
});

router.get('/reports/field', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const { date_from, date_to, worker_id } = req.query;
    const from = date_from || new Date(Date.now() - 30*24*3600000).toISOString().split('T')[0];
    const to = date_to || new Date().toISOString().split('T')[0];
    let workerWhere = '';
    const params = [from, to];
    if (worker_id) { workerWhere = ' AND dv.worker_id=?'; params.push(worker_id); }
    const [visits_by_worker] = await db.query(
      `SELECT u.name as worker_name, COUNT(*) as visits, SUM(dv.duration_minutes) as total_time,
       SUM(dv.outcome='order_placed') as orders, SUM(dv.outcome='interested') as interested
       FROM doctor_visits dv JOIN users u ON u.id=dv.worker_id
       WHERE DATE(dv.arrival_time) BETWEEN ? AND ?${workerWhere}
       GROUP BY dv.worker_id ORDER BY visits DESC`,
      params
    );
    const [visits_by_area] = await db.query(
      `SELECT a.name as area_name, COUNT(*) as visits
       FROM doctor_visits dv JOIN doctors doc ON doc.id=dv.doctor_id
       LEFT JOIN areas a ON a.id=doc.area_id
       WHERE DATE(dv.arrival_time) BETWEEN ? AND ?${workerWhere}
       GROUP BY doc.area_id ORDER BY visits DESC`,
      [from, to, ...(worker_id ? [worker_id] : [])]
    );
    const [outcome_summary] = await db.query(
      `SELECT outcome, COUNT(*) as cnt FROM doctor_visits
       WHERE DATE(arrival_time) BETWEEN ? AND ?${workerWhere}
       GROUP BY outcome`,
      [from, to, ...(worker_id ? [worker_id] : [])]
    );
    res.json({ visits_by_worker, visits_by_area, outcome_summary });
  } catch (err) {
    console.error('GET /reports/field error:', err.message);
    res.status(500).json({ message: 'Failed to fetch field reports', error: err.message });
  }
});

router.get('/reports/production', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const [by_dept] = await db.query(
      `SELECT d.name as dept_name, d.color, COUNT(*) as tasks, SUM(t.status='completed') as done
       FROM task_assignments t JOIN departments d ON d.id=t.department_id
       GROUP BY t.department_id ORDER BY done DESC`
    );
    const [by_status] = await db.query(
      `SELECT status, COUNT(*) as cnt FROM task_assignments GROUP BY status`
    );
    const [recent_orders] = await db.query(
      `SELECT o.order_no, o.name, o.status, o.priority, o.deadline,
       (SELECT COUNT(*) FROM task_assignments WHERE order_id=o.id) as tasks,
       (SELECT COUNT(*) FROM task_assignments WHERE order_id=o.id AND status='completed') as done
       FROM production_orders o WHERE o.status != 'deleted' ORDER BY o.created_at DESC LIMIT 10`
    );
    res.json({ by_dept, by_status, recent_orders });
  } catch (err) {
    console.error('GET /reports/production error:', err.message);
    res.status(500).json({ message: 'Failed to fetch production reports', error: err.message });
  }
});

// ─── APP SETTINGS ─────────────────────────────────────────────────────────────
router.get('/settings', auth, async (req, res) => {
  try {
    const db = await getPool();
    const [rows] = await db.query('SELECT setting_key, setting_value FROM app_settings');
    const settings = {};
    rows.forEach(r => { settings[r.setting_key] = r.setting_value; });
    res.json(settings);
  } catch (err) {
    console.error('GET /settings error:', err.message);
    res.status(500).json({ message: 'Failed to fetch settings', error: err.message });
  }
});

router.put('/settings', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    for (const [k, v] of Object.entries(req.body)) {
      await db.query('INSERT INTO app_settings (setting_key, setting_value, updated_by) VALUES (?,?,?) ON DUPLICATE KEY UPDATE setting_value=?, updated_by=?', [k, v, req.user.id, v, req.user.id]);
    }
    res.json({ message: 'Settings saved' });
  } catch (err) {
    console.error('PUT /settings error:', err.message);
    res.status(500).json({ message: 'Failed to save settings', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// SUPER ADMIN
// ═══════════════════════════════════════════════════════════════════════════════
function superAdminOnly(req, res, next) {
  if (req.user.role !== 'super_admin') return res.status(403).json({ message: 'Super admin only' });
  next();
}

const ALL_MENUS = [
  { key: 'dashboard',      label: 'Dashboard',         icon: '📊' },
  { key: 'orders',         label: 'Production Orders',  icon: '📦' },
  { key: 'tasks',          label: 'Tasks',              icon: '✅' },
  { key: 'departments',    label: 'Departments',        icon: '🏭' },
  { key: 'workers',        label: 'Workers',            icon: '👷' },
  { key: 'doctors',        label: 'Doctors',            icon: '👨‍⚕️' },
  { key: 'areas',          label: 'Areas',              icon: '🗺️' },
  { key: 'visit-plans',    label: 'Visit Plans',        icon: '📋' },
  { key: 'field-tracking', label: 'Live Tracking',      icon: '📍' },
  { key: 'visits',         label: 'Visits Table',       icon: '🗒️' },
  { key: 'reports',        label: 'Reports & Alerts',   icon: '📈' },
  { key: 'settings',       label: 'Settings',           icon: '⚙️' },
];

// ── GET all organizations ────────────────────────────────────────────────────
router.get('/super/organizations', auth, superAdminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const [orgs] = await db.query(`
      SELECT o.*,
        (SELECT COUNT(*) FROM org_users ou JOIN users u ON u.id=ou.user_id WHERE ou.org_id=o.id AND u.role='admin') as admin_count,
        (SELECT COUNT(*) FROM org_users ou WHERE ou.org_id=o.id) as user_count
      FROM organizations o ORDER BY o.created_at DESC`);
    res.json(orgs);
  } catch (err) {
    console.error('GET /super/organizations error:', err.message);
    res.status(500).json({ message: 'Failed', error: err.message });
  }
});

// ── CREATE organization ──────────────────────────────────────────────────────
router.post('/super/organizations', auth, superAdminOnly, async (req, res) => {
  try {
    const { name, slug, owner_name, email, phone, address, license_expiry, max_users,
            admin_name, admin_username, admin_password, enabled_menus } = req.body;
    const db = await getPool();

    // Check slug unique
    const [[existing]] = await db.query('SELECT id FROM organizations WHERE slug=?', [slug]);
    if (existing) return res.status(400).json({ message: 'Slug already exists' });

    // Create org
    const [orgRes] = await db.query(
      `INSERT INTO organizations (name,slug,owner_name,email,phone,address,license_expiry,max_users)
       VALUES (?,?,?,?,?,?,?,?)`,
      [name, slug, owner_name, email, phone, address, license_expiry || null, max_users || 50]
    );
    const orgId = orgRes.insertId;

    // Create admin user for this org
    const bcrypt = require('bcryptjs');
    const hashed = bcrypt.hashSync(admin_password, 10);
    const [userRes] = await db.query(
      `INSERT INTO users (name,username,password,role) VALUES (?,?,?,?)`,
      [admin_name, admin_username, hashed, 'admin']
    );
    const userId = userRes.insertId;

    // Link user to org
    await db.query('INSERT INTO org_users (org_id,user_id) VALUES (?,?)', [orgId, userId]);

    // Set menu permissions
    const menus = enabled_menus || ALL_MENUS.map(m => m.key);
    for (const menuKey of ALL_MENUS.map(m => m.key)) {
      await db.query(
        'INSERT INTO org_permissions (org_id,menu_key,is_enabled) VALUES (?,?,?)',
        [orgId, menuKey, menus.includes(menuKey) ? 1 : 0]
      );
    }

    res.status(201).json({ id: orgId, name, admin_username });
  } catch (err) {
    console.error('POST /super/organizations error:', err.message);
    res.status(500).json({ message: 'Failed', error: err.message });
  }
});

// ── UPDATE organization ──────────────────────────────────────────────────────
router.put('/super/organizations/:id', auth, superAdminOnly, async (req, res) => {
  try {
    const { name, owner_name, email, phone, address, license_expiry, max_users, is_active } = req.body;
    const db = await getPool();
    await db.query(
      `UPDATE organizations SET name=?,owner_name=?,email=?,phone=?,address=?,
       license_expiry=?,max_users=?,is_active=? WHERE id=?`,
      [name, owner_name, email, phone, address,
       license_expiry || null, max_users || 50, is_active, req.params.id]
    );
    res.json({ message: 'Updated' });
  } catch (err) {
    console.error('PUT /super/organizations/:id error:', err.message);
    res.status(500).json({ message: 'Failed', error: err.message });
  }
});

// ── TOGGLE license (active/inactive) ────────────────────────────────────────
router.patch('/super/organizations/:id/toggle', auth, superAdminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const [[org]] = await db.query('SELECT is_active FROM organizations WHERE id=?', [req.params.id]);
    if (!org) return res.status(404).json({ message: 'Org not found' });
    const newStatus = org.is_active ? 0 : 1;
    await db.query('UPDATE organizations SET is_active=? WHERE id=?', [newStatus, req.params.id]);
    res.json({ is_active: newStatus, message: newStatus ? 'License activated' : 'License deactivated' });
  } catch (err) {
    console.error('PATCH /super/organizations/:id/toggle error:', err.message);
    res.status(500).json({ message: 'Failed', error: err.message });
  }
});

// ── GET/UPDATE org menu permissions ─────────────────────────────────────────
router.get('/super/organizations/:id/permissions', auth, superAdminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const [perms] = await db.query('SELECT menu_key, is_enabled FROM org_permissions WHERE org_id=?', [req.params.id]);
    // Return full menu list with enabled status
    const result = ALL_MENUS.map(m => {
      const p = perms.find(p => p.menu_key === m.key);
      return { ...m, is_enabled: p ? p.is_enabled : 1 };
    });
    res.json(result);
  } catch (err) {
    console.error('GET /super/organizations/:id/permissions error:', err.message);
    res.status(500).json({ message: 'Failed', error: err.message });
  }
});

router.put('/super/organizations/:id/permissions', auth, superAdminOnly, async (req, res) => {
  try {
    const { permissions } = req.body; // { 'dashboard': true, 'orders': false, ... }
    const db = await getPool();
    for (const [menuKey, enabled] of Object.entries(permissions)) {
      await db.query(
        `INSERT INTO org_permissions (org_id,menu_key,is_enabled) VALUES (?,?,?)
         ON DUPLICATE KEY UPDATE is_enabled=?`,
        [req.params.id, menuKey, enabled ? 1 : 0, enabled ? 1 : 0]
      );
    }
    res.json({ message: 'Permissions updated' });
  } catch (err) {
    console.error('PUT /super/organizations/:id/permissions error:', err.message);
    res.status(500).json({ message: 'Failed', error: err.message });
  }
});

// ── GET all menus list (for frontend) ───────────────────────────────────────
router.get('/super/menus', auth, superAdminOnly, async (req, res) => {
  res.json(ALL_MENUS);
});

// ── GET org users ────────────────────────────────────────────────────────────
router.get('/super/organizations/:id/users', auth, superAdminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const [users] = await db.query(
      `SELECT u.id, u.name, u.username, u.role, u.is_active, u.created_at
       FROM users u JOIN org_users ou ON ou.user_id=u.id
       WHERE ou.org_id=? ORDER BY u.role, u.name`,
      [req.params.id]
    );
    res.json(users);
  } catch (err) {
    console.error('GET /super/organizations/:id/users error:', err.message);
    res.status(500).json({ message: 'Failed', error: err.message });
  }
});

// ── DELETE organization (and all its data) ───────────────────────────────────
router.delete('/super/organizations/:id', auth, superAdminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const [[org]] = await db.query('SELECT * FROM organizations WHERE id=?', [req.params.id]);
    if (!org) return res.status(404).json({ message: 'Organization not found' });

    // Delete org data in order (FK constraints)
    await db.query('DELETE dv FROM doctor_visits dv WHERE dv.org_id=?', [req.params.id]);
    await db.query('DELETE lp FROM location_pings lp JOIN field_sessions fs ON lp.session_id=fs.id WHERE fs.org_id=?', [req.params.id]);
    await db.query('DELETE FROM field_sessions WHERE org_id=?', [req.params.id]);
    await db.query('DELETE FROM visit_plans WHERE org_id=?', [req.params.id]);
    await db.query('DELETE FROM doctors WHERE org_id=?', [req.params.id]);
    await db.query('DELETE FROM areas WHERE org_id=?', [req.params.id]);
    // Delete org users (but not super_admin)
    const [orgUsers] = await db.query("SELECT user_id FROM org_users WHERE org_id=?", [req.params.id]);
    for (const ou of orgUsers) {
      await db.query('DELETE FROM org_users WHERE user_id=?', [ou.user_id]);
      await db.query("DELETE FROM users WHERE id=? AND role != 'super_admin'", [ou.user_id]);
    }
    // Delete org itself (cascade handles org_permissions, org_users)
    await db.query('DELETE FROM organizations WHERE id=?', [req.params.id]);

    res.json({ message: `Organization "${org.name}" aur uska sab data delete ho gaya` });
  } catch (err) {
    console.error('DELETE /super/organizations/:id error:', err.message);
    res.status(500).json({ message: 'Delete failed', error: err.message });
  }
});

// ── ORG PERMISSIONS CHECK — used in auth flow (admin sees only allowed menus) ─
router.get('/my/permissions', auth, async (req, res) => {
  try {
    const db = await getPool();
    // super_admin gets everything
    if (req.user.role === 'super_admin') {
      return res.json({ menus: ALL_MENUS.map(m => m.key), is_active: true });
    }
    // Find org for this user
    const [[orgUser]] = await db.query(
      `SELECT o.id, o.is_active, o.license_expiry
       FROM organizations o JOIN org_users ou ON ou.org_id=o.id
       WHERE ou.user_id=?`,
      [req.user.id]
    );
    if (!orgUser) {
      // User not linked to any org — give full access (legacy/demo mode)
      return res.json({ menus: ALL_MENUS.map(m => m.key), is_active: true });
    }
    // Check license
    const isActive = orgUser.is_active &&
      (!orgUser.license_expiry || new Date(orgUser.license_expiry) >= new Date());
    if (!isActive) {
      return res.json({ menus: [], is_active: false, message: 'License expired or inactive' });
    }
    // Get enabled menus
    const [perms] = await db.query(
      'SELECT menu_key FROM org_permissions WHERE org_id=? AND is_enabled=1',
      [orgUser.id]
    );
    res.json({ menus: perms.map(p => p.menu_key), is_active: true, org_id: orgUser.id });
  } catch (err) {
    console.error('GET /my/permissions error:', err.message);
    res.status(500).json({ message: 'Failed', error: err.message });
  }
});

module.exports = router;
