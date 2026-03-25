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
    // get departments if worker
    let departments = [];
    if (user.role === 'worker') {
      const [depts] = await db.query(
        `SELECT d.* FROM departments d JOIN worker_departments wd ON wd.department_id=d.id WHERE wd.worker_id=?`,
        [user.id]
      );
      departments = depts;
    }
    // get areas if field_worker
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
  const { current_password, new_password } = req.body;
  const db = await getPool();
  const [[user]] = await db.query('SELECT * FROM users WHERE id=?', [req.user.id]);
  if (!bcrypt.compareSync(current_password, user.password))
    return res.status(400).json({ message: 'Current password wrong hai' });
  const hashed = bcrypt.hashSync(new_password, 10);
  await db.query('UPDATE users SET password=? WHERE id=?', [hashed, req.user.id]);
  res.json({ message: 'Password updated' });
});

// ═══════════════════════════════════════════════════════════════════════════════
// DEPARTMENTS
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/departments', auth, async (req, res) => {
  const db = await getPool();
  const where = req.query.active_only === '1' ? 'WHERE is_active=1' : 'WHERE 1=1';
  const [rows] = await db.query(`SELECT * FROM departments ${where} ORDER BY stage_order, name`);
  res.json(rows);
});

router.post('/departments', auth, adminOnly, async (req, res) => {
  const { name, description, color, stage_order } = req.body;
  const db = await getPool();
  const [r] = await db.query(
    'INSERT INTO departments (name,description,color,stage_order) VALUES (?,?,?,?)',
    [name, description, color || '#3B82F6', stage_order || 999]
  );
  res.json({ id: r.insertId, name, description, color, stage_order });
});

router.put('/departments/:id', auth, adminOnly, async (req, res) => {
  const { name, description, color, stage_order, is_active } = req.body;
  const db = await getPool();
  await db.query(
    'UPDATE departments SET name=?,description=?,color=?,stage_order=?,is_active=? WHERE id=?',
    [name, description, color, stage_order, is_active, req.params.id]
  );
  res.json({ message: 'Updated' });
});

router.delete('/departments/:id', auth, adminOnly, async (req, res) => {
  const db = await getPool();
  await db.query('UPDATE departments SET is_active=0 WHERE id=?', [req.params.id]);
  res.json({ message: 'Deactivated' });
});

// ═══════════════════════════════════════════════════════════════════════════════
// USERS / WORKERS
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/workers', auth, async (req, res) => {
  const db = await getPool();
  const role = req.query.role || null;
  let where = "WHERE role != 'admin'";
  const params = [];
  if (role) { where += ' AND role=?'; params.push(role); }
  const [workers] = await db.query(`SELECT id,name,username,phone,role,hourly_rate,is_active,created_at FROM users ${where} ORDER BY name`, params);
  // get departments for production workers
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
});

router.post('/workers', auth, adminOnly, async (req, res) => {
  const { name, username, password, phone, role, hourly_rate, department_ids, area_ids } = req.body;
  const db = await getPool();
  const hashed = bcrypt.hashSync(password, 10);
  const [r] = await db.query(
    'INSERT INTO users (name,username,password,role,phone,hourly_rate) VALUES (?,?,?,?,?,?)',
    [name, username, hashed, role || 'worker', phone, hourly_rate || 0]
  );
  const uid = r.insertId;
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
});

router.put('/workers/:id', auth, adminOnly, async (req, res) => {
  const { name, phone, hourly_rate, is_active, department_ids, area_ids, role } = req.body;
  const db = await getPool();
  await db.query(
    'UPDATE users SET name=?,phone=?,hourly_rate=?,is_active=? WHERE id=?',
    [name, phone, hourly_rate || 0, is_active, req.params.id]
  );
  // update departments
  if (department_ids !== undefined && role === 'worker') {
    await db.query('DELETE FROM worker_departments WHERE worker_id=?', [req.params.id]);
    for (const did of department_ids || []) {
      await db.query('INSERT IGNORE INTO worker_departments (worker_id,department_id) VALUES (?,?)', [req.params.id, did]);
    }
  }
  // update areas
  if (area_ids !== undefined && role === 'field_worker') {
    await db.query('DELETE FROM field_worker_areas WHERE worker_id=?', [req.params.id]);
    for (const aid of area_ids || []) {
      await db.query('INSERT IGNORE INTO field_worker_areas (worker_id,area_id) VALUES (?,?)', [req.params.id, aid]);
    }
  }
  res.json({ message: 'Updated' });
});

router.delete('/workers/:id', auth, adminOnly, async (req, res) => {
  const db = await getPool();
  await db.query('UPDATE users SET is_active=0 WHERE id=?', [req.params.id]);
  res.json({ message: 'Deactivated' });
});

// ═══════════════════════════════════════════════════════════════════════════════
// PRODUCT CATEGORIES
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/product-categories', auth, async (req, res) => {
  const db = await getPool();
  const [rows] = await db.query('SELECT * FROM product_categories WHERE is_active=1 ORDER BY name');
  res.json(rows);
});
router.post('/product-categories', auth, adminOnly, async (req, res) => {
  const { name, description } = req.body;
  const db = await getPool();
  const [r] = await db.query('INSERT INTO product_categories (name,description) VALUES (?,?)', [name, description]);
  res.json({ id: r.insertId, name, description });
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
  const { order_no, name, category_id, client_name, client_phone, description, priority, order_date, deadline, total_amount, notes } = req.body;
  const db = await getPool();
  let finalOrderNo = order_no;
  if (!finalOrderNo || finalOrderNo.trim() === '') {
    const [[{ cnt }]] = await db.query('SELECT COUNT(*) as cnt FROM production_orders');
    finalOrderNo = `MO-${String(cnt + 1).padStart(4, '0')}`;
  }
  const [r] = await db.query(
    'INSERT INTO production_orders (order_no,name,category_id,client_name,client_phone,description,priority,order_date,deadline,total_amount,notes,created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
    [finalOrderNo, name, category_id, client_name, client_phone, description, priority || 'medium', order_date, deadline, total_amount || 0, notes, req.user.id]
  );
  res.json({ id: r.insertId, order_no: finalOrderNo, name });
});

router.get('/orders/:id', auth, async (req, res) => {
  const db = await getPool();
  const [[order]] = await db.query(
    `SELECT o.*, pc.name as category_name FROM production_orders o LEFT JOIN product_categories pc ON pc.id=o.category_id WHERE o.id=?`,
    [req.params.id]
  );
  if (!order) return res.status(404).json({ message: 'Not found' });
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
});

router.put('/orders/:id', auth, adminOnly, async (req, res) => {
  const { name, category_id, client_name, client_phone, description, status, priority, order_date, deadline, total_amount, notes } = req.body;
  const db = await getPool();
  await db.query(
    'UPDATE production_orders SET name=?,category_id=?,client_name=?,client_phone=?,description=?,status=?,priority=?,order_date=?,deadline=?,total_amount=?,notes=? WHERE id=?',
    [name, category_id, client_name, client_phone, description, status, priority, order_date, deadline, total_amount, notes, req.params.id]
  );
  res.json({ message: 'Updated' });
});

router.delete('/orders/:id', auth, adminOnly, async (req, res) => {
  const db = await getPool();
  await db.query("UPDATE production_orders SET status='deleted' WHERE id=?", [req.params.id]);
  res.json({ message: 'Deleted' });
});

// ─── PRODUCTION ITEMS ────────────────────────────────────────────────────────
router.post('/orders/:id/items', auth, adminOnly, async (req, res) => {
  const { item_name, item_code, description, quantity, unit, unit_price, notes } = req.body;
  const db = await getPool();
  const [r] = await db.query(
    'INSERT INTO production_items (order_id,item_name,item_code,description,quantity,unit,unit_price,notes) VALUES (?,?,?,?,?,?,?,?)',
    [req.params.id, item_name, item_code, description, quantity || 1, unit || 'pcs', unit_price || 0, notes]
  );
  res.json({ id: r.insertId, item_name });
});

router.put('/orders/:orderId/items/:id', auth, adminOnly, async (req, res) => {
  const { item_name, item_code, description, quantity, unit, unit_price, status, notes } = req.body;
  const db = await getPool();
  await db.query(
    'UPDATE production_items SET item_name=?,item_code=?,description=?,quantity=?,unit=?,unit_price=?,status=?,notes=? WHERE id=? AND order_id=?',
    [item_name, item_code, description, quantity, unit, unit_price, status, notes, req.params.id, req.params.orderId]
  );
  res.json({ message: 'Updated' });
});

router.delete('/orders/:orderId/items/:id', auth, adminOnly, async (req, res) => {
  const db = await getPool();
  await db.query('DELETE FROM production_items WHERE id=? AND order_id=?', [req.params.id, req.params.orderId]);
  res.json({ message: 'Deleted' });
});

// ─── PRODUCTION CHAIN ────────────────────────────────────────────────────────
router.post('/orders/:id/chain', auth, adminOnly, async (req, res) => {
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
});

// ═══════════════════════════════════════════════════════════════════════════════
// TASK ASSIGNMENTS (production tasks)
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/tasks/all', auth, adminOnly, async (req, res) => {
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
});

router.get('/tasks/my', auth, async (req, res) => {
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
});

router.post('/tasks', auth, adminOnly, async (req, res) => {
  const { order_id, item_id, assign_type, worker_id, department_id, stage_order, task_title, task_description, quantity_assigned, priority, start_date, due_date, admin_notes } = req.body;
  const db = await getPool();
  // Convert empty string to NULL to avoid FK constraint failure
  const safeWorkerId = (worker_id && worker_id !== '') ? worker_id : null;
  const safeDeptId = (department_id && department_id !== '') ? department_id : null;
  const safeDueDate = (due_date && due_date !== '') ? due_date : null;
  const safeStartDate = (start_date && start_date !== '') ? start_date : null;
  const [r] = await db.query(
    'INSERT INTO task_assignments (order_id,item_id,assign_type,worker_id,department_id,stage_order,task_title,task_description,quantity_assigned,priority,start_date,due_date,admin_notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
    [order_id, item_id, assign_type || 'worker', safeWorkerId, safeDeptId, stage_order || 0, task_title, task_description, quantity_assigned || 1, priority || 'medium', safeStartDate, safeDueDate, admin_notes]
  );
  res.json({ id: r.insertId, task_title });
});

router.put('/tasks/:id', auth, adminOnly, async (req, res) => {
  const { task_title, task_description, quantity_assigned, status, priority, start_date, due_date, admin_notes, worker_id, department_id } = req.body;
  const db = await getPool();
  // Convert empty string to NULL to avoid FK constraint failure
  const safeWorkerId = (worker_id && worker_id !== '') ? worker_id : null;
  const safeDeptId = (department_id && department_id !== '') ? department_id : null;
  const safeDueDate = (due_date && due_date !== '') ? due_date : null;
  const safeStartDate = (start_date && start_date !== '') ? start_date : null;
  await db.query(
    'UPDATE task_assignments SET task_title=?,task_description=?,quantity_assigned=?,status=?,priority=?,start_date=?,due_date=?,admin_notes=?,worker_id=?,department_id=? WHERE id=?',
    [task_title, task_description, quantity_assigned, status, priority, safeStartDate, safeDueDate, admin_notes, safeWorkerId, safeDeptId, req.params.id]
  );
  res.json({ message: 'Updated' });
});

router.patch('/tasks/:id/progress', auth, async (req, res) => {
  const { quantity_completed, status, worker_notes } = req.body;
  const db = await getPool();
  const updates = [];
  const vals = [];
  if (quantity_completed !== undefined) { updates.push('quantity_completed=?'); vals.push(quantity_completed); }
  if (status) { updates.push('status=?'); vals.push(status); if (status === 'completed') { updates.push('completed_date=CURDATE()'); } }
  if (worker_notes !== undefined) { updates.push('worker_notes=?'); vals.push(worker_notes); }
  vals.push(req.params.id);
  if (updates.length) await db.query(`UPDATE task_assignments SET ${updates.join(',')} WHERE id=?`, vals);
  res.json({ message: 'Updated' });
});

router.delete('/tasks/:id', auth, adminOnly, async (req, res) => {
  const db = await getPool();
  await db.query('DELETE FROM task_assignments WHERE id=?', [req.params.id]);
  res.json({ message: 'Deleted' });
});

// ─── CLOCK IN/OUT ─────────────────────────────────────────────────────────────
router.post('/tasks/:id/clock-in', auth, async (req, res) => {
  const db = await getPool();
  const [[active]] = await db.query(
    "SELECT id FROM worker_time_logs WHERE worker_id=? AND clock_out IS NULL",
    [req.user.id]
  );
  if (active) return res.status(400).json({ message: 'Pehle clock-out karo' });
  await db.query('INSERT INTO worker_time_logs (task_id,worker_id,clock_in) VALUES (?,?,NOW())', [req.params.id, req.user.id]);
  await db.query("UPDATE task_assignments SET status='in_progress' WHERE id=? AND status='pending'", [req.params.id]);
  res.json({ message: 'Clocked in' });
});

router.post('/tasks/:id/clock-out', auth, async (req, res) => {
  const db = await getPool();
  const [[log]] = await db.query(
    "SELECT * FROM worker_time_logs WHERE task_id=? AND worker_id=? AND clock_out IS NULL",
    [req.params.id, req.user.id]
  );
  if (!log) return res.status(400).json({ message: 'Active session nahi mili' });
  await db.query(
    "UPDATE worker_time_logs SET clock_out=NOW(), duration_minutes=TIMESTAMPDIFF(MINUTE,clock_in,NOW()) WHERE id=?",
    [log.id]
  );
  res.json({ message: 'Clocked out' });
});

router.get('/tasks/:id/active-session', auth, async (req, res) => {
  const db = await getPool();
  const [[session]] = await db.query(
    "SELECT * FROM worker_time_logs WHERE task_id=? AND worker_id=? AND clock_out IS NULL",
    [req.params.id, req.user.id]
  );
  res.json(session || null);
});

// ─── DAILY PROGRESS ──────────────────────────────────────────────────────────
router.post('/tasks/:id/daily-progress', auth, async (req, res) => {
  const { item_id, department_id, work_date, qty_done, notes } = req.body;
  const db = await getPool();
  await db.query(
    'INSERT INTO daily_progress (task_id,item_id,department_id,worker_id,work_date,qty_done,notes,created_by) VALUES (?,?,?,?,?,?,?,?)',
    [req.params.id, item_id, department_id, req.user.id, work_date || new Date().toISOString().split('T')[0], qty_done, notes, req.user.id]
  );
  res.json({ message: 'Progress saved' });
});

router.get('/tasks/:id/daily-progress', auth, async (req, res) => {
  const db = await getPool();
  const [rows] = await db.query(
    `SELECT dp.*, u.name as worker_name, d.name as dept_name FROM daily_progress dp
     LEFT JOIN users u ON u.id=dp.worker_id LEFT JOIN departments d ON d.id=dp.department_id
     WHERE dp.task_id=? ORDER BY dp.work_date DESC, dp.created_at DESC`,
    [req.params.id]
  );
  res.json(rows);
});

// ═══════════════════════════════════════════════════════════════════════════════
// AREAS
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/areas', auth, async (req, res) => {
  const db = await getPool();
  const [rows] = await db.query('SELECT * FROM areas WHERE is_active=1 ORDER BY name');
  res.json(rows);
});

router.post('/areas', auth, adminOnly, async (req, res) => {
  const { name, city, state, description } = req.body;
  const db = await getPool();
  const [r] = await db.query('INSERT INTO areas (name,city,state,description) VALUES (?,?,?,?)', [name, city, state, description]);
  res.json({ id: r.insertId, name, city, state });
});

router.put('/areas/:id', auth, adminOnly, async (req, res) => {
  const { name, city, state, description, is_active } = req.body;
  const db = await getPool();
  await db.query('UPDATE areas SET name=?,city=?,state=?,description=?,is_active=? WHERE id=?', [name, city, state, description, is_active, req.params.id]);
  res.json({ message: 'Updated' });
});

router.delete('/areas/:id', auth, adminOnly, async (req, res) => {
  const db = await getPool();
  await db.query('UPDATE areas SET is_active=0 WHERE id=?', [req.params.id]);
  res.json({ message: 'Deleted' });
});

// ═══════════════════════════════════════════════════════════════════════════════
// DOCTORS
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/doctors', auth, async (req, res) => {
  const db = await getPool();
  const { area_id, search } = req.query;
  let where = 'WHERE d.is_active=1';
  const params = [];
  if (area_id) { where += ' AND d.area_id=?'; params.push(area_id); }
  if (search) { where += ' AND (d.name LIKE ? OR d.clinic_name LIKE ? OR d.specialization LIKE ?)'; params.push(`%${search}%`, `%${search}%`, `%${search}%`); }
  const [rows] = await db.query(
    `SELECT d.*, a.name as area_name, a.city FROM doctors d LEFT JOIN areas a ON a.id=d.area_id ${where} ORDER BY d.name`,
    params
  );
  res.json(rows);
});

router.post('/doctors', auth, adminOnly, async (req, res) => {
  const { name, specialization, clinic_name, phone, email, address, area_id, latitude, longitude } = req.body;
  const db = await getPool();
  const [r] = await db.query(
    'INSERT INTO doctors (name,specialization,clinic_name,phone,email,address,area_id,latitude,longitude) VALUES (?,?,?,?,?,?,?,?,?)',
    [name, specialization, clinic_name, phone, email, address, area_id, latitude, longitude]
  );
  res.json({ id: r.insertId, name });
});

router.put('/doctors/:id', auth, adminOnly, async (req, res) => {
  const { name, specialization, clinic_name, phone, email, address, area_id, latitude, longitude, is_active } = req.body;
  const db = await getPool();
  await db.query(
    'UPDATE doctors SET name=?,specialization=?,clinic_name=?,phone=?,email=?,address=?,area_id=?,latitude=?,longitude=?,is_active=? WHERE id=?',
    [name, specialization, clinic_name, phone, email, address, area_id, latitude, longitude, is_active, req.params.id]
  );
  res.json({ message: 'Updated' });
});

router.delete('/doctors/:id', auth, adminOnly, async (req, res) => {
  const db = await getPool();
  await db.query('UPDATE doctors SET is_active=0 WHERE id=?', [req.params.id]);
  res.json({ message: 'Deleted' });
});

// ═══════════════════════════════════════════════════════════════════════════════
// VISIT PLANS
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/visit-plans', auth, async (req, res) => {
  const db = await getPool();
  const { worker_id, date, status } = req.query;
  let where = 'WHERE 1=1';
  const params = [];
  // field workers see only their own
  const wid = req.user.role === 'field_worker' ? req.user.id : worker_id;
  if (wid) { where += ' AND vp.worker_id=?'; params.push(wid); }
  if (date) { where += ' AND vp.planned_date=?'; params.push(date); }
  if (status) { where += ' AND vp.status=?'; params.push(status); }
  const [rows] = await db.query(
    `SELECT vp.*, u.name as worker_name, doc.name as doctor_name, doc.clinic_name, doc.specialization, doc.phone as doctor_phone, a.name as area_name
     FROM visit_plans vp
     JOIN users u ON u.id=vp.worker_id
     JOIN doctors doc ON doc.id=vp.doctor_id
     LEFT JOIN areas a ON a.id=doc.area_id
     ${where} ORDER BY vp.planned_date DESC, vp.id DESC`,
    params
  );
  res.json(rows);
});

router.post('/visit-plans', auth, adminOnly, async (req, res) => {
  const { worker_id, doctor_id, planned_date, purpose, sample_products, admin_notes } = req.body;
  const db = await getPool();
  const [r] = await db.query(
    'INSERT INTO visit_plans (worker_id,doctor_id,planned_date,purpose,sample_products,admin_notes,created_by) VALUES (?,?,?,?,?,?,?)',
    [worker_id, doctor_id, planned_date, purpose, sample_products, admin_notes, req.user.id]
  );
  res.json({ id: r.insertId });
});

router.put('/visit-plans/:id', auth, adminOnly, async (req, res) => {
  const { planned_date, purpose, sample_products, status, admin_notes } = req.body;
  const db = await getPool();
  await db.query(
    'UPDATE visit_plans SET planned_date=?,purpose=?,sample_products=?,status=?,admin_notes=? WHERE id=?',
    [planned_date, purpose, sample_products, status, admin_notes, req.params.id]
  );
  res.json({ message: 'Updated' });
});

router.delete('/visit-plans/:id', auth, adminOnly, async (req, res) => {
  const db = await getPool();
  await db.query('DELETE FROM visit_plans WHERE id=?', [req.params.id]);
  res.json({ message: 'Deleted' });
});

// ═══════════════════════════════════════════════════════════════════════════════
// FIELD SESSIONS (START / END)
// ═══════════════════════════════════════════════════════════════════════════════
router.post('/field/session/start', auth, async (req, res) => {
  const { latitude, longitude } = req.body;
  const db = await getPool();
  // check for existing active session
  const [[active]] = await db.query(
    "SELECT id FROM field_sessions WHERE worker_id=? AND status='active'",
    [req.user.id]
  );
  if (active) return res.status(400).json({ message: 'Session already active hai', session_id: active.id });
  const [r] = await db.query(
    'INSERT INTO field_sessions (worker_id,start_time,start_location_lat,start_location_lng) VALUES (?,NOW(),?,?)',
    [req.user.id, latitude, longitude]
  );
  // first ping
  if (latitude && longitude) {
    await db.query(
      'INSERT INTO location_pings (session_id,worker_id,latitude,longitude,recorded_at) VALUES (?,?,?,?,NOW())',
      [r.insertId, req.user.id, latitude, longitude]
    );
  }
  res.json({ session_id: r.insertId, message: 'Session started' });
});

router.post('/field/session/end', auth, async (req, res) => {
  const { latitude, longitude, total_distance_km, notes } = req.body;
  const db = await getPool();
  const [[session]] = await db.query(
    "SELECT * FROM field_sessions WHERE worker_id=? AND status='active'",
    [req.user.id]
  );
  if (!session) return res.status(400).json({ message: 'No active session' });
  const duration = Math.round((Date.now() - new Date(session.start_time)) / 60000);
  await db.query(
    "UPDATE field_sessions SET end_time=NOW(), end_location_lat=?, end_location_lng=?, total_distance_km=?, duration_minutes=?, status='completed', notes=? WHERE id=?",
    [latitude, longitude, total_distance_km || 0, duration, notes, session.id]
  );
  res.json({ message: 'Session ended', duration_minutes: duration });
});

router.get('/field/session/active', auth, async (req, res) => {
  const db = await getPool();
  const [[session]] = await db.query(
    "SELECT * FROM field_sessions WHERE worker_id=? AND status='active'",
    [req.user.id]
  );
  res.json(session || null);
});

router.get('/field/sessions', auth, async (req, res) => {
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
});

router.get('/field/sessions/:id', auth, async (req, res) => {
  const db = await getPool();
  const [[session]] = await db.query(
    `SELECT fs.*, u.name as worker_name FROM field_sessions fs JOIN users u ON u.id=fs.worker_id WHERE fs.id=?`,
    [req.params.id]
  );
  if (!session) return res.status(404).json({ message: 'Not found' });
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
});

// ═══════════════════════════════════════════════════════════════════════════════
// DOCTOR VISITS
// ═══════════════════════════════════════════════════════════════════════════════
router.post('/field/visits', auth, async (req, res) => {
  const { session_id, doctor_id, visit_plan_id, arrival_lat, arrival_lng, samples_given, doctor_feedback, outcome, notes, distance_from_prev_km, travel_time_minutes } = req.body;
  const db = await getPool();
  const [r] = await db.query(
    'INSERT INTO doctor_visits (session_id,worker_id,doctor_id,visit_plan_id,arrival_time,arrival_lat,arrival_lng,samples_given,doctor_feedback,outcome,notes,distance_from_prev_km,travel_time_minutes) VALUES (?,?,?,?,NOW(),?,?,?,?,?,?,?,?)',
    [session_id, req.user.id, doctor_id, visit_plan_id || null, arrival_lat, arrival_lng, samples_given, doctor_feedback, outcome || 'sample_given', notes, distance_from_prev_km || 0, travel_time_minutes || 0]
  );
  // mark visit plan as completed if provided
  if (visit_plan_id) {
    await db.query("UPDATE visit_plans SET status='completed' WHERE id=?", [visit_plan_id]);
  }
  res.json({ id: r.insertId, message: 'Visit recorded' });
});

router.put('/field/visits/:id/depart', auth, async (req, res) => {
  const db = await getPool();
  const [[visit]] = await db.query('SELECT * FROM doctor_visits WHERE id=? AND worker_id=?', [req.params.id, req.user.id]);
  if (!visit) return res.status(404).json({ message: 'Visit not found' });
  const duration = Math.round((Date.now() - new Date(visit.arrival_time)) / 60000);
  await db.query(
    'UPDATE doctor_visits SET departure_time=NOW(), duration_minutes=? WHERE id=?',
    [duration, req.params.id]
  );
  res.json({ message: 'Departure recorded', duration_minutes: duration });
});

router.put('/field/visits/:id', auth, async (req, res) => {
  const { samples_given, doctor_feedback, outcome, notes } = req.body;
  const db = await getPool();
  await db.query(
    'UPDATE doctor_visits SET samples_given=?,doctor_feedback=?,outcome=?,notes=? WHERE id=? AND worker_id=?',
    [samples_given, doctor_feedback, outcome, notes, req.params.id, req.user.id]
  );
  res.json({ message: 'Updated' });
});

router.get('/field/visits', auth, async (req, res) => {
  const db = await getPool();
  const worker_id = req.user.role === 'field_worker' ? req.user.id : (req.query.worker_id || null);
  const { date_from, date_to, doctor_id, outcome } = req.query;
  let where = 'WHERE 1=1';
  const params = [];
  if (worker_id) { where += ' AND dv.worker_id=?'; params.push(worker_id); }
  if (date_from) { where += ' AND DATE(dv.arrival_time)>=?'; params.push(date_from); }
  if (date_to) { where += ' AND DATE(dv.arrival_time)<=?'; params.push(date_to); }
  if (doctor_id) { where += ' AND dv.doctor_id=?'; params.push(doctor_id); }
  if (outcome) { where += ' AND dv.outcome=?'; params.push(outcome); }
  const [rows] = await db.query(
    `SELECT dv.*, u.name as worker_name, doc.name as doctor_name, doc.clinic_name, doc.specialization, a.name as area_name
     FROM doctor_visits dv
     JOIN users u ON u.id=dv.worker_id
     JOIN doctors doc ON doc.id=dv.doctor_id
     LEFT JOIN areas a ON a.id=doc.area_id
     ${where} ORDER BY dv.arrival_time DESC`,
    params
  );
  res.json(rows);
});

// ═══════════════════════════════════════════════════════════════════════════════
// LOCATION PINGS
// ═══════════════════════════════════════════════════════════════════════════════
router.post('/field/location', auth, async (req, res) => {
  const { session_id, latitude, longitude, accuracy, speed, heading } = req.body;
  const db = await getPool();
  await db.query(
    'INSERT INTO location_pings (session_id,worker_id,latitude,longitude,accuracy,speed,heading,recorded_at) VALUES (?,?,?,?,?,?,?,NOW())',
    [session_id, req.user.id, latitude, longitude, accuracy, speed, heading]
  );
  res.json({ message: 'Ping saved' });
});

router.get('/field/location/live', auth, async (req, res) => {
  const db = await getPool();
  // get latest ping for each active field worker
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
});

// ═══════════════════════════════════════════════════════════════════════════════
// SAMPLE PRODUCTS
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/samples', auth, async (req, res) => {
  const db = await getPool();
  const [rows] = await db.query("SELECT * FROM sample_products WHERE is_active=1 ORDER BY name");
  res.json(rows);
});
router.post('/samples', auth, adminOnly, async (req, res) => {
  const { name, category, description } = req.body;
  const db = await getPool();
  const [r] = await db.query('INSERT INTO sample_products (name,category,description) VALUES (?,?,?)', [name, category, description]);
  res.json({ id: r.insertId, name });
});
router.put('/samples/:id', auth, adminOnly, async (req, res) => {
  const { name, category, description, is_active } = req.body;
  const db = await getPool();
  await db.query('UPDATE sample_products SET name=?,category=?,description=?,is_active=? WHERE id=?', [name, category, description, is_active, req.params.id]);
  res.json({ message: 'Updated' });
});

// ═══════════════════════════════════════════════════════════════════════════════
// REPORTS
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/reports/dashboard', auth, async (req, res) => {
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
});

router.get('/reports/field', auth, adminOnly, async (req, res) => {
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
});

router.get('/reports/production', auth, adminOnly, async (req, res) => {
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
});

// ─── APP SETTINGS ─────────────────────────────────────────────────────────────
router.get('/settings', auth, async (req, res) => {
  const db = await getPool();
  const [rows] = await db.query('SELECT setting_key, setting_value FROM app_settings');
  const settings = {};
  rows.forEach(r => { settings[r.setting_key] = r.setting_value; });
  res.json(settings);
});

router.put('/settings', auth, adminOnly, async (req, res) => {
  const db = await getPool();
  for (const [k, v] of Object.entries(req.body)) {
    await db.query('INSERT INTO app_settings (setting_key, setting_value, updated_by) VALUES (?,?,?) ON DUPLICATE KEY UPDATE setting_value=?, updated_by=?', [k, v, req.user.id, v, req.user.id]);
  }
  res.json({ message: 'Settings saved' });
});

module.exports = router;
