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
//new force
// ═══════════════════════════════════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════════════════════════════════
router.post('/auth/login', async (req, res) => {
  const { username, password, org_slug } = req.body;
  const db = await getPool();
  try {
    // Try to find user — prefer exact match with org_slug if provided
    let user = null;

    if (org_slug) {
      // Org-scoped login: find user in that specific org
      const [[u]] = await db.query(
        `SELECT u.* FROM users u
         JOIN org_users ou ON ou.user_id=u.id
         JOIN organizations o ON o.id=ou.org_id
         WHERE u.username=? AND u.is_active=1 AND o.slug=?`,
        [username, org_slug]
      );
      user = u;
    }

    if (!user) {
      // Fallback: find super_admin or admin by username globally (they must be unique at admin level)
      const [[u]] = await db.query(
        `SELECT * FROM users WHERE username=? AND is_active=1 AND role IN ('super_admin','admin') LIMIT 1`,
        [username]
      );
      user = u;
    }

    if (!user) {
      // Last resort: find any active user with this username (single org system or legacy)
      const [[u]] = await db.query(
        `SELECT * FROM users WHERE username=? AND is_active=1 LIMIT 1`,
        [username]
      );
      user = u;
    }

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
    const orgId = await getOrgId(req.user.id);
    let where = req.query.active_only === '1' ? 'WHERE is_active=1' : 'WHERE 1=1';
    const params = [];
    if (orgId) { where += ' AND org_id=?'; params.push(orgId); }
    const [rows] = await db.query(`SELECT * FROM departments ${where} ORDER BY stage_order, name`, params);
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
    const orgId = await getOrgId(req.user.id);
    const [r] = await db.query(
      'INSERT INTO departments (name,description,color,stage_order,org_id) VALUES (?,?,?,?,?)',
      [name, description, color || '#3B82F6', stage_order || 999, orgId]
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
    const orgId = await getOrgId(req.user.id);
    const [result] = await db.query(
      'UPDATE departments SET name=?,description=?,color=?,stage_order=?,is_active=? WHERE id=? AND (org_id=? OR org_id IS NULL)',
      [name, description, color, stage_order, is_active, req.params.id, orgId]
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
    const orgId = await getOrgId(req.user.id);
    const [result] = await db.query('UPDATE departments SET is_active=0 WHERE id=? AND org_id=?', [req.params.id, orgId]);
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
    const orgId = await getOrgId(req.user.id);
    let where = 'WHERE is_active=1';
    const params = [];
    if (orgId) { where += ' AND org_id=?'; params.push(orgId); }
    const [rows] = await db.query(`SELECT * FROM product_categories ${where} ORDER BY name`, params);
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
    const orgId = await getOrgId(req.user.id);
    const [r] = await db.query('INSERT INTO product_categories (name,description,org_id) VALUES (?,?,?)', [name, description, orgId]);
    res.status(201).json({ id: r.insertId, name, description });
  } catch (err) {
    console.error('POST /product-categories error:', err.message);
    res.status(500).json({ message: 'Failed to create category', error: err.message });
  }
});
router.put('/product-categories/:id', auth, adminOnly, async (req, res) => {
  const { name, description, is_active } = req.body;
  const db = await getPool();
  const orgId = await getOrgId(req.user.id);
  await db.query('UPDATE product_categories SET name=?,description=?,is_active=? WHERE id=? AND org_id=?', [name, description, is_active, req.params.id, orgId]);
  res.json({ message: 'Updated' });
});

// ═══════════════════════════════════════════════════════════════════════════════
// PRODUCTION ORDERS
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/orders', auth, async (req, res) => {
  const db = await getPool();
  const orgId = await getOrgId(req.user.id);
  const { status, search } = req.query;
  let where = "WHERE o.status != 'deleted'";
  const params = [];
  if (orgId) { where += ' AND o.org_id=?'; params.push(orgId); }
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
    const orgId = await getOrgId(req.user.id);
    let finalOrderNo = order_no;
    if (!finalOrderNo || finalOrderNo.trim() === '') {
      const [[{ cnt }]] = await db.query('SELECT COUNT(*) as cnt FROM production_orders WHERE org_id=?', [orgId]);
      finalOrderNo = `MO-${String(cnt + 1).padStart(4, '0')}`;
    }
    const safeOrderDate = (order_date && order_date !== '') ? order_date : null;
    const safeDeadline = (deadline && deadline !== '') ? deadline : null;
    const [r] = await db.query(
      'INSERT INTO production_orders (order_no,name,category_id,client_name,client_phone,description,priority,order_date,deadline,total_amount,notes,created_by,org_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
      [finalOrderNo, name, (category_id && category_id !== '') ? category_id : null, client_name, client_phone, description, priority || 'medium', safeOrderDate, safeDeadline, total_amount || 0, notes, req.user.id, orgId]
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
      [name, (category_id && category_id !== '') ? category_id : null, client_name, client_phone, description, status, priority, safeOrderDate, safeDeadline, total_amount, notes, req.params.id]
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
    const orgId = await getOrgId(req.user.id);
    const { status, worker_id, department_id, order_id } = req.query;
    let where = 'WHERE 1=1';
    const params = [];
    if (orgId) { where += ' AND o.org_id=?'; params.push(orgId); }
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
    const orgId = await getOrgId(req.user.id);
    const worker_id = req.user.role === 'field_worker' ? req.user.id : (req.query.worker_id || null);
    const { date_from, date_to } = req.query;
    let where = 'WHERE 1=1';
    const params = [];
    if (orgId) { where += ' AND fs.org_id=?'; params.push(orgId); }
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
    const orgId = await getOrgId(req.user.id);
    const orgFilter = orgId ? 'AND fs.org_id=?' : '';
    const params = orgId ? [orgId] : [];
    const [rows] = await db.query(
      `SELECT u.id as worker_id, u.name as worker_name, lp.latitude, lp.longitude, lp.recorded_at, fs.id as session_id
       FROM users u
       JOIN field_sessions fs ON fs.worker_id=u.id AND fs.status='active'
       JOIN location_pings lp ON lp.session_id=fs.id AND lp.id=(
         SELECT id FROM location_pings WHERE session_id=fs.id ORDER BY recorded_at DESC LIMIT 1
       )
       WHERE u.role='field_worker' AND u.is_active=1 ${orgFilter}`, params
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
    const orgId = await getOrgId(req.user.id);
    let where = 'WHERE is_active=1';
    const params = [];
    if (orgId) { where += ' AND org_id=?'; params.push(orgId); }
    const [rows] = await db.query(`SELECT * FROM sample_products ${where} ORDER BY name`, params);
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
    const orgId = await getOrgId(req.user.id);
    const [r] = await db.query('INSERT INTO sample_products (name,category,description,org_id) VALUES (?,?,?,?)', [name, category, description, orgId]);
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
    const orgId = await getOrgId(req.user.id);
    const [result] = await db.query('UPDATE sample_products SET name=?,category=?,description=?,is_active=? WHERE id=? AND org_id=?', [name, category, description, is_active, req.params.id, orgId]);
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
    const orgId = await getOrgId(req.user.id);
    const orgFilter = orgId ? 'AND fs.org_id=?' : '';
    const alertParams = orgId ? [orgId, thresholdMin] : [thresholdMin];
    const [stale] = await db.query(
      `SELECT fs.id as session_id, u.id as worker_id, u.name as worker_name,
       MAX(lp.recorded_at) as last_ping,
       TIMESTAMPDIFF(MINUTE, MAX(lp.recorded_at), NOW()) as minutes_since_ping
       FROM field_sessions fs
       JOIN users u ON u.id=fs.worker_id
       LEFT JOIN location_pings lp ON lp.session_id=fs.id
       WHERE fs.status='active' ${orgFilter}
       GROUP BY fs.id
       HAVING minutes_since_ping >= ? OR last_ping IS NULL`,
      alertParams
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
    const orgId2 = await getOrgId(req.user.id);
    const fakeParams = orgId2 ? [orgId2] : [];
    const fakeOrgFilter = orgId2 ? 'AND dv.org_id=?' : '';
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
       ${fakeOrgFilter}
       ORDER BY dv.arrival_time DESC`, fakeParams
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
    const orgId = await getOrgId(req.user.id);
    const orgFilter = orgId ? 'AND org_id=?' : '';
    const orgWorkerFilter = orgId ? `AND u.id IN (SELECT user_id FROM org_users WHERE org_id=${orgId})` : '';
    const p = orgId ? [orgId] : [];
    const [[orders]] = await db.query(`SELECT COUNT(*) as total, SUM(status='active') as active, SUM(status='completed') as completed FROM production_orders WHERE status!='deleted' ${orgFilter}`, p);
    const [[tasks]] = await db.query(`SELECT COUNT(*) as total, SUM(t.status='in_progress') as in_progress, SUM(t.status='completed') as completed, SUM(t.status='pending') as pending FROM task_assignments t JOIN production_orders o ON o.id=t.order_id WHERE 1=1 ${orgFilter.replace('org_id', 'o.org_id')}`, p);
    const [[workers]] = await db.query(`SELECT COUNT(*) as production FROM users u WHERE role='worker' AND is_active=1 ${orgWorkerFilter}`);
    const [[field_workers]] = await db.query(`SELECT COUNT(*) as cnt FROM users u WHERE role='field_worker' AND is_active=1 ${orgWorkerFilter}`);
    const [[visits_today]] = await db.query(`SELECT COUNT(*) as cnt FROM doctor_visits WHERE DATE(arrival_time)=CURDATE() ${orgFilter}`, p);
    const [[active_sessions]] = await db.query(`SELECT COUNT(*) as cnt FROM field_sessions WHERE status='active' ${orgFilter}`, p);
    const [[doctors]] = await db.query(`SELECT COUNT(*) as cnt FROM doctors WHERE is_active=1 ${orgFilter}`, p);
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
    const orgId = await getOrgId(req.user.id);
    const { date_from, date_to, worker_id } = req.query;
    const from = date_from || new Date(Date.now() - 30*24*3600000).toISOString().split('T')[0];
    const to = date_to || new Date().toISOString().split('T')[0];
    let extraWhere = '';
    const baseParams = [from, to];
    if (orgId) { extraWhere += ' AND dv.org_id=?'; baseParams.push(orgId); }
    if (worker_id) { extraWhere += ' AND dv.worker_id=?'; baseParams.push(worker_id); }
    const [visits_by_worker] = await db.query(
      `SELECT u.name as worker_name, COUNT(*) as visits, SUM(dv.duration_minutes) as total_time,
       SUM(dv.outcome='order_placed') as orders, SUM(dv.outcome='interested') as interested
       FROM doctor_visits dv JOIN users u ON u.id=dv.worker_id
       WHERE DATE(dv.arrival_time) BETWEEN ? AND ?${extraWhere}
       GROUP BY dv.worker_id ORDER BY visits DESC`,
      baseParams
    );
    const [visits_by_area] = await db.query(
      `SELECT a.name as area_name, COUNT(*) as visits
       FROM doctor_visits dv JOIN doctors doc ON doc.id=dv.doctor_id
       LEFT JOIN areas a ON a.id=doc.area_id
       WHERE DATE(dv.arrival_time) BETWEEN ? AND ?${extraWhere}
       GROUP BY doc.area_id ORDER BY visits DESC`,
      baseParams
    );
    const [outcome_summary] = await db.query(
      `SELECT dv.outcome, COUNT(*) as cnt FROM doctor_visits dv
       WHERE DATE(dv.arrival_time) BETWEEN ? AND ?${extraWhere}
       GROUP BY dv.outcome`,
      baseParams
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
    const orgId = await getOrgId(req.user.id);
    const orgFilter = orgId ? 'AND o.org_id=?' : '';
    const p = orgId ? [orgId] : [];
    const [by_dept] = await db.query(
      `SELECT d.name as dept_name, d.color, COUNT(*) as tasks, SUM(t.status='completed') as done
       FROM task_assignments t
       JOIN departments d ON d.id=t.department_id
       JOIN production_orders o ON o.id=t.order_id
       WHERE 1=1 ${orgFilter}
       GROUP BY t.department_id ORDER BY done DESC`, p
    );
    const [by_status] = await db.query(
      `SELECT t.status, COUNT(*) as cnt FROM task_assignments t
       JOIN production_orders o ON o.id=t.order_id
       WHERE 1=1 ${orgFilter} GROUP BY t.status`, p
    );
    const [recent_orders] = await db.query(
      `SELECT o.order_no, o.name, o.status, o.priority, o.deadline,
       (SELECT COUNT(*) FROM task_assignments WHERE order_id=o.id) as tasks,
       (SELECT COUNT(*) FROM task_assignments WHERE order_id=o.id AND status='completed') as done
       FROM production_orders o WHERE o.status != 'deleted' ${orgFilter}
       ORDER BY o.created_at DESC LIMIT 10`, p
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
    const orgId = await getOrgId(req.user.id);
    let where = 'WHERE 1=1';
    const params = [];
    if (orgId) { where += ' AND (org_id=? OR org_id IS NULL)'; params.push(orgId); }
    const [rows] = await db.query(`SELECT setting_key, setting_value FROM app_settings ${where}`, params);
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
    const orgId = await getOrgId(req.user.id);
    for (const [k, v] of Object.entries(req.body)) {
      await db.query(
        'INSERT INTO app_settings (setting_key, setting_value, updated_by, org_id) VALUES (?,?,?,?) ON DUPLICATE KEY UPDATE setting_value=?, updated_by=?',
        [k, v, req.user.id, orgId, v, req.user.id]
      );
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
  { key: 'dashboard',      label: 'Dashboard',            icon: '📊', group: 'Production' },
  { key: 'orders',         label: 'Production Orders',    icon: '📦', group: 'Production' },
  { key: 'tasks',          label: 'Tasks',                icon: '✅', group: 'Production' },
  { key: 'departments',    label: 'Departments',          icon: '🏭', group: 'Production' },
  { key: 'workers',        label: 'Workers',              icon: '👷', group: 'Production' },
  { key: 'doctors',        label: 'Doctors',              icon: '👨‍⚕️', group: 'Field Operations' },
  { key: 'chemists',       label: 'Chemists & Stockists', icon: '🏪', group: 'Field Operations' },
  { key: 'areas',          label: 'Areas',                icon: '🗺️', group: 'Field Operations' },
  { key: 'visit-plans',    label: 'Visit Plans',          icon: '📋', group: 'Field Operations' },
  { key: 'field-tracking', label: 'Live Tracking',        icon: '📍', group: 'Field Operations' },
  { key: 'visits',         label: 'Visits Table',         icon: '🗒️', group: 'Field Operations' },
  { key: 'engagement',     label: 'Doctor Engagement',    icon: '📈', group: 'Field Operations' },
  { key: 'appointments',   label: 'Appointments',         icon: '📅', group: 'Field Operations' },
  { key: 'targets',        label: 'Sales Targets',        icon: '🎯', group: 'Performance' },
  { key: 'leaderboard',    label: 'Leaderboard',          icon: '🏆', group: 'Performance' },
  { key: 'inventory',      label: 'Sample Inventory',     icon: '💊', group: 'Performance' },
  { key: 'notifications',  label: 'Notifications/SMS',    icon: '📱', group: 'Tools' },
  { key: 'ai-summary',     label: 'AI Visit Summary',     icon: '🤖', group: 'Tools' },
  { key: 'reports',        label: 'Reports & Alerts',     icon: '📊', group: 'Tools' },
  { key: 'audit',          label: 'HIPAA & Audit',        icon: '🔐', group: 'Tools' },
  { key: 'settings',       label: 'Settings',             icon: '⚙️', group: 'Tools' },
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
      `SELECT o.id, o.name as org_name, o.logo_url, o.is_active, o.license_expiry
       FROM organizations o JOIN org_users ou ON ou.org_id=o.id
       WHERE ou.user_id=?`,
      [req.user.id]
    );
    if (!orgUser) {
      return res.json({ menus: ALL_MENUS.map(m => m.key), is_active: true, org_name: 'Medical Manager', logo_url: null });
    }
    const isActive = orgUser.is_active &&
      (!orgUser.license_expiry || new Date(orgUser.license_expiry) >= new Date());
    if (!isActive) {
      return res.json({ menus: [], is_active: false, message: 'License expired or inactive', org_name: orgUser.org_name, logo_url: orgUser.logo_url });
    }
    const [perms] = await db.query(
      'SELECT menu_key FROM org_permissions WHERE org_id=? AND is_enabled=1',
      [orgUser.id]
    );
    res.json({ menus: perms.map(p => p.menu_key), is_active: true, org_id: orgUser.id, org_name: orgUser.org_name, logo_url: orgUser.logo_url });
  } catch (err) {
    console.error('GET /my/permissions error:', err.message);
    res.status(500).json({ message: 'Failed', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// DEPARTMENT DEFAULT WORKER CHAIN
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/departments/:id/chain', auth, async (req, res) => {
  try {
    const db = await getPool();
    const [rows] = await db.query(
      `SELECT dc.*, u.name as worker_name, u.role as worker_role
       FROM department_chains dc
       JOIN users u ON u.id=dc.worker_id
       WHERE dc.department_id=? ORDER BY dc.seq_order`,
      [req.params.id]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch chain', error: err.message });
  }
});

router.put('/departments/:id/chain', auth, adminOnly, async (req, res) => {
  try {
    const { worker_ids } = req.body; // ordered array of worker_ids
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    await db.query('DELETE FROM department_chains WHERE department_id=?', [req.params.id]);
    for (let i = 0; i < worker_ids.length; i++) {
      await db.query(
        'INSERT INTO department_chains (department_id, worker_id, seq_order, org_id) VALUES (?,?,?,?)',
        [req.params.id, worker_ids[i], i + 1, orgId]
      );
    }
    res.json({ message: 'Department chain saved' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to save chain', error: err.message });
  }
});

// Auto-assign tasks when order chain is saved
router.post('/orders/:id/auto-assign', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const orderId = req.params.id;

    // Get order chain (department sequence)
    const [chain] = await db.query(
      'SELECT * FROM production_chains WHERE order_id=? ORDER BY stage_order',
      [orderId]
    );
    if (!chain.length) return res.status(400).json({ message: 'No chain defined for this order' });

    // Get order items
    const [items] = await db.query('SELECT * FROM production_items WHERE order_id=?', [orderId]);
    const [[order]] = await db.query('SELECT * FROM production_orders WHERE id=?', [orderId]);

    // Delete existing auto-assigned pending tasks for this order
    await db.query(
      "DELETE FROM task_assignments WHERE order_id=? AND status='pending' AND admin_notes='auto-assigned'",
      [orderId]
    );

    let tasksCreated = 0;
    for (const stage of chain) {
      // Get workers linked to this department via department_chains
      const [deptWorkers] = await db.query(
        'SELECT worker_id FROM department_chains WHERE department_id=? AND org_id=? ORDER BY seq_order',
        [stage.department_id, orgId]
      );

      const targetItems = stage.item_id
        ? items.filter(i => i.id === stage.item_id)
        : items;

      for (const item of targetItems) {
        if (deptWorkers.length > 0) {
          // Assign to each worker in the chain for this department
          for (const dw of deptWorkers) {
            await db.query(
              `INSERT INTO task_assignments
               (order_id, item_id, assign_type, worker_id, department_id, stage_order,
                task_title, task_description, quantity_assigned, priority, admin_notes, status)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
              [orderId, item.id, 'worker', dw.worker_id, stage.department_id, stage.stage_order,
               `${item.item_name} — ${order.name}`,
               `Auto-assigned from department chain`,
               item.quantity, order.priority || 'medium', 'auto-assigned', 'pending']
            );
            tasksCreated++;
          }
        } else {
          // No workers in chain — assign to department
          await db.query(
            `INSERT INTO task_assignments
             (order_id, item_id, assign_type, department_id, stage_order,
              task_title, task_description, quantity_assigned, priority, admin_notes, status)
             VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
            [orderId, item.id, 'department', stage.department_id, stage.stage_order,
             `${item.item_name} — ${order.name}`,
             `Auto-assigned from department chain`,
             item.quantity, order.priority || 'medium', 'auto-assigned', 'pending']
          );
          tasksCreated++;
        }
      }
    }
    res.json({ message: `${tasksCreated} tasks auto-assigned successfully`, tasks_created: tasksCreated });
  } catch (err) {
    console.error('POST /orders/:id/auto-assign error:', err.message);
    res.status(500).json({ message: 'Auto-assign failed', error: err.message });
  }
});


// ═══════════════════════════════════════════════════════════════════════════════
// ORG LOGO UPLOAD
// ═══════════════════════════════════════════════════════════════════════════════
router.post('/org/logo', auth, adminOnly, async (req, res) => {
  try {
    const { image_base64 } = req.body;
    if (!image_base64) return res.status(400).json({ message: 'image_base64 is required' });
    if (!CLOUDINARY_CLOUD_NAME || !CLOUDINARY_API_KEY || !CLOUDINARY_API_SECRET) {
      return res.status(500).json({ message: 'Cloudinary not configured' });
    }
    const orgId = await getOrgId(req.user.id);
    if (!orgId) return res.status(403).json({ message: 'Not linked to an organization' });
    const db = await getPool();
    const timestamp = Math.floor(Date.now() / 1000);
    const folder = 'org_logos';
    const publicId = `org_${orgId}_logo`;
    const uploadData = await cloudinaryUpload(
      CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET,
      image_base64, folder, publicId
    );
    await db.query('UPDATE organizations SET logo_url=? WHERE id=?', [uploadData.secure_url, orgId]);
    res.json({ url: uploadData.secure_url, message: 'Logo uploaded successfully' });
  } catch (err) {
    console.error('POST /org/logo error:', err.message);
    res.status(500).json({ message: 'Logo upload failed', error: err.message });
  }
});


// ═══════════════════════════════════════════════════════════════════════════════
// SAMPLE INVENTORY MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════════

// GET all workers' inventory summary (admin view)
router.get('/inventory', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    let where = 'WHERE 1=1';
    const params = [];
    if (orgId) { where += ' AND si.org_id=?'; params.push(orgId); }
    const [rows] = await db.query(
      `SELECT si.id, si.quantity, si.min_stock, si.updated_at,
       sp.id as product_id, sp.name as product_name, sp.category,
       u.id as worker_id, u.name as worker_name,
       CASE WHEN si.quantity <= si.min_stock THEN 1 ELSE 0 END as low_stock
       FROM sample_inventory si
       JOIN sample_products sp ON sp.id = si.product_id
       JOIN users u ON u.id = si.worker_id
       ${where}
       ORDER BY low_stock DESC, u.name, sp.name`,
      params
    );
    res.json(rows);
  } catch (err) {
    console.error('GET /inventory error:', err.message);
    res.status(500).json({ message: 'Failed to fetch inventory', error: err.message });
  }
});

// GET inventory for logged-in field worker
router.get('/inventory/my', auth, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const [rows] = await db.query(
      `SELECT si.id, si.quantity, si.min_stock, si.updated_at,
       sp.id as product_id, sp.name as product_name, sp.category, sp.description,
       CASE WHEN si.quantity <= si.min_stock THEN 1 ELSE 0 END as low_stock
       FROM sample_inventory si
       JOIN sample_products sp ON sp.id = si.product_id
       WHERE si.worker_id = ? AND sp.is_active = 1
       ORDER BY low_stock DESC, sp.name`,
      [req.user.id]
    );
    res.json(rows);
  } catch (err) {
    console.error('GET /inventory/my error:', err.message);
    res.status(500).json({ message: 'Failed to fetch inventory', error: err.message });
  }
});

// POST restock — admin adds stock to a worker
router.post('/inventory/restock', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const { worker_id, product_id, quantity, notes } = req.body;
    if (!worker_id || !product_id || !quantity || quantity <= 0)
      return res.status(400).json({ message: 'worker_id, product_id, quantity required' });

    // Upsert inventory row
    await db.query(
      `INSERT INTO sample_inventory (product_id, worker_id, org_id, quantity, min_stock)
       VALUES (?, ?, ?, ?, 5)
       ON DUPLICATE KEY UPDATE quantity = quantity + VALUES(quantity), updated_at = NOW()`,
      [product_id, worker_id, orgId, quantity]
    );
    // Log transaction
    await db.query(
      `INSERT INTO sample_transactions (product_id, worker_id, org_id, type, quantity, notes, created_by)
       VALUES (?, ?, ?, 'restock', ?, ?, ?)`,
      [product_id, worker_id, orgId, quantity, notes || null, req.user.id]
    );
    res.json({ message: 'Restock successful' });
  } catch (err) {
    console.error('POST /inventory/restock error:', err.message);
    res.status(500).json({ message: 'Restock failed', error: err.message });
  }
});

// POST adjustment — admin manually sets stock level
router.post('/inventory/adjust', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const { worker_id, product_id, quantity, min_stock, notes } = req.body;
    if (!worker_id || !product_id || quantity === undefined)
      return res.status(400).json({ message: 'worker_id, product_id, quantity required' });

    await db.query(
      `INSERT INTO sample_inventory (product_id, worker_id, org_id, quantity, min_stock)
       VALUES (?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE quantity = VALUES(quantity), min_stock = COALESCE(VALUES(min_stock), min_stock), updated_at = NOW()`,
      [product_id, worker_id, orgId, quantity, min_stock || 5]
    );
    await db.query(
      `INSERT INTO sample_transactions (product_id, worker_id, org_id, type, quantity, notes, created_by)
       VALUES (?, ?, ?, 'adjustment', ?, ?, ?)`,
      [product_id, worker_id, orgId, quantity, notes || null, req.user.id]
    );
    res.json({ message: 'Adjustment saved' });
  } catch (err) {
    console.error('POST /inventory/adjust error:', err.message);
    res.status(500).json({ message: 'Adjustment failed', error: err.message });
  }
});

// GET transaction history for a worker+product
router.get('/inventory/transactions', auth, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const { worker_id, product_id } = req.query;
    const wid = req.user.role === 'field_worker' ? req.user.id : (worker_id || null);
    let where = 'WHERE 1=1';
    const params = [];
    if (wid) { where += ' AND st.worker_id=?'; params.push(wid); }
    if (product_id) { where += ' AND st.product_id=?'; params.push(product_id); }
    if (orgId) { where += ' AND st.org_id=?'; params.push(orgId); }
    const [rows] = await db.query(
      `SELECT st.*, sp.name as product_name, u.name as worker_name,
       cb.name as created_by_name
       FROM sample_transactions st
       JOIN sample_products sp ON sp.id = st.product_id
       JOIN users u ON u.id = st.worker_id
       LEFT JOIN users cb ON cb.id = st.created_by
       ${where}
       ORDER BY st.created_at DESC LIMIT 100`,
      params
    );
    res.json(rows);
  } catch (err) {
    console.error('GET /inventory/transactions error:', err.message);
    res.status(500).json({ message: 'Failed to fetch transactions', error: err.message });
  }
});

// Auto-deduct from inventory when a visit records samples given
// Called internally — also exposed as PUT for manual deduction
router.post('/inventory/deduct', auth, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const { product_id, quantity, visit_id, notes } = req.body;
    if (!product_id || !quantity || quantity <= 0)
      return res.status(400).json({ message: 'product_id and quantity required' });

    const [[inv]] = await db.query(
      'SELECT quantity FROM sample_inventory WHERE worker_id=? AND product_id=?',
      [req.user.id, product_id]
    );
    if (!inv) return res.status(404).json({ message: 'No inventory found for this product' });
    if (inv.quantity < quantity) return res.status(400).json({ message: 'Insufficient stock' });

    await db.query(
      'UPDATE sample_inventory SET quantity = quantity - ?, updated_at=NOW() WHERE worker_id=? AND product_id=?',
      [quantity, req.user.id, product_id]
    );
    await db.query(
      `INSERT INTO sample_transactions (product_id, worker_id, org_id, type, quantity, reference_visit_id, notes, created_by)
       VALUES (?, ?, ?, 'given', ?, ?, ?, ?)`,
      [product_id, req.user.id, orgId, quantity, visit_id || null, notes || null, req.user.id]
    );
    res.json({ message: 'Deducted successfully' });
  } catch (err) {
    console.error('POST /inventory/deduct error:', err.message);
    res.status(500).json({ message: 'Deduction failed', error: err.message });
  }
});

// GET low stock alerts for admin
router.get('/inventory/low-stock', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    let where = 'WHERE si.quantity <= si.min_stock';
    const params = [];
    if (orgId) { where += ' AND si.org_id=?'; params.push(orgId); }
    const [rows] = await db.query(
      `SELECT sp.name as product_name, sp.category,
       u.name as worker_name, u.id as worker_id,
       si.quantity, si.min_stock
       FROM sample_inventory si
       JOIN sample_products sp ON sp.id = si.product_id
       JOIN users u ON u.id = si.worker_id
       ${where}
       ORDER BY si.quantity ASC`,
      params
    );
    res.json(rows);
  } catch (err) {
    console.error('GET /inventory/low-stock error:', err.message);
    res.status(500).json({ message: 'Failed to fetch low stock', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// PDF / EXCEL REPORT EXPORT
// ═══════════════════════════════════════════════════════════════════════════════

// GET /export/report/field — field visits detailed CSV (existing) already exists at /export/visits
// New: /export/report/summary — full PDF-ready JSON with charts data

router.get('/export/report/field-summary', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const { date_from, date_to, worker_id, format } = req.query;
    const from = date_from || new Date(Date.now() - 30*24*3600000).toISOString().split('T')[0];
    const to   = date_to   || new Date().toISOString().split('T')[0];

    let extraWhere = '';
    const p = [from, to];
    if (orgId)    { extraWhere += ' AND dv.org_id=?';    p.push(orgId); }
    if (worker_id){ extraWhere += ' AND dv.worker_id=?'; p.push(worker_id); }

    const [visits_by_worker] = await db.query(
      `SELECT u.name as worker_name,
       COUNT(*) as total_visits,
       SUM(dv.outcome='order_placed') as orders,
       SUM(dv.outcome='interested') as interested,
       SUM(dv.outcome='sample_given') as samples_given,
       SUM(dv.outcome='follow_up') as follow_ups,
       SUM(dv.outcome='not_available') as not_available,
       SUM(dv.outcome='not_interested') as not_interested,
       SUM(dv.order_amount) as total_order_value,
       ROUND(AVG(dv.duration_minutes),1) as avg_duration_min,
       SUM(dv.geo_verified) as geo_verified_count
       FROM doctor_visits dv JOIN users u ON u.id=dv.worker_id
       WHERE DATE(dv.arrival_time) BETWEEN ? AND ?${extraWhere}
       GROUP BY dv.worker_id ORDER BY total_visits DESC`,
      p
    );

    const [visits_by_area] = await db.query(
      `SELECT COALESCE(a.name,'Unknown') as area_name, COUNT(*) as visits,
       SUM(dv.outcome='order_placed') as orders
       FROM doctor_visits dv
       JOIN doctors doc ON doc.id=dv.doctor_id
       LEFT JOIN areas a ON a.id=doc.area_id
       WHERE DATE(dv.arrival_time) BETWEEN ? AND ?${extraWhere}
       GROUP BY doc.area_id ORDER BY visits DESC`,
      p
    );

    const [daily_trend] = await db.query(
      `SELECT DATE(dv.arrival_time) as date, COUNT(*) as visits,
       SUM(dv.outcome='order_placed') as orders
       FROM doctor_visits dv
       WHERE DATE(dv.arrival_time) BETWEEN ? AND ?${extraWhere}
       GROUP BY DATE(dv.arrival_time) ORDER BY date ASC`,
      p
    );

    const [outcome_summary] = await db.query(
      `SELECT dv.outcome, COUNT(*) as cnt
       FROM doctor_visits dv
       WHERE DATE(dv.arrival_time) BETWEEN ? AND ?${extraWhere}
       GROUP BY dv.outcome`,
      p
    );

    const [top_doctors] = await db.query(
      `SELECT doc.name as doctor_name, doc.clinic_name,
       COALESCE(a.name,'Unknown') as area_name,
       COUNT(*) as visits, SUM(dv.outcome='order_placed') as orders,
       SUM(dv.order_amount) as total_order_value
       FROM doctor_visits dv
       JOIN doctors doc ON doc.id=dv.doctor_id
       LEFT JOIN areas a ON a.id=doc.area_id
       WHERE DATE(dv.arrival_time) BETWEEN ? AND ?${extraWhere}
       GROUP BY dv.doctor_id ORDER BY visits DESC LIMIT 10`,
      p
    );

    const [[totals]] = await db.query(
      `SELECT COUNT(*) as total_visits,
       COUNT(DISTINCT dv.worker_id) as active_workers,
       COUNT(DISTINCT dv.doctor_id) as doctors_visited,
       SUM(dv.outcome='order_placed') as total_orders,
       SUM(dv.order_amount) as total_order_value,
       ROUND(AVG(dv.duration_minutes),1) as avg_visit_duration
       FROM doctor_visits dv
       WHERE DATE(dv.arrival_time) BETWEEN ? AND ?${extraWhere}`,
      p
    );

    // Low stock alerts for the report
    const [low_stock] = await db.query(
      `SELECT sp.name as product_name, u.name as worker_name, si.quantity, si.min_stock
       FROM sample_inventory si
       JOIN sample_products sp ON sp.id=si.product_id
       JOIN users u ON u.id=si.worker_id
       WHERE si.quantity <= si.min_stock ${orgId ? 'AND si.org_id=?' : ''}
       ORDER BY si.quantity ASC`,
      orgId ? [orgId] : []
    );

    const reportData = {
      generated_at: new Date().toISOString(),
      period: { from, to },
      totals,
      visits_by_worker,
      visits_by_area,
      daily_trend,
      outcome_summary,
      top_doctors,
      low_stock_alerts: low_stock,
    };

    if (format === 'csv') {
      // Multi-section CSV
      const lines = [];
      const esc = v => { const s = String(v ?? ''); return s.includes(',') || s.includes('"') ? `"${s.replace(/"/g,'""')}"` : s; };
      const row = arr => arr.map(esc).join(',');

      lines.push('FIELD REPORT SUMMARY');
      lines.push(`Period,${from},to,${to}`);
      lines.push(`Generated,${new Date().toLocaleString('en-IN')}`);
      lines.push('');

      lines.push('TOTALS');
      lines.push(row(['Total Visits','Active Workers','Doctors Visited','Total Orders','Order Value (₹)','Avg Visit (min)']));
      lines.push(row([totals.total_visits, totals.active_workers, totals.doctors_visited, totals.total_orders, totals.total_order_value || 0, totals.avg_visit_duration || 0]));
      lines.push('');

      lines.push('WORKER-WISE PERFORMANCE');
      lines.push(row(['Worker','Total Visits','Orders','Interested','Samples Given','Follow Ups','Not Available','Order Value (₹)','Avg Duration (min)','Geo Verified']));
      visits_by_worker.forEach(r => lines.push(row([r.worker_name, r.total_visits, r.orders, r.interested, r.samples_given, r.follow_ups, r.not_available, r.total_order_value||0, r.avg_duration_min||0, r.geo_verified_count])));
      lines.push('');

      lines.push('AREA-WISE VISITS');
      lines.push(row(['Area','Total Visits','Orders']));
      visits_by_area.forEach(r => lines.push(row([r.area_name, r.visits, r.orders])));
      lines.push('');

      lines.push('DAILY TREND');
      lines.push(row(['Date','Visits','Orders']));
      daily_trend.forEach(r => lines.push(row([r.date, r.visits, r.orders])));
      lines.push('');

      lines.push('TOP DOCTORS');
      lines.push(row(['Doctor','Clinic','Area','Visits','Orders','Order Value (₹)']));
      top_doctors.forEach(r => lines.push(row([r.doctor_name, r.clinic_name||'', r.area_name, r.visits, r.orders, r.total_order_value||0])));
      lines.push('');

      if (low_stock.length > 0) {
        lines.push('LOW STOCK ALERTS');
        lines.push(row(['Product','Worker','Current Stock','Min Stock']));
        low_stock.forEach(r => lines.push(row([r.product_name, r.worker_name, r.quantity, r.min_stock])));
      }

      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="field_report_${from}_to_${to}.csv"`);
      return res.send('\uFEFF' + lines.join('\n')); // BOM for Excel
    }

    res.json(reportData);
  } catch (err) {
    console.error('GET /export/report/field-summary error:', err.message);
    res.status(500).json({ message: 'Report export failed', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// ROUTE OPTIMIZATION
// ═══════════════════════════════════════════════════════════════════════════════

// GET /route/optimize — returns ordered list of doctors to visit for a day
// Uses a greedy nearest-neighbor TSP for fast response (no external API needed)
router.get('/route/optimize', auth, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const { worker_id, date, start_lat, start_lng } = req.query;
    const wid = req.user.role === 'field_worker' ? req.user.id : (worker_id || req.user.id);
    const targetDate = date || new Date().toISOString().split('T')[0];

    // Fetch planned visits for this worker on this date
    const [plans] = await db.query(
      `SELECT vp.id as plan_id, vp.purpose, vp.sample_products,
       doc.id as doctor_id, doc.name as doctor_name, doc.clinic_name,
       doc.phone, doc.address, doc.latitude, doc.longitude,
       a.name as area_name
       FROM visit_plans vp
       JOIN doctors doc ON doc.id = vp.doctor_id
       LEFT JOIN areas a ON a.id = doc.area_id
       WHERE vp.worker_id = ? AND vp.planned_date = ? AND vp.status = 'planned'
       AND doc.latitude IS NOT NULL AND doc.longitude IS NOT NULL
       ${orgId ? 'AND vp.org_id=?' : ''}
       ORDER BY doc.name`,
      orgId ? [wid, targetDate, orgId] : [wid, targetDate]
    );

    if (plans.length === 0) {
      return res.json({ optimized_route: [], total_distance_km: 0, message: 'No planned visits with GPS coordinates found for this date' });
    }

    // Greedy nearest-neighbor algorithm
    const toRad = d => d * Math.PI / 180;
    const haversine = (lat1, lng1, lat2, lng2) => {
      const R = 6371;
      const dLat = toRad(lat2 - lat1);
      const dLng = toRad(lng2 - lng1);
      const a = Math.sin(dLat/2)**2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng/2)**2;
      return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
    };

    let curLat = parseFloat(start_lat) || (plans[0].latitude ? parseFloat(plans[0].latitude) : 0);
    let curLng = parseFloat(start_lng) || (plans[0].longitude ? parseFloat(plans[0].longitude) : 0);

    const unvisited = [...plans];
    const route = [];
    let totalDist = 0;

    while (unvisited.length > 0) {
      let nearest = null, nearestIdx = -1, minDist = Infinity;
      unvisited.forEach((doc, idx) => {
        const d = haversine(curLat, curLng, parseFloat(doc.latitude), parseFloat(doc.longitude));
        if (d < minDist) { minDist = d; nearest = doc; nearestIdx = idx; }
      });
      totalDist += minDist;
      route.push({ ...nearest, distance_from_prev_km: Math.round(minDist * 10) / 10, order: route.length + 1 });
      curLat = parseFloat(nearest.latitude);
      curLng = parseFloat(nearest.longitude);
      unvisited.splice(nearestIdx, 1);
    }

    // Already visited doctors today (to mark as done)
    const [done] = await db.query(
      `SELECT DISTINCT doctor_id FROM doctor_visits
       WHERE worker_id=? AND DATE(arrival_time)=?`,
      [wid, targetDate]
    );
    const doneIds = new Set(done.map(d => d.doctor_id));
    route.forEach(r => { r.already_visited = doneIds.has(r.doctor_id); });

    res.json({
      optimized_route: route,
      total_distance_km: Math.round(totalDist * 10) / 10,
      total_stops: route.length,
      completed: doneIds.size,
      remaining: route.filter(r => !r.already_visited).length,
    });
  } catch (err) {
    console.error('GET /route/optimize error:', err.message);
    res.status(500).json({ message: 'Route optimization failed', error: err.message });
  }
});

// GET /route/doctors-near — nearest doctors to current GPS for quick add
router.get('/route/doctors-near', auth, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const { lat, lng, radius_km = 5 } = req.query;
    if (!lat || !lng) return res.status(400).json({ message: 'lat and lng required' });

    let where = 'WHERE doc.is_active=1 AND doc.latitude IS NOT NULL AND doc.longitude IS NOT NULL';
    const params = [];
    if (orgId) { where += ' AND doc.org_id=?'; params.push(orgId); }

    const [doctors] = await db.query(
      `SELECT doc.id, doc.name, doc.clinic_name, doc.phone, doc.address,
       doc.latitude, doc.longitude, a.name as area_name,
       (6371 * 2 * ASIN(SQRT(
         POWER(SIN((RADIANS(?) - RADIANS(doc.latitude))/2), 2) +
         COS(RADIANS(?)) * COS(RADIANS(doc.latitude)) *
         POWER(SIN((RADIANS(?) - RADIANS(doc.longitude))/2), 2)
       ))) AS distance_km
       FROM doctors doc
       LEFT JOIN areas a ON a.id=doc.area_id
       ${where}
       HAVING distance_km <= ?
       ORDER BY distance_km ASC
       LIMIT 20`,
      [lat, lat, lng, ...params, radius_km]
    );
    res.json(doctors.map(d => ({ ...d, distance_km: Math.round(d.distance_km * 100) / 100 })));
  } catch (err) {
    console.error('GET /route/doctors-near error:', err.message);
    res.status(500).json({ message: 'Nearby doctors fetch failed', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// FEATURE: SALES TARGETS & ACHIEVEMENT
// ═══════════════════════════════════════════════════════════════════════════════

router.get('/targets', auth, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const { month, year, worker_id } = req.query;
    const m = month || (new Date().getMonth() + 1);
    const y = year  || new Date().getFullYear();
    let where = 'WHERE t.month=? AND t.year=?';
    const params = [m, y];
    if (orgId) { where += ' AND t.org_id=?'; params.push(orgId); }
    if (worker_id) { where += ' AND t.worker_id=?'; params.push(worker_id); }
    const [targets] = await db.query(
      `SELECT t.*, u.name as worker_name,
       (SELECT COUNT(*) FROM doctor_visits dv
        WHERE dv.worker_id=t.worker_id AND MONTH(dv.arrival_time)=t.month AND YEAR(dv.arrival_time)=t.year) as actual_visits,
       (SELECT COUNT(*) FROM doctor_visits dv
        WHERE dv.worker_id=t.worker_id AND dv.outcome='order_placed' AND MONTH(dv.arrival_time)=t.month AND YEAR(dv.arrival_time)=t.year) as actual_orders,
       (SELECT COALESCE(SUM(dv.order_amount),0) FROM doctor_visits dv
        WHERE dv.worker_id=t.worker_id AND MONTH(dv.arrival_time)=t.month AND YEAR(dv.arrival_time)=t.year) as actual_revenue,
       (SELECT COUNT(DISTINCT dv.doctor_id) FROM doctor_visits dv
        WHERE dv.worker_id=t.worker_id AND MONTH(dv.arrival_time)=t.month AND YEAR(dv.arrival_time)=t.year) as actual_new_doctors
       FROM sales_targets t JOIN users u ON u.id=t.worker_id
       ${where} ORDER BY u.name`,
      params
    );
    res.json(targets);
  } catch (err) {
    console.error('GET /targets error:', err.message);
    res.status(500).json({ message: 'Failed to fetch targets', error: err.message });
  }
});

router.post('/targets', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const { worker_id, month, year, target_visits, target_orders, target_revenue, target_new_doctors } = req.body;
    if (!worker_id || !month || !year) return res.status(400).json({ message: 'worker_id, month, year required' });
    await db.query(
      `INSERT INTO sales_targets (worker_id, org_id, month, year, target_visits, target_orders, target_revenue, target_new_doctors)
       VALUES (?,?,?,?,?,?,?,?)
       ON DUPLICATE KEY UPDATE target_visits=VALUES(target_visits), target_orders=VALUES(target_orders),
       target_revenue=VALUES(target_revenue), target_new_doctors=VALUES(target_new_doctors)`,
      [worker_id, orgId, month, year, target_visits||0, target_orders||0, target_revenue||0, target_new_doctors||0]
    );
    res.json({ message: 'Target saved' });
  } catch (err) {
    console.error('POST /targets error:', err.message);
    res.status(500).json({ message: 'Failed to save target', error: err.message });
  }
});

router.delete('/targets/:id', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    await db.query('DELETE FROM sales_targets WHERE id=?', [req.params.id]);
    res.json({ message: 'Target deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Delete failed', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// FEATURE: LEADERBOARD & GAMIFICATION
// ═══════════════════════════════════════════════════════════════════════════════

router.get('/leaderboard', auth, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const { month, year } = req.query;
    const m = month || (new Date().getMonth() + 1);
    const y = year  || new Date().getFullYear();
    const startDate = `${y}-${String(m).padStart(2,'0')}-01`;
    const endDate   = new Date(y, m, 0).toISOString().split('T')[0];
    let orgFilter = orgId ? 'AND dv.org_id=?' : '';
    const p = orgId ? [startDate, endDate, orgId] : [startDate, endDate];
    const [rows] = await db.query(
      `SELECT u.id as worker_id, u.name as worker_name,
       COUNT(dv.id) as visits,
       SUM(dv.outcome='order_placed') as orders,
       COALESCE(SUM(dv.order_amount),0) as revenue,
       COUNT(DISTINCT dv.doctor_id) as unique_doctors,
       ROUND(AVG(dv.duration_minutes),1) as avg_duration,
       SUM(dv.geo_verified) as verified_visits
       FROM doctor_visits dv JOIN users u ON u.id=dv.worker_id
       WHERE DATE(dv.arrival_time) BETWEEN ? AND ? ${orgFilter}
       GROUP BY dv.worker_id ORDER BY visits DESC, orders DESC`,
      p
    );
    // Assign ranks and badges
    const result = rows.map((r, i) => {
      const badges = [];
      if (i === 0) badges.push({ label: 'Top Performer', emoji: '🥇' });
      if (i === 1) badges.push({ label: 'Runner Up', emoji: '🥈' });
      if (i === 2) badges.push({ label: 'Third Place', emoji: '🥉' });
      if (r.visits >= 50)  badges.push({ label: '50 Visits', emoji: '🎯' });
      if (r.visits >= 100) badges.push({ label: '100 Visits', emoji: '💯' });
      if (r.orders >= 10)  badges.push({ label: '10 Orders', emoji: '🛒' });
      if (r.orders >= 25)  badges.push({ label: '25 Orders', emoji: '⭐' });
      if (r.verified_visits >= 20) badges.push({ label: 'GPS Champion', emoji: '📍' });
      return { ...r, rank: i + 1, badges };
    });
    res.json({ month: m, year: y, leaderboard: result });
  } catch (err) {
    console.error('GET /leaderboard error:', err.message);
    res.status(500).json({ message: 'Failed to fetch leaderboard', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// FEATURE: CALL LOG TRACKING (virtual visits)
// ═══════════════════════════════════════════════════════════════════════════════

router.get('/call-logs', auth, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const { date_from, date_to, worker_id } = req.query;
    const wid = req.user.role === 'field_worker' ? req.user.id : (worker_id || null);
    let where = 'WHERE 1=1';
    const params = [];
    if (date_from) { where += ' AND DATE(cl.call_date)>=?'; params.push(date_from); }
    if (date_to)   { where += ' AND DATE(cl.call_date)<=?'; params.push(date_to); }
    if (wid)       { where += ' AND cl.worker_id=?'; params.push(wid); }
    if (orgId)     { where += ' AND cl.org_id=?'; params.push(orgId); }
    const [rows] = await db.query(
      `SELECT cl.*, u.name as worker_name, doc.name as doctor_name, doc.clinic_name, doc.phone as doctor_phone, a.name as area_name
       FROM call_logs cl
       JOIN users u ON u.id=cl.worker_id
       JOIN doctors doc ON doc.id=cl.doctor_id
       LEFT JOIN areas a ON a.id=doc.area_id
       ${where} ORDER BY cl.call_date DESC LIMIT 200`,
      params
    );
    res.json(rows);
  } catch (err) {
    console.error('GET /call-logs error:', err.message);
    res.status(500).json({ message: 'Failed to fetch call logs', error: err.message });
  }
});

router.post('/call-logs', auth, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const { doctor_id, call_date, duration_minutes, outcome, notes, follow_up_date } = req.body;
    if (!doctor_id) return res.status(400).json({ message: 'doctor_id required' });
    const [r] = await db.query(
      `INSERT INTO call_logs (worker_id, doctor_id, org_id, call_date, duration_minutes, outcome, notes, follow_up_date)
       VALUES (?,?,?,?,?,?,?,?)`,
      [req.user.id, doctor_id, orgId, call_date || new Date(), duration_minutes||0, outcome||'discussed', notes||null, follow_up_date||null]
    );
    res.json({ id: r.insertId, message: 'Call log saved' });
  } catch (err) {
    console.error('POST /call-logs error:', err.message);
    res.status(500).json({ message: 'Failed to save call log', error: err.message });
  }
});

router.delete('/call-logs/:id', auth, async (req, res) => {
  try {
    const db = await getPool();
    await db.query('DELETE FROM call_logs WHERE id=? AND worker_id=?', [req.params.id, req.user.id]);
    res.json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Delete failed', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// FEATURE: DOCTOR ENGAGEMENT SCORE
// ═══════════════════════════════════════════════════════════════════════════════

router.get('/doctors/:id/engagement', auth, async (req, res) => {
  try {
    const db = await getPool();
    const [[doc]] = await db.query('SELECT * FROM doctors WHERE id=?', [req.params.id]);
    if (!doc) return res.status(404).json({ message: 'Doctor not found' });
    const [[stats]] = await db.query(
      `SELECT
       COUNT(*) as total_visits,
       SUM(outcome='order_placed') as orders,
       SUM(outcome='interested') as interested,
       SUM(outcome='not_interested') as not_interested,
       SUM(outcome='not_available') as not_available,
       MAX(arrival_time) as last_visit,
       MIN(arrival_time) as first_visit,
       COALESCE(SUM(order_amount),0) as total_revenue,
       ROUND(AVG(duration_minutes),1) as avg_duration
       FROM doctor_visits WHERE doctor_id=?`,
      [req.params.id]
    );
    const [[last30]] = await db.query(
      `SELECT COUNT(*) as visits_last_30 FROM doctor_visits
       WHERE doctor_id=? AND arrival_time >= DATE_SUB(NOW(), INTERVAL 30 DAY)`,
      [req.params.id]
    );
    // Score calculation (0-100)
    const daysSinceVisit = stats.last_visit
      ? Math.floor((Date.now() - new Date(stats.last_visit)) / 86400000) : 999;
    const recencyScore   = Math.max(0, 30 - Math.min(30, daysSinceVisit/2));
    const frequencyScore = Math.min(25, last30.visits_last_30 * 5);
    const orderScore     = Math.min(30, stats.orders * 6);
    const engagementRate = stats.total_visits > 0 ? stats.interested / stats.total_visits : 0;
    const engagementScore = Math.round(engagementRate * 15);
    const totalScore = Math.round(recencyScore + frequencyScore + orderScore + engagementScore);
    const level = totalScore >= 70 ? 'Hot' : totalScore >= 40 ? 'Warm' : totalScore >= 20 ? 'Cool' : 'Cold';
    const levelColor = { Hot:'#22c55e', Warm:'#f59e0b', Cool:'#3b82f6', Cold:'#6b7280' }[level];
    res.json({
      doctor_id: doc.id, doctor_name: doc.name, clinic_name: doc.clinic_name,
      score: totalScore, level, level_color: levelColor,
      breakdown: { recency: Math.round(recencyScore), frequency: Math.round(frequencyScore), orders: Math.round(orderScore), engagement: engagementScore },
      stats: { ...stats, visits_last_30: last30.visits_last_30, days_since_visit: daysSinceVisit }
    });
  } catch (err) {
    console.error('GET /doctors/:id/engagement error:', err.message);
    res.status(500).json({ message: 'Failed to get engagement score', error: err.message });
  }
});

router.get('/doctors/engagement/all', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    let where = 'WHERE d.is_active=1';
    const params = [];
    if (orgId) { where += ' AND d.org_id=?'; params.push(orgId); }
    const [doctors] = await db.query(
      `SELECT d.id, d.name, d.clinic_name, a.name as area_name,
       COUNT(dv.id) as total_visits,
       SUM(dv.outcome='order_placed') as orders,
       MAX(dv.arrival_time) as last_visit,
       (SELECT COUNT(*) FROM doctor_visits dv2 WHERE dv2.doctor_id=d.id AND dv2.arrival_time >= DATE_SUB(NOW(), INTERVAL 30 DAY)) as visits_last_30
       FROM doctors d
       LEFT JOIN areas a ON a.id=d.area_id
       LEFT JOIN doctor_visits dv ON dv.doctor_id=d.id
       ${where} GROUP BY d.id ORDER BY total_visits DESC`,
      params
    );
    const result = doctors.map(doc => {
      const daysSince = doc.last_visit ? Math.floor((Date.now() - new Date(doc.last_visit)) / 86400000) : 999;
      const recency   = Math.max(0, 30 - Math.min(30, daysSince/2));
      const frequency = Math.min(25, doc.visits_last_30 * 5);
      const orders    = Math.min(30, doc.orders * 6);
      const score     = Math.round(recency + frequency + orders);
      const level     = score >= 70 ? 'Hot' : score >= 40 ? 'Warm' : score >= 20 ? 'Cool' : 'Cold';
      return { ...doc, score, level, days_since_visit: daysSince };
    });
    result.sort((a, b) => b.score - a.score);
    res.json(result);
  } catch (err) {
    console.error('GET /doctors/engagement/all error:', err.message);
    res.status(500).json({ message: 'Failed', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// FEATURE: SMART FOLLOW-UP REMINDERS
// ═══════════════════════════════════════════════════════════════════════════════

router.get('/reminders', auth, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const wid = req.user.role === 'field_worker' ? req.user.id : (req.query.worker_id || null);
    let where = "WHERE r.status='pending'";
    const params = [];
    if (wid)   { where += ' AND r.worker_id=?'; params.push(wid); }
    if (orgId) { where += ' AND r.org_id=?'; params.push(orgId); }
    const [rows] = await db.query(
      `SELECT r.*, u.name as worker_name, doc.name as doctor_name, doc.clinic_name, doc.phone as doctor_phone
       FROM follow_up_reminders r
       JOIN users u ON u.id=r.worker_id
       JOIN doctors doc ON doc.id=r.doctor_id
       ${where} ORDER BY r.remind_date ASC`,
      params
    );
    // Mark overdue
    const today = new Date().toISOString().split('T')[0];
    res.json(rows.map(r => ({ ...r, overdue: r.remind_date < today })));
  } catch (err) {
    console.error('GET /reminders error:', err.message);
    res.status(500).json({ message: 'Failed to fetch reminders', error: err.message });
  }
});

router.post('/reminders', auth, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const { doctor_id, remind_date, notes, visit_id } = req.body;
    if (!doctor_id || !remind_date) return res.status(400).json({ message: 'doctor_id and remind_date required' });
    const [r] = await db.query(
      `INSERT INTO follow_up_reminders (worker_id, doctor_id, org_id, remind_date, notes, source_visit_id)
       VALUES (?,?,?,?,?,?)`,
      [req.user.id, doctor_id, orgId, remind_date, notes||null, visit_id||null]
    );
    res.json({ id: r.insertId, message: 'Reminder set' });
  } catch (err) {
    console.error('POST /reminders error:', err.message);
    res.status(500).json({ message: 'Failed to set reminder', error: err.message });
  }
});

router.patch('/reminders/:id/done', auth, async (req, res) => {
  try {
    const db = await getPool();
    await db.query("UPDATE follow_up_reminders SET status='done' WHERE id=? AND worker_id=?", [req.params.id, req.user.id]);
    res.json({ message: 'Marked done' });
  } catch (err) {
    res.status(500).json({ message: 'Failed', error: err.message });
  }
});

router.delete('/reminders/:id', auth, async (req, res) => {
  try {
    const db = await getPool();
    await db.query('DELETE FROM follow_up_reminders WHERE id=? AND worker_id=?', [req.params.id, req.user.id]);
    res.json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Delete failed', error: err.message });
  }
});

// Auto-create reminder when visit outcome is 'follow_up'
// Called internally after POST /field/visits — also exposed as GET for pending count
router.get('/reminders/count', auth, async (req, res) => {
  try {
    const db = await getPool();
    const wid = req.user.role === 'field_worker' ? req.user.id : (req.query.worker_id || null);
    const today = new Date().toISOString().split('T')[0];
    let where = "WHERE status='pending' AND remind_date<=?";
    const params = [today];
    if (wid) { where += ' AND worker_id=?'; params.push(wid); }
    const [[{ cnt }]] = await db.query(`SELECT COUNT(*) as cnt FROM follow_up_reminders ${where}`, params);
    res.json({ due_today: cnt });
  } catch (err) {
    res.status(500).json({ message: 'Failed', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// FEATURE: CHEMIST / STOCKIST MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════════

router.get('/chemists', auth, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const { search, area_id, type } = req.query;
    let where = 'WHERE c.is_active=1';
    const params = [];
    if (orgId)   { where += ' AND c.org_id=?'; params.push(orgId); }
    if (area_id) { where += ' AND c.area_id=?'; params.push(area_id); }
    if (type)    { where += ' AND c.type=?'; params.push(type); }
    if (search)  { where += ' AND (c.name LIKE ? OR c.owner_name LIKE ? OR c.phone LIKE ?)'; params.push(`%${search}%`,`%${search}%`,`%${search}%`); }
    const [rows] = await db.query(
      `SELECT c.*, a.name as area_name,
       (SELECT COUNT(*) FROM chemist_orders co WHERE co.chemist_id=c.id) as total_orders,
       (SELECT COALESCE(SUM(co.amount),0) FROM chemist_orders co WHERE co.chemist_id=c.id) as total_revenue,
       (SELECT MAX(co.order_date) FROM chemist_orders co WHERE co.chemist_id=c.id) as last_order_date
       FROM chemists c LEFT JOIN areas a ON a.id=c.area_id
       ${where} ORDER BY c.name`,
      params
    );
    res.json(rows);
  } catch (err) {
    console.error('GET /chemists error:', err.message);
    res.status(500).json({ message: 'Failed to fetch chemists', error: err.message });
  }
});

router.post('/chemists', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const { name, owner_name, type, phone, email, address, area_id, latitude, longitude, credit_limit, payment_terms } = req.body;
    if (!name) return res.status(400).json({ message: 'Name required' });
    const [r] = await db.query(
      `INSERT INTO chemists (name, owner_name, type, phone, email, address, area_id, latitude, longitude, credit_limit, payment_terms, org_id)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
      [name, owner_name||null, type||'chemist', phone||null, email||null, address||null,
       area_id||null, latitude||null, longitude||null, credit_limit||0, payment_terms||'immediate', orgId]
    );
    res.json({ id: r.insertId, message: 'Chemist added' });
  } catch (err) {
    console.error('POST /chemists error:', err.message);
    res.status(500).json({ message: 'Failed to add chemist', error: err.message });
  }
});

router.put('/chemists/:id', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const { name, owner_name, type, phone, email, address, area_id, latitude, longitude, credit_limit, payment_terms, is_active } = req.body;
    await db.query(
      `UPDATE chemists SET name=?,owner_name=?,type=?,phone=?,email=?,address=?,area_id=?,latitude=?,longitude=?,credit_limit=?,payment_terms=?,is_active=? WHERE id=?`,
      [name, owner_name||null, type||'chemist', phone||null, email||null, address||null,
       area_id||null, latitude||null, longitude||null, credit_limit||0, payment_terms||'immediate', is_active!==undefined?is_active:1, req.params.id]
    );
    res.json({ message: 'Updated' });
  } catch (err) {
    res.status(500).json({ message: 'Update failed', error: err.message });
  }
});

router.delete('/chemists/:id', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    await db.query('UPDATE chemists SET is_active=0 WHERE id=?', [req.params.id]);
    res.json({ message: 'Deactivated' });
  } catch (err) {
    res.status(500).json({ message: 'Delete failed', error: err.message });
  }
});

router.get('/chemists/:id/orders', auth, async (req, res) => {
  try {
    const db = await getPool();
    const [rows] = await db.query(
      `SELECT co.*, u.name as worker_name FROM chemist_orders co
       LEFT JOIN users u ON u.id=co.worker_id
       WHERE co.chemist_id=? ORDER BY co.order_date DESC`,
      [req.params.id]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: 'Failed', error: err.message });
  }
});

router.post('/chemists/:id/orders', auth, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const { amount, items, order_date, payment_status, notes } = req.body;
    const [r] = await db.query(
      `INSERT INTO chemist_orders (chemist_id, worker_id, org_id, amount, items, order_date, payment_status, notes)
       VALUES (?,?,?,?,?,?,?,?)`,
      [req.params.id, req.user.id, orgId, amount||0, items||null, order_date||new Date(), payment_status||'pending', notes||null]
    );
    res.json({ id: r.insertId, message: 'Order recorded' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to record order', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// FEATURE: WHATSAPP / SMS NOTIFICATIONS (MSG91 integration)
// ═══════════════════════════════════════════════════════════════════════════════
// Set MSG91_AUTH_KEY and MSG91_TEMPLATE_ID in .env to activate

async function sendSMS(phone, message) {
  const authKey = process.env.MSG91_AUTH_KEY;
  if (!authKey) return { skipped: true, reason: 'MSG91_AUTH_KEY not set in .env' };
  try {
    const payload = {
      sender: process.env.MSG91_SENDER_ID || 'MEDMGR',
      route: '4',
      country: '91',
      sms: [{ message, to: [String(phone).replace(/\D/g, '')] }]
    };
    const resp = await fetch('https://api.msg91.com/api/sendhttp.php', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', authkey: authKey },
      body: JSON.stringify(payload)
    });
    return await resp.json();
  } catch (e) {
    return { error: e.message };
  }
}

router.post('/notifications/send', auth, adminOnly, async (req, res) => {
  try {
    const { phone, message, type } = req.body;
    if (!phone || !message) return res.status(400).json({ message: 'phone and message required' });
    const result = await sendSMS(phone, message);
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    await db.query(
      `INSERT INTO notification_logs (org_id, phone, message, type, status, response, sent_by)
       VALUES (?,?,?,?,?,?,?)`,
      [orgId, phone, message, type||'manual', result.skipped?'skipped':'sent', JSON.stringify(result), req.user.id]
    );
    res.json({ message: 'Notification processed', result });
  } catch (err) {
    console.error('POST /notifications/send error:', err.message);
    res.status(500).json({ message: 'Notification failed', error: err.message });
  }
});

router.get('/notifications/logs', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const [rows] = await db.query(
      `SELECT nl.*, u.name as sent_by_name FROM notification_logs nl
       LEFT JOIN users u ON u.id=nl.sent_by
       WHERE nl.org_id=? ORDER BY nl.created_at DESC LIMIT 100`,
      [orgId]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: 'Failed', error: err.message });
  }
});

router.get('/notifications/settings', auth, adminOnly, async (req, res) => {
  const configured = !!process.env.MSG91_AUTH_KEY;
  res.json({
    configured,
    provider: 'MSG91',
    sender_id: process.env.MSG91_SENDER_ID || 'MEDMGR',
    message: configured ? 'MSG91 configured' : 'Set MSG91_AUTH_KEY in .env to enable SMS'
  });
});

// ═══════════════════════════════════════════════════════════════════════════════
// FEATURE: MULTI-LANGUAGE (i18n) — backend just returns locale strings
// ═══════════════════════════════════════════════════════════════════════════════

const I18N_STRINGS = {
  en: { app_name:'Medical Field Manager', visits:'Visits', orders:'Orders', doctors:'Doctors', workers:'Workers', reports:'Reports', settings:'Settings', logout:'Logout', dashboard:'Dashboard', session:'Session', today:'Today', plans:'Plans', no_data:'No data available', loading:'Loading...', save:'Save', cancel:'Cancel', delete:'Delete', edit:'Edit', add:'Add', search:'Search', filter:'Filter', export:'Export', low_stock:'Low Stock', restock:'Restock', target:'Target', achieved:'Achieved', leaderboard:'Leaderboard', follow_up:'Follow Up', reminder:'Reminder', chemist:'Chemist', stockist:'Stockist' },
  hi: { app_name:'मेडिकल फील्ड मैनेजर', visits:'विज़िट', orders:'ऑर्डर', doctors:'डॉक्टर', workers:'वर्कर', reports:'रिपोर्ट', settings:'सेटिंग', logout:'लॉगआउट', dashboard:'डैशबोर्ड', session:'सेशन', today:'आज', plans:'प्लान', no_data:'कोई डेटा नहीं', loading:'लोड हो रहा है...', save:'सेव करें', cancel:'रद्द करें', delete:'हटाएं', edit:'संपादित करें', add:'जोड़ें', search:'खोजें', filter:'फ़िल्टर', export:'एक्सपोर्ट', low_stock:'कम स्टॉक', restock:'स्टॉक भरें', target:'लक्ष्य', achieved:'हासिल', leaderboard:'लीडरबोर्ड', follow_up:'फॉलो अप', reminder:'रिमाइंडर', chemist:'केमिस्ट', stockist:'स्टॉकिस्ट' },
  ar: { app_name:'مدير الميدان الطبي', visits:'الزيارات', orders:'الطلبات', doctors:'الأطباء', workers:'الموظفون', reports:'التقارير', settings:'الإعدادات', logout:'تسجيل خروج', dashboard:'لوحة التحكم', session:'الجلسة', today:'اليوم', plans:'الخطط', no_data:'لا توجد بيانات', loading:'جار التحميل...', save:'حفظ', cancel:'إلغاء', delete:'حذف', edit:'تعديل', add:'إضافة', search:'بحث', filter:'فلتر', export:'تصدير', low_stock:'مخزون منخفض', restock:'إعادة التخزين', target:'الهدف', achieved:'المحقق', leaderboard:'المتصدرون', follow_up:'متابعة', reminder:'تذكير', chemist:'الصيدلي', stockist:'الموزع' },
};

router.get('/i18n/:lang', (req, res) => {
  const lang = req.params.lang;
  const strings = I18N_STRINGS[lang] || I18N_STRINGS['en'];
  res.json({ lang, strings });
});

router.get('/i18n', (req, res) => {
  res.json({ available: Object.keys(I18N_STRINGS), default: 'en' });
});

// ═══════════════════════════════════════════════════════════════════════════════
// DOCTOR APPOINTMENTS
// ═══════════════════════════════════════════════════════════════════════════════

router.get('/appointments', auth, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const { worker_id, doctor_id, status, date_from, date_to } = req.query;
    let where = 'WHERE 1=1';
    const params = [];
    if (orgId) { where += ' AND da.org_id=?'; params.push(orgId); }
    if (req.user.role === 'field_worker') { where += ' AND da.worker_id=?'; params.push(req.user.id); }
    else if (worker_id) { where += ' AND da.worker_id=?'; params.push(worker_id); }
    if (doctor_id) { where += ' AND da.doctor_id=?'; params.push(doctor_id); }
    if (status) { where += ' AND da.status=?'; params.push(status); }
    if (date_from) { where += ' AND da.appointment_date>=?'; params.push(date_from); }
    if (date_to) { where += ' AND da.appointment_date<=?'; params.push(date_to); }
    const [rows] = await db.query(
      `SELECT da.*, doc.name as doctor_name, doc.clinic_name, doc.phone as doctor_phone,
       a.name as area_name, u.name as worker_name
       FROM doctor_appointments da
       JOIN doctors doc ON doc.id=da.doctor_id
       LEFT JOIN areas a ON a.id=doc.area_id
       JOIN users u ON u.id=da.worker_id
       ${where} ORDER BY da.appointment_date ASC, da.appointment_time ASC`,
      params
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch appointments', error: err.message });
  }
});

router.post('/appointments', auth, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const { doctor_id, appointment_date, appointment_time, purpose, notes } = req.body;
    if (!doctor_id || !appointment_date) return res.status(400).json({ message: 'doctor_id and appointment_date required' });
    const worker_id = req.user.role === 'field_worker' ? req.user.id : req.body.worker_id;
    if (!worker_id) return res.status(400).json({ message: 'worker_id required' });
    const code = 'APT-' + Date.now().toString(36).toUpperCase();
    const [r] = await db.query(
      `INSERT INTO doctor_appointments (doctor_id, worker_id, org_id, appointment_date, appointment_time, purpose, notes, confirmation_code)
       VALUES (?,?,?,?,?,?,?,?)`,
      [doctor_id, worker_id, orgId, appointment_date, appointment_time || null, purpose || null, notes || null, code]
    );
    // Auto-create follow-up reminder
    await db.query(
      `INSERT INTO follow_up_reminders (worker_id, doctor_id, org_id, remind_date, notes, created_by)
       VALUES (?,?,?,?,?,?)`,
      [worker_id, doctor_id, orgId, appointment_date, `Appointment: ${purpose || 'Doctor visit'}`, req.user.id]
    ).catch(() => {});
    res.status(201).json({ id: r.insertId, confirmation_code: code, message: 'Appointment booked' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to book appointment', error: err.message });
  }
});

router.put('/appointments/:id', auth, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const { appointment_date, appointment_time, purpose, notes, status } = req.body;
    const [result] = await db.query(
      `UPDATE doctor_appointments SET appointment_date=?,appointment_time=?,purpose=?,notes=?,status=?,updated_at=NOW()
       WHERE id=? AND org_id=?`,
      [appointment_date, appointment_time || null, purpose, notes, status, req.params.id, orgId]
    );
    if (result.affectedRows === 0) return res.status(404).json({ message: 'Appointment not found' });
    res.json({ message: 'Appointment updated' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to update appointment', error: err.message });
  }
});

router.delete('/appointments/:id', auth, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    await db.query('DELETE FROM doctor_appointments WHERE id=? AND org_id=?', [req.params.id, orgId]);
    res.json({ message: 'Appointment deleted' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to delete appointment', error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// HIPAA COMPLIANCE — AUDIT LOGS
// ═══════════════════════════════════════════════════════════════════════════════

// Middleware to auto-log sensitive actions (attach to routes as needed)
async function auditLog(db, { orgId, userId, userName, action, entityType, entityId, oldValues, newValues, req }) {
  try {
    await db.query(
      `INSERT INTO audit_logs (org_id,user_id,user_name,action,entity_type,entity_id,old_values,new_values,ip_address,user_agent)
       VALUES (?,?,?,?,?,?,?,?,?,?)`,
      [
        orgId || null, userId || null, userName || null, action,
        entityType || null, entityId || null,
        oldValues ? JSON.stringify(oldValues) : null,
        newValues ? JSON.stringify(newValues) : null,
        req?.ip || req?.connection?.remoteAddress || null,
        req?.headers?.['user-agent']?.substring(0, 500) || null,
      ]
    );
  } catch (e) { /* audit failure must never break main flow */ }
}
// Export for use in other routes if needed
router.auditLog = auditLog;

router.get('/audit/logs', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const { entity_type, user_id, date_from, date_to, action, limit = 200 } = req.query;
    let where = 'WHERE al.org_id=?';
    const params = [orgId];
    if (entity_type) { where += ' AND al.entity_type=?'; params.push(entity_type); }
    if (user_id) { where += ' AND al.user_id=?'; params.push(user_id); }
    if (action) { where += ' AND al.action LIKE ?'; params.push(`%${action}%`); }
    if (date_from) { where += ' AND DATE(al.created_at)>=?'; params.push(date_from); }
    if (date_to) { where += ' AND DATE(al.created_at)<=?'; params.push(date_to); }
    params.push(Math.min(Number(limit), 500));
    const [rows] = await db.query(
      `SELECT al.* FROM audit_logs al ${where} ORDER BY al.created_at DESC LIMIT ?`,
      params
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch audit logs', error: err.message });
  }
});

router.get('/audit/summary', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const [[totals]] = await db.query(
      `SELECT COUNT(*) as total_events,
       COUNT(DISTINCT user_id) as unique_users,
       SUM(DATE(created_at)=CURDATE()) as today,
       SUM(DATE(created_at)>=DATE_SUB(CURDATE(),INTERVAL 7 DAY)) as last_7_days
       FROM audit_logs WHERE org_id=?`, [orgId]
    );
    const [by_action] = await db.query(
      `SELECT action, COUNT(*) as cnt FROM audit_logs WHERE org_id=? GROUP BY action ORDER BY cnt DESC LIMIT 10`, [orgId]
    );
    const [by_user] = await db.query(
      `SELECT user_name, COUNT(*) as cnt FROM audit_logs WHERE org_id=? AND user_name IS NOT NULL GROUP BY user_id ORDER BY cnt DESC LIMIT 10`, [orgId]
    );
    const [recent] = await db.query(
      `SELECT * FROM audit_logs WHERE org_id=? ORDER BY created_at DESC LIMIT 20`, [orgId]
    );
    res.json({ totals, by_action, by_user, recent });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch audit summary', error: err.message });
  }
});

// HIPAA: Right to delete — remove all personally identifiable data for a doctor
router.delete('/hipaa/doctor/:id/purge', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const doctorId = req.params.id;
    // Anonymize instead of hard delete to preserve aggregate statistics
    await db.query(
      `UPDATE doctors SET name='[DELETED]', phone=NULL, email=NULL, address=NULL, latitude=NULL, longitude=NULL, is_active=0
       WHERE id=? AND org_id=?`, [doctorId, orgId]
    );
    await db.query(
      `UPDATE doctor_visits SET doctor_feedback=NULL, notes=NULL, photo_url=NULL WHERE doctor_id=? AND org_id=?`,
      [doctorId, orgId]
    );
    await auditLog(db, { orgId, userId: req.user.id, userName: req.user.name, action: 'HIPAA_PURGE', entityType: 'doctor', entityId: doctorId, req });
    res.json({ message: 'Doctor PII purged (HIPAA compliant)' });
  } catch (err) {
    res.status(500).json({ message: 'Purge failed', error: err.message });
  }
});

router.get('/hipaa/data-export/:userId', auth, adminOnly, async (req, res) => {
  try {
    const db = await getPool();
    const orgId = await getOrgId(req.user.id);
    const uid = req.params.userId;
    const [[user]] = await db.query('SELECT id,name,username,role,created_at FROM users WHERE id=?', [uid]);
    const [visits] = await db.query('SELECT * FROM doctor_visits WHERE worker_id=? AND org_id=?', [uid, orgId]);
    const [sessions] = await db.query('SELECT * FROM field_sessions WHERE worker_id=? AND org_id=?', [uid, orgId]);
    const [pings] = await db.query('SELECT * FROM location_pings WHERE worker_id=?', [uid]);
    await auditLog(db, { orgId, userId: req.user.id, userName: req.user.name, action: 'HIPAA_DATA_EXPORT', entityType: 'user', entityId: uid, req });
    res.json({ user, visits, sessions, location_pings: pings, exported_at: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ message: 'Export failed', error: err.message });
  }
});

module.exports = router;

