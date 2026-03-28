const mysql = require('mysql2/promise');
require('dotenv').config();

let pool;

async function getPool() {
  if (!pool) {
    pool = mysql.createPool({
      // Supports Railway variable names (MYSQLHOST, MYSQLUSER etc.)
      // as well as custom names (DB_HOST, DB_USER etc.)
      host:     process.env.DB_HOST     || process.env.MYSQLHOST     || 'localhost',
      port:     process.env.DB_PORT     || process.env.MYSQLPORT     || 3306,
      user:     process.env.DB_USER     || process.env.MYSQLUSER     || 'root',
      password: process.env.DB_PASSWORD || process.env.MYSQLPASSWORD || '',
      database: process.env.DB_NAME     || process.env.MYSQLDATABASE || 'medical_manager',
      waitForConnections: true,
      connectionLimit: 10,
      connectTimeout: 30000,
      // SSL for Railway
      ssl: process.env.DB_HOST?.includes('railway') || process.env.MYSQLHOST?.includes('railway')
        ? { rejectUnauthorized: false }
        : false,
    });
  }
  return pool;
}

async function initializeDatabase() {
  const host     = process.env.DB_HOST     || process.env.MYSQLHOST     || 'localhost';
  const port     = process.env.DB_PORT     || process.env.MYSQLPORT     || 3306;
  const user     = process.env.DB_USER     || process.env.MYSQLUSER     || 'root';
  const password = process.env.DB_PASSWORD || process.env.MYSQLPASSWORD || '';
  const dbName   = process.env.DB_NAME     || process.env.MYSQLDATABASE || 'medical_manager';

  console.log(`🔌 Connecting to MySQL: ${user}@${host}:${port}/${dbName}`);

  // Create database if it doesn't exist yet
  try {
    const tempPool = mysql.createPool({
      host, port, user, password,
      waitForConnections: true,
      connectionLimit: 2,
      connectTimeout: 30000,
      ssl: host.includes('railway') ? { rejectUnauthorized: false } : false,
    });
    await tempPool.query(`CREATE DATABASE IF NOT EXISTS \`${dbName}\``);
    await tempPool.end();
  } catch (e) {
    // On Railway, the database already exists
    // CREATE DATABASE may fail — safe to ignore
    console.log('ℹ️  DB create skip (already exists):', e.message);
  }

  const db = await getPool();

  // ─── USERS ──────────────────────────────────────────────────────────────────
  await db.query(`CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin','worker','field_worker') DEFAULT 'worker',
    phone VARCHAR(50),
    hourly_rate DECIMAL(10,2) DEFAULT 0,
    is_active TINYINT DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // ─── DEPARTMENTS ────────────────────────────────────────────────────────────
  await db.query(`CREATE TABLE IF NOT EXISTS departments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    color VARCHAR(20) DEFAULT '#3B82F6',
    stage_order INT DEFAULT 999,
    is_active TINYINT DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // ─── WORKER <-> DEPARTMENT ──────────────────────────────────────────────────
  await db.query(`CREATE TABLE IF NOT EXISTS worker_departments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    worker_id INT NOT NULL,
    department_id INT NOT NULL,
    UNIQUE KEY unique_wd (worker_id, department_id),
    FOREIGN KEY (worker_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (department_id) REFERENCES departments(id) ON DELETE CASCADE
  )`);

  // ─── PRODUCT CATEGORIES ─────────────────────────────────────────────────────
  await db.query(`CREATE TABLE IF NOT EXISTS product_categories (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    is_active TINYINT DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // ─── PRODUCTION ORDERS ──────────────────────────────────────────────────────
  await db.query(`CREATE TABLE IF NOT EXISTS production_orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    order_no VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    category_id INT,
    client_name VARCHAR(255),
    client_phone VARCHAR(50),
    description TEXT,
    status ENUM('active','completed','on_hold','cancelled','deleted') DEFAULT 'active',
    priority ENUM('low','medium','high','urgent') DEFAULT 'medium',
    order_date DATE,
    deadline DATE,
    total_amount DECIMAL(12,2) DEFAULT 0,
    notes TEXT,
    created_by INT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (category_id) REFERENCES product_categories(id) ON DELETE SET NULL
  )`);

  // ─── PRODUCTION ITEMS ───────────────────────────────────────────────────────
  await db.query(`CREATE TABLE IF NOT EXISTS production_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    order_id INT NOT NULL,
    item_name VARCHAR(255) NOT NULL,
    item_code VARCHAR(100),
    description TEXT,
    quantity INT DEFAULT 1,
    unit VARCHAR(50) DEFAULT 'pcs',
    unit_price DECIMAL(10,2) DEFAULT 0,
    status ENUM('pending','in_progress','completed') DEFAULT 'pending',
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (order_id) REFERENCES production_orders(id) ON DELETE CASCADE
  )`);

  // ─── PRODUCTION CHAINS ──────────────────────────────────────────────────────
  await db.query(`CREATE TABLE IF NOT EXISTS production_chains (
    id INT AUTO_INCREMENT PRIMARY KEY,
    order_id INT NOT NULL,
    item_id INT,
    department_id INT NOT NULL,
    stage_order INT NOT NULL DEFAULT 1,
    is_active TINYINT DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (order_id) REFERENCES production_orders(id) ON DELETE CASCADE,
    FOREIGN KEY (item_id) REFERENCES production_items(id) ON DELETE CASCADE,
    FOREIGN KEY (department_id) REFERENCES departments(id)
  )`);

  // ─── TASK ASSIGNMENTS ───────────────────────────────────────────────────────
  await db.query(`CREATE TABLE IF NOT EXISTS task_assignments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    order_id INT NOT NULL,
    item_id INT,
    assign_type ENUM('worker','department') DEFAULT 'worker',
    worker_id INT,
    department_id INT,
    stage_order INT DEFAULT 0,
    task_title VARCHAR(255) NOT NULL,
    task_description TEXT,
    quantity_assigned INT DEFAULT 1,
    quantity_completed INT DEFAULT 0,
    status ENUM('pending','in_progress','completed','on_hold','waiting') DEFAULT 'pending',
    priority ENUM('low','medium','high','urgent') DEFAULT 'medium',
    start_date DATE,
    due_date DATE,
    completed_date DATE,
    worker_notes TEXT,
    admin_notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (order_id) REFERENCES production_orders(id) ON DELETE CASCADE,
    FOREIGN KEY (item_id) REFERENCES production_items(id) ON DELETE SET NULL,
    FOREIGN KEY (worker_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (department_id) REFERENCES departments(id) ON DELETE SET NULL
  )`);

  // ─── WORKER TIME LOGS ───────────────────────────────────────────────────────
  await db.query(`CREATE TABLE IF NOT EXISTS worker_time_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    task_id INT NOT NULL,
    worker_id INT NOT NULL,
    clock_in DATETIME NOT NULL,
    clock_out DATETIME,
    duration_minutes INT DEFAULT 0,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (task_id) REFERENCES task_assignments(id) ON DELETE CASCADE,
    FOREIGN KEY (worker_id) REFERENCES users(id)
  )`);

  // ─── DAILY PROGRESS ─────────────────────────────────────────────────────────
  await db.query(`CREATE TABLE IF NOT EXISTS daily_progress (
    id INT AUTO_INCREMENT PRIMARY KEY,
    task_id INT NOT NULL,
    item_id INT NOT NULL,
    department_id INT,
    worker_id INT,
    work_date DATE NOT NULL,
    qty_done INT DEFAULT 0,
    notes TEXT,
    created_by INT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (task_id) REFERENCES task_assignments(id) ON DELETE CASCADE,
    FOREIGN KEY (item_id) REFERENCES production_items(id) ON DELETE CASCADE,
    FOREIGN KEY (department_id) REFERENCES departments(id),
    FOREIGN KEY (worker_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (created_by) REFERENCES users(id)
  )`);

  // ─── ORGANIZATIONS (must be before areas/doctors which reference it) ─────────
  await db.query(`CREATE TABLE IF NOT EXISTS organizations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    owner_name VARCHAR(255),
    email VARCHAR(255),
    phone VARCHAR(50),
    address TEXT,
    is_active TINYINT DEFAULT 1,
    license_expiry DATE,
    max_users INT DEFAULT 50,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // ─── AREAS ──────────────────────────────────────────────────────────────────
  await db.query(`CREATE TABLE IF NOT EXISTS areas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    org_id INT,
    name VARCHAR(255) NOT NULL,
    city VARCHAR(255),
    state VARCHAR(255),
    description TEXT,
    is_active TINYINT DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
  )`);

  // ─── DOCTORS ────────────────────────────────────────────────────────────────
  await db.query(`CREATE TABLE IF NOT EXISTS doctors (
    id INT AUTO_INCREMENT PRIMARY KEY,
    org_id INT,
    name VARCHAR(255) NOT NULL,
    specialization VARCHAR(255),
    clinic_name VARCHAR(255),
    phone VARCHAR(50),
    email VARCHAR(255),
    address TEXT,
    area_id INT,
    latitude DECIMAL(10,8),
    longitude DECIMAL(11,8),
    is_active TINYINT DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (area_id) REFERENCES areas(id) ON DELETE SET NULL,
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
  )`);

  // ─── FIELD WORKER <-> AREA ──────────────────────────────────────────────────
  await db.query(`CREATE TABLE IF NOT EXISTS field_worker_areas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    worker_id INT NOT NULL,
    area_id INT NOT NULL,
    UNIQUE KEY unique_wa (worker_id, area_id),
    FOREIGN KEY (worker_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (area_id) REFERENCES areas(id) ON DELETE CASCADE
  )`);

  // ─── VISIT PLANS ────────────────────────────────────────────────────────────
  await db.query(`CREATE TABLE IF NOT EXISTS visit_plans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    worker_id INT NOT NULL,
    doctor_id INT NOT NULL,
    planned_date DATE NOT NULL,
    purpose TEXT,
    sample_products TEXT,
    status ENUM('planned','completed','skipped','rescheduled') DEFAULT 'planned',
    admin_notes TEXT,
    created_by INT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (worker_id) REFERENCES users(id),
    FOREIGN KEY (doctor_id) REFERENCES doctors(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
  )`);

  // ─── FIELD SESSIONS ─────────────────────────────────────────────────────────
  await db.query(`CREATE TABLE IF NOT EXISTS field_sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    worker_id INT NOT NULL,
    start_time DATETIME NOT NULL,
    end_time DATETIME,
    start_location_lat DECIMAL(10,8),
    start_location_lng DECIMAL(11,8),
    end_location_lat DECIMAL(10,8),
    end_location_lng DECIMAL(11,8),
    total_distance_km DECIMAL(8,2) DEFAULT 0,
    duration_minutes INT DEFAULT 0,
    status ENUM('active','completed') DEFAULT 'active',
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (worker_id) REFERENCES users(id)
  )`);

  // ─── DOCTOR VISITS ──────────────────────────────────────────────────────────
  await db.query(`CREATE TABLE IF NOT EXISTS doctor_visits (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id INT NOT NULL,
    worker_id INT NOT NULL,
    doctor_id INT NOT NULL,
    visit_plan_id INT,
    visit_type ENUM('doctor','chemist') DEFAULT 'doctor',
    arrival_time DATETIME NOT NULL,
    departure_time DATETIME,
    arrival_lat DECIMAL(10,8),
    arrival_lng DECIMAL(11,8),
    duration_minutes INT DEFAULT 0,
    product_id INT,
    samples_given TEXT,
    order_received TINYINT DEFAULT 0,
    order_amount DECIMAL(10,2) DEFAULT 0,
    photo_url VARCHAR(500),
    doctor_feedback TEXT,
    outcome ENUM('interested','not_interested','follow_up','sample_given','order_placed','not_available','failed') DEFAULT 'sample_given',
    failure_reason TEXT,
    notes TEXT,
    distance_from_prev_km DECIMAL(8,2) DEFAULT 0,
    travel_time_minutes INT DEFAULT 0,
    geo_verified TINYINT DEFAULT 0,
    distance_from_doctor_m INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES field_sessions(id),
    FOREIGN KEY (worker_id) REFERENCES users(id),
    FOREIGN KEY (doctor_id) REFERENCES doctors(id),
    FOREIGN KEY (visit_plan_id) REFERENCES visit_plans(id) ON DELETE SET NULL
  )`);

  // ─── ALTER doctor_visits for existing DBs (safe migrations) ─────────────────
  // Safe column migration: check INFORMATION_SCHEMA first (works on all MySQL versions)
  async function addColumnIfMissing(db, table, column, definition) {
    const [[row]] = await db.query(
      `SELECT COUNT(*) as cnt FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=? AND COLUMN_NAME=?`,
      [table, column]
    );
    if (row.cnt === 0) {
      try {
        await db.query(`ALTER TABLE \`${table}\` ADD COLUMN \`${column}\` ${definition}`);
        console.log(`  ✅ Added column ${table}.${column}`);
      } catch (e) {
        console.log(`  ⚠️  Could not add ${table}.${column}: ${e.message}`);
      }
    }
  }

  await addColumnIfMissing(db, 'doctor_visits', 'visit_type', "ENUM('doctor','chemist') DEFAULT 'doctor'");
  await addColumnIfMissing(db, 'doctor_visits', 'product_id', 'INT NULL');
  await addColumnIfMissing(db, 'doctor_visits', 'order_received', 'TINYINT DEFAULT 0');
  await addColumnIfMissing(db, 'doctor_visits', 'order_amount', 'DECIMAL(10,2) DEFAULT 0');
  await addColumnIfMissing(db, 'doctor_visits', 'photo_url', 'VARCHAR(500)');
  await addColumnIfMissing(db, 'doctor_visits', 'failure_reason', 'TEXT');
  await addColumnIfMissing(db, 'doctor_visits', 'geo_verified', 'TINYINT DEFAULT 0');
  await addColumnIfMissing(db, 'doctor_visits', 'distance_from_doctor_m', 'INT DEFAULT 0');
  // Modify outcome enum safely
  try {
    await db.query(`ALTER TABLE doctor_visits MODIFY COLUMN outcome ENUM('interested','not_interested','follow_up','sample_given','order_placed','not_available','failed') DEFAULT 'sample_given'`);
  } catch (e) { /* already correct */ }

  // ─── LOCATION PINGS ─────────────────────────────────────────────────────────
  await db.query(`CREATE TABLE IF NOT EXISTS location_pings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id INT NOT NULL,
    worker_id INT NOT NULL,
    latitude DECIMAL(10,8) NOT NULL,
    longitude DECIMAL(11,8) NOT NULL,
    accuracy DECIMAL(8,2),
    speed DECIMAL(8,2),
    heading DECIMAL(8,2),
    recorded_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES field_sessions(id),
    FOREIGN KEY (worker_id) REFERENCES users(id)
  )`);

  // ─── SAMPLE PRODUCTS ────────────────────────────────────────────────────────
  await db.query(`CREATE TABLE IF NOT EXISTS sample_products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(255),
    description TEXT,
    is_active TINYINT DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // ─── APP SETTINGS ───────────────────────────────────────────────────────────
  await db.query(`CREATE TABLE IF NOT EXISTS app_settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    setting_key VARCHAR(100) UNIQUE NOT NULL,
    setting_value TEXT NOT NULL,
    updated_by INT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
  )`);

  // ─── ORG PERMISSIONS (which menus are enabled per org) ──────────────────────
  await db.query(`CREATE TABLE IF NOT EXISTS org_permissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    org_id INT NOT NULL,
    menu_key VARCHAR(100) NOT NULL,
    is_enabled TINYINT DEFAULT 1,
    UNIQUE KEY uq_org_menu (org_id, menu_key),
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
  )`);

  // ─── ORG USERS (which org does each admin/user belong to) ───────────────────
  await db.query(`CREATE TABLE IF NOT EXISTS org_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    org_id INT NOT NULL,
    user_id INT NOT NULL,
    UNIQUE KEY uq_org_user (org_id, user_id),
    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  // ─── Alter users role to include super_admin ───────────────────────────────────
  try {
    await db.query(`ALTER TABLE users MODIFY COLUMN role ENUM('super_admin','admin','worker','field_worker') DEFAULT 'worker'`);
  } catch(e) { /* already updated */ }

  // ─── Add org_id to existing tables (safe migrations) ─────────────────────────
  await addColumnIfMissing(db, 'areas',          'org_id', 'INT NULL');
  await addColumnIfMissing(db, 'doctors',        'org_id', 'INT NULL');
  await addColumnIfMissing(db, 'visit_plans',    'org_id', 'INT NULL');
  await addColumnIfMissing(db, 'doctor_visits',  'org_id', 'INT NULL');
  await addColumnIfMissing(db, 'field_sessions', 'org_id', 'INT NULL');
  await addColumnIfMissing(db, 'users',          'org_id', 'INT NULL');

  // ─── SEED DATA ─────────────────────────────────────────────────────────────────
  const bcrypt = require('bcryptjs');

  // Default app settings
  const defaultSettings = [
    ['currency_symbol', '₹'],
    ['currency_name', 'INR'],
    ['date_format', 'DD/MM/YYYY'],
    ['company_name', 'Medical Manager'],
    ['timezone', 'Asia/Kolkata'],
    ['location_ping_interval', '60'],
    ['geofence_radius_m', '500'],
    ['no_movement_alert_minutes', '30'],
  ];
  for (const [k, v] of defaultSettings) {
    await db.query('INSERT IGNORE INTO app_settings (setting_key, setting_value) VALUES (?,?)', [k, v]);
  }

  // Super Admin user — Laxman (upsert on duplicate)
  const superPass = bcrypt.hashSync('Laksh@8173', 10);
  await db.query(
    `INSERT INTO users (name, username, password, role) VALUES (?,?,?,?)
     ON DUPLICATE KEY UPDATE role='super_admin', password=VALUES(password), name=VALUES(name)`,
    ['Laxman', 'Laxman', superPass, 'super_admin']
  );

  // Global departments (shared, no org_id — production module only)
  const depts = [
    ['Raw Material Intake', 'Incoming raw material verification', '#EF4444', 1],
    ['Machining', 'CNC & precision machining', '#F97316', 2],
    ['Assembly', 'Component assembly', '#EAB308', 3],
    ['Quality Control', 'QC inspection & testing', '#22C55E', 4],
    ['Sterilization', 'Sterilization & packaging', '#06B6D4', 5],
    ['Dispatch', 'Final packing & dispatch', '#8B5CF6', 6],
  ];
  for (const [name, desc, color, order] of depts) {
    await db.query(
      `INSERT IGNORE INTO departments (name, description, color, stage_order) VALUES (?,?,?,?)`,
      [name, desc, color, order]
    );
  }
  // Note: Areas are org-specific — each organization manages their own areas.

  console.log('✅ Database initialized successfully');
}

module.exports = { getPool, initializeDatabase };
