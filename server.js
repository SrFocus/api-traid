require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, param, query, validationResult } = require('express-validator');
const hpp = require('hpp');
const compression = require('compression');

const app = express();
const PORT = process.env.PORT || 3001;

// ==================== SISTEMA DE CACHE SIMPLES ====================
const cache = new Map();
const CACHE_TTL = 30 * 1000; // 30 segundos

const cacheGet = (key) => {
  const item = cache.get(key);
  if (!item) return null;
  if (Date.now() > item.expiry) {
    cache.delete(key);
    return null;
  }
  return item.data;
};

const cacheSet = (key, data, ttl = CACHE_TTL) => {
  cache.set(key, { data, expiry: Date.now() + ttl });
};

const cacheClear = (pattern) => {
  if (!pattern) {
    cache.clear();
    return;
  }
  for (const key of cache.keys()) {
    if (key.includes(pattern)) {
      cache.delete(key);
    }
  }
};

// ==================== CONFIGURAÇÕES DE SEGURANÇA ====================

// Verificar se JWT_SECRET está configurado (OBRIGATÓRIO em produção)
if (!process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET não definido! Configure no .env antes de rodar o backend.');
}
const JWT_SECRET = process.env.JWT_SECRET;

// Configuração do Helmet (Headers de segurança HTTP)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// Proteção contra HTTP Parameter Pollution
app.use(hpp());

// Compressão GZIP para respostas
app.use(compression({
  level: 6, // Nível de compressão (1-9, 6 é bom equilíbrio)
  threshold: 1024, // Mínimo de bytes para comprimir
  filter: (req, res) => {
    if (req.headers['x-no-compression']) return false;
    return compression.filter(req, res);
  }
}));

// Rate Limiting Global - 100 requisições por minuto por IP
const globalLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minuto
  max: 100,
  message: { error: 'Muitas requisições. Tente novamente em alguns segundos.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  },
});
app.use(globalLimiter);

// Rate Limiting específico para login - 5 tentativas por minuto
const loginLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minuto
  max: 5,
  message: { error: 'Muitas tentativas de login. Aguarde 1 minuto.' },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  },
});

// Rate Limiting para ações sensíveis - 20 por minuto
const actionLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { error: 'Muitas ações realizadas. Aguarde um momento.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// CORS configurado de forma segura
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : ['http://localhost:5173', 'http://localhost:3000', 'http://127.0.0.1:5173'];

app.use(cors({
  origin: function(origin, callback) {
    // Permitir requisições sem origin (como mobile apps ou curl)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
      return callback(null, true);
    }
    return callback(new Error('Não permitido pelo CORS'), false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400, // Cache preflight por 24 horas
}));

// Parser JSON com limite de tamanho
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Sanitização de dados de entrada
const sanitizeInput = (obj) => {
  if (typeof obj === 'string') {
    // Remove caracteres perigosos e protege contra NoSQL/SQL injection
    return obj
      .replace(/[${}]/g, '')
      .replace(/[<>]/g, '')
      .trim()
      .slice(0, 1000); // Limite de tamanho
  }
  if (Array.isArray(obj)) {
    return obj.map(sanitizeInput);
  }
  if (obj && typeof obj === 'object') {
    const sanitized = {};
    for (const [key, value] of Object.entries(obj)) {
      const safeKey = key.replace(/[${}]/g, '').slice(0, 100);
      sanitized[safeKey] = sanitizeInput(value);
    }
    return sanitized;
  }
  return obj;
};

// Middleware de sanitização
app.use((req, res, next) => {
  if (req.body) req.body = sanitizeInput(req.body);
  if (req.query) req.query = sanitizeInput(req.query);
  if (req.params) req.params = sanitizeInput(req.params);
  next();
});

// ==================== HEALTH CHECK (público) ====================
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ==================== VALIDADORES REUTILIZÁVEIS ====================

const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
      error: 'Dados inválidos', 
      details: errors.array().map(e => e.msg) 
    });
  }
  next();
};

const validateId = param('id').isInt({ min: 1 }).withMessage('ID inválido');
const validateAmount = body('amount').isInt({ min: 1, max: 999999999 }).withMessage('Quantidade inválida');
const validateItem = body('item').isString().isLength({ min: 1, max: 100 }).trim().withMessage('Item inválido');
const validatePage = query('page').optional().isInt({ min: 1, max: 10000 }).withMessage('Página inválida');
const validateLimit = query('limit').optional().isInt({ min: 1, max: 100 }).withMessage('Limite inválido');
const validateSearch = query('search').optional().isString().isLength({ max: 100 }).trim().withMessage('Busca inválida');

// Conexão com o banco de dados vRP (com configurações de segurança)
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  connectTimeout: 10000,
  acquireTimeout: 10000,
  timeout: 30000,
  enableKeepAlive: true,
  keepAliveInitialDelay: 10000,
  // Proteções adicionais
  multipleStatements: false, // Previne SQL injection via múltiplas queries
  dateStrings: true,
});

// Teste de conexão com o banco
pool.getConnection()
  .then(conn => {
    console.log('✅ Conexão com banco de dados estabelecida');
    conn.release();
  })
  .catch(err => {
    console.error('❌ Erro ao conectar com banco de dados:', err.message);
  });

// Função para registrar log de ação (com proteção contra erros)
const logAction = async (userId, username, action, details = null, targetType = null, targetId = null, ip = null) => {
  try {
    // Sanitiza e limita tamanho dos campos
    const safeDetails = details ? String(details).slice(0, 500) : null;
    const safeUsername = String(username).slice(0, 50);
    const safeAction = String(action).slice(0, 50);
    const safeTargetType = targetType ? String(targetType).slice(0, 50) : null;
    const safeTargetId = targetId ? String(targetId).slice(0, 50) : null;
    const safeIp = ip ? String(ip).slice(0, 45) : null;
    
    await pool.query(
      'INSERT INTO panel_logs (user_id, username, action, details, target_type, target_id, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [userId, safeUsername, safeAction, safeDetails, safeTargetType, safeTargetId, safeIp]
    );
  } catch (error) {
    console.error('Erro ao registrar log:', error.message);
  }
};

// Obter IP real do cliente
const getClientIp = (req) => {
  const forwarded = req.headers['x-forwarded-for'];
  const ip = forwarded ? forwarded.split(',')[0].trim() : req.socket.remoteAddress;
  return ip ? ip.replace(/^::ffff:/, '') : 'unknown';
};

// Middleware de autenticação (com verificações adicionais)
const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Token não fornecido' });
    }
    
    const token = authHeader.slice(7);
    
    if (!token || token.length < 10 || token.length > 1000) {
      return res.status(401).json({ error: 'Token inválido' });
    }
    
    const decoded = jwt.verify(token, JWT_SECRET, {
      algorithms: ['HS256'],
      maxAge: '24h',
    });
    
    // Verificar se usuário ainda existe e está ativo
    const [users] = await pool.query(
      'SELECT id, username, role, active FROM panel_users WHERE id = ? AND active = TRUE',
      [decoded.id]
    );
    
    if (users.length === 0) {
      return res.status(401).json({ error: 'Usuário não encontrado ou desativado' });
    }
    
    req.user = {
      id: users[0].id,
      username: users[0].username,
      role: users[0].role,
    };
    
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expirado' });
    }
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Token inválido' });
    }
    console.error('Erro na autenticação:', error.message);
    return res.status(401).json({ error: 'Erro na autenticação' });
  }
};

// Middleware para verificar se é dono
const ownerMiddleware = (req, res, next) => {
  if (req.user.role !== 'dono') {
    return res.status(403).json({ error: 'Acesso negado. Apenas donos podem acessar.' });
  }
  next();
};

const safeJsonParse = (value, fallback = {}) => {
  try {
    if (value === null || value === undefined || value === '') return fallback;
    return typeof value === 'string' ? JSON.parse(value) : value;
  } catch {
    return fallback;
  }
};

const normalizeInventoryItems = (inventoryObj) => {
  if (!inventoryObj || typeof inventoryObj !== 'object') return [];

  return Object.entries(inventoryObj)
    .filter(([, data]) => data && data.item)
    .map(([slot, data]) => ({
      slot: parseInt(slot),
      item: data.item,
      amount: parseInt(data.amount || 0)
    }))
    .sort((a, b) => a.slot - b.slot);
};

// Normaliza inventário no formato {itemName: {amount: N}} (baú de casa/veículo no vrp_srv_data)
const normalizeNamedInventory = (obj) => {
  if (!obj || typeof obj !== 'object') return [];
  return Object.entries(obj)
    .filter(([, v]) => v && parseInt(v.amount) > 0)
    .map(([name, v]) => ({ slot: name, item: name, amount: parseInt(v.amount) || 0 }))
    .sort((a, b) => a.item.localeCompare(b.item));
};

const getContainerFromState = (stateObj) => {
  const parsed = safeJsonParse(stateObj, {});

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return {
      root: { trunk: {} },
      key: 'trunk',
      inventory: {}
    };
  }

  if (parsed.trunk && typeof parsed.trunk === 'object') {
    return { root: parsed, key: 'trunk', inventory: parsed.trunk };
  }

  if (parsed.inventorys && typeof parsed.inventorys === 'object') {
    return { root: parsed, key: 'inventorys', inventory: parsed.inventorys };
  }

  if (parsed.items && typeof parsed.items === 'object') {
    return { root: parsed, key: 'items', inventory: parsed.items };
  }

  const values = Object.values(parsed);
  const looksLikeSlotMap = values.length > 0 && values.every((entry) => entry && typeof entry === 'object' && entry.item);
  if (looksLikeSlotMap) {
    return { root: parsed, key: null, inventory: parsed };
  }

  parsed.trunk = parsed.trunk || {};
  return { root: parsed, key: 'trunk', inventory: parsed.trunk };
};

const buildStateWithInventory = (containerInfo, updatedInventory) => {
  const root = containerInfo.root;

  if (containerInfo.key) {
    root[containerInfo.key] = updatedInventory;
    return root;
  }

  return updatedInventory;
};

const upsertItemInInventory = (inventoryObj, itemName, amount) => {
  const normalizedItem = String(itemName).toUpperCase();
  const addAmount = parseInt(amount);

  let targetSlot = null;
  let existingAmount = 0;

  for (const [slot, data] of Object.entries(inventoryObj)) {
    if (data?.item && data.item.toLowerCase() === normalizedItem.toLowerCase()) {
      targetSlot = slot;
      existingAmount = parseInt(data.amount || 0);
      break;
    }
  }

  if (!targetSlot) {
    for (let index = 1; index <= 200; index++) {
      if (!inventoryObj[index.toString()]) {
        targetSlot = index.toString();
        break;
      }
    }
  }

  if (!targetSlot) return null;

  inventoryObj[targetSlot] = {
    item: normalizedItem,
    amount: existingAmount + addAmount
  };

  return targetSlot;
};

const generatePlate = () => {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let plate = '';
  for (let index = 0; index < 8; index++) {
    plate += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return plate;
};

// ==================== ROTAS DE AUTENTICAÇÃO ====================

// Armazenamento de tentativas de login falhas (em memória - considere Redis em produção)
const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutos

// Limpar tentativas antigas periodicamente
setInterval(() => {
  const now = Date.now();
  for (const [key, data] of loginAttempts.entries()) {
    if (now - data.firstAttempt > LOCKOUT_TIME) {
      loginAttempts.delete(key);
    }
  }
}, 60 * 1000);

app.post('/api/auth/login', 
  loginLimiter,
  body('username').isString().isLength({ min: 3, max: 50 }).trim().withMessage('Username inválido'),
  body('password').isString().isLength({ min: 6, max: 100 }).withMessage('Senha inválida'),
  handleValidationErrors,
  async (req, res) => {
    const { username, password } = req.body;
    const ip = getClientIp(req);
    const attemptKey = `${ip}:${username.toLowerCase()}`;
    
    try {
      // Verificar bloqueio por tentativas excessivas
      const attempts = loginAttempts.get(attemptKey);
      if (attempts && attempts.count >= MAX_LOGIN_ATTEMPTS) {
        const timeLeft = Math.ceil((LOCKOUT_TIME - (Date.now() - attempts.firstAttempt)) / 1000 / 60);
        if (timeLeft > 0) {
          await logAction(0, username, 'LOGIN_BLOCKED', `Bloqueado por tentativas excessivas. IP: ${ip}`, 'user', username, ip);
          return res.status(429).json({ 
            error: `Conta temporariamente bloqueada. Tente novamente em ${timeLeft} minutos.` 
          });
        } else {
          loginAttempts.delete(attemptKey);
        }
      }
      
      const [users] = await pool.query(
        'SELECT * FROM panel_users WHERE username = ? AND active = TRUE',
        [username]
      );
      
      if (users.length === 0) {
        // Registrar tentativa falha
        const current = loginAttempts.get(attemptKey) || { count: 0, firstAttempt: Date.now() };
        current.count++;
        loginAttempts.set(attemptKey, current);
        
        await logAction(0, username, 'LOGIN_FAILED', `Usuário não encontrado. IP: ${ip}. Tentativa ${current.count}/${MAX_LOGIN_ATTEMPTS}`, 'user', username, ip);
        
        // Resposta genérica para não revelar existência do usuário
        return res.status(401).json({ error: 'Credenciais inválidas' });
      }
      
      const user = users[0];
      const validPassword = await bcrypt.compare(password, user.password);
      
      if (!validPassword) {
        // Registrar tentativa falha
        const current = loginAttempts.get(attemptKey) || { count: 0, firstAttempt: Date.now() };
        current.count++;
        loginAttempts.set(attemptKey, current);
        
        await logAction(0, username, 'LOGIN_FAILED', `Senha incorreta. IP: ${ip}. Tentativa ${current.count}/${MAX_LOGIN_ATTEMPTS}`, 'user', username, ip);
        
        if (current.count >= MAX_LOGIN_ATTEMPTS) {
          return res.status(429).json({ 
            error: `Conta bloqueada por 15 minutos devido a tentativas excessivas.` 
          });
        }
        
        return res.status(401).json({ error: 'Credenciais inválidas' });
      }
      
      // Login bem-sucedido - limpar tentativas
      loginAttempts.delete(attemptKey);
      
      // Atualizar último login
      await pool.query('UPDATE panel_users SET last_login = NOW() WHERE id = ?', [user.id]);
      
      const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        JWT_SECRET,
        { 
          expiresIn: '24h',
          algorithm: 'HS256',
        }
      );
      
      await logAction(user.id, user.username, 'LOGIN_SUCCESS', `Login bem-sucedido. IP: ${ip}`, 'user', user.id.toString(), ip);
      
      return res.json({ 
        token, 
        user: { id: user.id, username: user.username, role: user.role } 
      });
    } catch (error) {
      console.error('Erro no login:', error.message);
      return res.status(500).json({ error: 'Erro interno do servidor' });
    }
  }
);

app.get('/api/auth/verify', authMiddleware, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// ==================== ROTAS DE ESTATÍSTICAS ====================

app.get('/api/stats', authMiddleware, async (req, res) => {
  try {
    // Verificar cache primeiro (cache de 30 segundos)
    const cachedStats = cacheGet('stats');
    if (cachedStats) {
      return res.json(cachedStats);
    }

    // Total de jogadores
    const [totalPlayers] = await pool.query('SELECT COUNT(*) as total FROM vrp_users WHERE deleted = 0');
    
    // Total de dinheiro no banco
    const [totalBank] = await pool.query('SELECT SUM(bank) as total FROM vrp_users WHERE deleted = 0');
    
    // Total de veículos
    const [totalVehicles] = await pool.query('SELECT COUNT(*) as total FROM vrp_vehicles');
    
    // Total de dinheiro no cassino (com proteção contra erro)
    let totalCasino = 0;
    try {
      const [casinoResult] = await pool.query('SELECT SUM(balance) as total FROM smartphone_casino');
      totalCasino = casinoResult[0].total || 0;
    } catch (e) {
      console.error('Erro ao buscar total do cassino:', e.message);
    }
    
    // Jogadores mais ricos (banco + cassino)
    const [richestPlayers] = await pool.query(`
      SELECT u.id, u.name, u.name2, u.bank, COALESCE(sc.balance, 0) as casino,
             (u.bank + COALESCE(sc.balance, 0)) as total_wealth
      FROM vrp_users u
      LEFT JOIN smartphone_casino sc ON sc.user_id = u.id
      WHERE u.deleted = 0 
      ORDER BY total_wealth DESC 
      LIMIT 5
    `);
    
    // Últimos jogadores registrados
    const [recentPlayers] = await pool.query(`
      SELECT id, name, name2, phone, bank, age
      FROM vrp_users 
      WHERE deleted = 0
      ORDER BY id DESC 
      LIMIT 5
    `);
    
    // Veículos mais comuns
    const [vehicleStats] = await pool.query(`
      SELECT vehicle, COUNT(*) as count 
      FROM vrp_vehicles 
      GROUP BY vehicle 
      ORDER BY count DESC 
      LIMIT 10
    `);
    
    // Total de banidos
    const [totalBans] = await pool.query('SELECT COUNT(*) as total FROM characters_bans');
    
    const statsData = {
      totalPlayers: totalPlayers[0].total,
      totalBank: totalBank[0].total || 0,
      totalVehicles: totalVehicles[0].total,
      totalCasino,
      totalBans: totalBans[0].total,
      richestPlayers,
      recentPlayers,
      vehicleStats
    };

    // Salvar no cache
    cacheSet('stats', statsData);

    res.json(statsData);
  } catch (error) {
    console.error('Erro ao buscar estatísticas:', error);
    res.status(500).json({ error: 'Erro ao buscar estatísticas' });
  }
});

// ==================== ROTAS DE JOGADORES ====================

app.get('/api/players', authMiddleware, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const search = req.query.search || '';
    const sortBy = req.query.sortBy || 'id';
    const sortOrder = req.query.sortOrder || 'asc';
    const offset = (page - 1) * limit;
    
    // Campos permitidos para ordenação
    const allowedSortFields = ['id', 'name', 'bank', 'casino_balance', 'phone'];
    const validSortBy = allowedSortFields.includes(sortBy) ? sortBy : 'id';
    const validSortOrder = sortOrder.toLowerCase() === 'asc' ? 'ASC' : 'DESC';

    const sortCol = validSortBy === 'casino_balance' ? 'sc.balance' : `u.${validSortBy}`;

    let query = 'SELECT u.*, sc.balance as casino_balance FROM vrp_users u LEFT JOIN smartphone_casino sc ON sc.user_id = u.id WHERE u.deleted = 0';
    let countQuery = 'SELECT COUNT(*) as total FROM vrp_users u LEFT JOIN smartphone_casino sc ON sc.user_id = u.id WHERE u.deleted = 0';
    let params = [];

    if (search) {
      const searchCondition = ' AND (u.id LIKE ? OR u.name LIKE ? OR u.name2 LIKE ? OR u.phone LIKE ? OR u.steam LIKE ?)';
      query += searchCondition;
      countQuery += searchCondition;
      params = [`%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`, `%${search}%`];
    }

    query += ` ORDER BY ${sortCol} ${validSortOrder} LIMIT ? OFFSET ?`;
    
    const [players] = await pool.query(query, [...params, limit, offset]);
    const [total] = await pool.query(countQuery, params);
    
    res.json({
      players,
      pagination: {
        page,
        limit,
        total: total[0].total,
        totalPages: Math.ceil(total[0].total / limit)
      }
    });
  } catch (error) {
    console.error('Erro ao listar jogadores:', error);
    res.status(500).json({ error: 'Erro ao listar jogadores' });
  }
});

app.get('/api/players/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Executar todas as queries em paralelo para carregamento mais rápido
    const [
      [players],
      [vehiclesData],
      [userData],
      [banStatus],
      [casinoRows],
      [permRows],
      [tempRows],
      [homes],
      [tempVehicleRows]
    ] = await Promise.all([
      pool.query('SELECT * FROM vrp_users WHERE id = ?', [id]),
      pool.query('SELECT * FROM vrp_vehicles WHERE user_id = ?', [id]),
      pool.query('SELECT dkey, dvalue FROM vrp_user_data WHERE user_id = ?', [id]),
      pool.query('SELECT * FROM characters_bans WHERE user_id = ?', [id]),
      pool.query('SELECT * FROM smartphone_casino WHERE user_id = ?', [id]),
      pool.query('SELECT permiss FROM vrp_permissions WHERE user_id = ?', [id]),
      pool.query('SELECT grupo, data_expiracao FROM grupos_temporarios WHERE user_id = ?', [id]),
      pool.query('SELECT * FROM vrp_homes WHERE user_id = ?', [id]),
      pool.query('SELECT vehicle_id, data_expiracao FROM veiculos_temporarios WHERE user_id = ?', [id])
    ]);
    
    if (players.length === 0) {
      return res.status(404).json({ error: 'Jogador não encontrado' });
    }
    
    // Processar dados do usuário
    const dataObj = {};
    userData.forEach(item => {
      try {
        dataObj[item.dkey] = JSON.parse(item.dvalue);
      } catch {
        dataObj[item.dkey] = item.dvalue;
      }
    });
    
    // Buscar baús de casas e veículos em paralelo
    const housePromises = homes.map(async (home) => {
      const vaultKey = `homesVault:${home.home}`;
      const [vaultRows] = await pool.query('SELECT dvalue FROM vrp_srv_data WHERE dkey = ?', [vaultKey]);
      const vaultData = safeJsonParse(vaultRows[0]?.dvalue, {});
      return {
        ...home,
        stashItems: normalizeNamedInventory(vaultData)
      };
    });

    const vehiclePromises = vehiclesData.map(async (vehicle) => {
      const trunkKey = `chest:${id}:${(vehicle.vehicle || '').toLowerCase()}`;
      const [trunkRows] = await pool.query('SELECT dvalue FROM vrp_srv_data WHERE dkey = ?', [trunkKey]);
      const trunkData = safeJsonParse(trunkRows[0]?.dvalue, {});
      const tempVehicle = tempVehicleRows.find(tv => tv.vehicle_id === vehicle.id);
      return {
        ...vehicle,
        trunkItems: normalizeNamedInventory(trunkData),
        data_expiracao: tempVehicle ? tempVehicle.data_expiracao : null
      };
    });

    const [houses, vehicles] = await Promise.all([
      Promise.all(housePromises),
      Promise.all(vehiclePromises)
    ]);
    
    // Extrair inventário do Datatable
    let inventory = [];
    if (dataObj.Datatable && dataObj.Datatable.inventorys) {
      const inv = dataObj.Datatable.inventorys;
      inventory = Object.entries(inv).map(([slot, data]) => ({
        slot: parseInt(slot),
        item: data.item,
        amount: data.amount
      })).sort((a, b) => a.slot - b.slot);
    }
    
    // Extrair status do jogador
    const playerStatus = dataObj.Datatable ? {
      health: dataObj.Datatable.health || 0,
      hunger: dataObj.Datatable.hunger || 0,
      thirst: dataObj.Datatable.thirst || 0,
      stress: dataObj.Datatable.stress || 0,
      armour: dataObj.Datatable.armour || 0
    } : null;
    
    const casino = casinoRows[0] || null;
    const permissions = permRows.map(r => r.permiss);
    const tempGroups = tempRows.map(r => ({ grupo: r.grupo, data_expiracao: r.data_expiracao }));

    res.json({
      player: players[0],
      vehicles,
      houses,
      casino,
      permissions,
      tempGroups,
      userData: dataObj,
      inventory,
      playerStatus,
      isBanned: banStatus.length > 0,
      banInfo: banStatus[0] || null
    });
  } catch (error) {
    console.error('Erro ao buscar jogador:', error);
    res.status(500).json({ error: 'Erro ao buscar jogador' });
  }
});

app.put('/api/players/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const updates = req.body;
    
    const allowedFields = ['name', 'name2', 'phone', 'bank', 'garage', 'prison', 'age', 'paypal', 'coins'];
    const updateFields = [];
    const updateValues = [];
    
    for (const field of allowedFields) {
      if (updates[field] !== undefined) {
        updateFields.push(`${field} = ?`);
        updateValues.push(updates[field]);
      }
    }
    
    if (updateFields.length === 0) {
      return res.status(400).json({ error: 'Nenhum campo válido para atualizar' });
    }
    
    updateValues.push(id);
    
    const query = `UPDATE vrp_users SET ${updateFields.join(', ')} WHERE id = ?`;
    await pool.query(query, updateValues);
    
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    await logAction(req.user.id, req.user.username, 'UPDATE_PLAYER', `Atualizou jogador ID ${id}: ${updateFields.join(', ')}`, 'player', id, ip);
    
    res.json({ success: true, message: 'Jogador atualizado com sucesso' });
  } catch (error) {
    console.error('Erro ao atualizar jogador:', error);
    res.status(500).json({ error: 'Erro ao atualizar jogador' });
  }
});

app.post('/api/players/:id/money', 
  authMiddleware, 
  actionLimiter,
  param('id').isInt({ min: 1 }).withMessage('ID de jogador inválido'),
  body('action').isIn(['add', 'remove', 'set']).withMessage('Ação inválida'),
  body('amount').isInt({ min: 0, max: 999999999999 }).withMessage('Valor inválido'),
  handleValidationErrors,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { action, amount } = req.body;
      const parsedAmount = parseInt(amount);
      
      const [players] = await pool.query('SELECT bank FROM vrp_users WHERE id = ?', [id]);
      
      if (players.length === 0) {
        return res.status(404).json({ error: 'Jogador não encontrado' });
      }
      
      let newBank = players[0].bank;
      
      if (action === 'add') {
        newBank = Math.min(newBank + parsedAmount, 999999999999);
      } else if (action === 'remove') {
        newBank = Math.max(0, newBank - parsedAmount);
      } else if (action === 'set') {
        newBank = Math.min(parsedAmount, 999999999999);
      }
      
      await pool.query('UPDATE vrp_users SET bank = ? WHERE id = ?', [newBank, id]);
      
      const ip = getClientIp(req);
      const actionLabel = action === 'add' ? 'Adicionou' : action === 'remove' ? 'Removeu' : 'Definiu';
      await logAction(req.user.id, req.user.username, 'MODIFY_MONEY', `${actionLabel} R$${parsedAmount} para jogador ID ${id}. Novo saldo: R$${newBank}`, 'player', id, ip);
      
      res.json({ success: true, bank: newBank });
    } catch (error) {
      console.error('Erro ao modificar dinheiro:', error.message);
      res.status(500).json({ error: 'Erro ao modificar dinheiro' });
    }
  }
);

app.post('/api/players/:id/casino', 
  authMiddleware, 
  actionLimiter,
  param('id').isInt({ min: 1 }).withMessage('ID de jogador inválido'),
  body('action').isIn(['add', 'remove', 'set']).withMessage('Ação inválida'),
  body('amount').isInt({ min: 0, max: 999999999999 }).withMessage('Valor inválido'),
  handleValidationErrors,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { action, amount } = req.body;
      const parsedAmount = parseInt(amount);

      const [rows] = await pool.query('SELECT balance FROM smartphone_casino WHERE user_id = ?', [id]);
      if (rows.length === 0) {
        return res.status(404).json({ error: 'Jogador não possui registro de casino' });
      }

      let newBalance = rows[0].balance;
      if (action === 'add') {
        newBalance = Math.min(newBalance + parsedAmount, 999999999999);
      } else if (action === 'remove') {
        newBalance = Math.max(0, newBalance - parsedAmount);
      } else if (action === 'set') {
        newBalance = Math.min(parsedAmount, 999999999999);
      }

      await pool.query('UPDATE smartphone_casino SET balance = ? WHERE user_id = ?', [newBalance, id]);

      const ip = getClientIp(req);
      const actionLabel = action === 'add' ? 'Adicionou' : action === 'remove' ? 'Removeu' : 'Definiu';
      await logAction(req.user.id, req.user.username, 'MODIFY_CASINO', `${actionLabel} $${parsedAmount} de casino para jogador ID ${id}. Novo saldo: $${newBalance}`, 'player', id, ip);

      res.json({ success: true, balance: newBalance });
    } catch (error) {
      console.error('Erro ao modificar casino:', error.message);
      res.status(500).json({ error: 'Erro ao modificar casino' });
    }
  }
);

// ==================== ROTAS DE INVENTÁRIO ====================

app.post('/api/players/:id/inventory', 
  authMiddleware, 
  actionLimiter,
  param('id').isInt({ min: 1 }).withMessage('ID de jogador inválido'),
  body('item').isString().isLength({ min: 1, max: 100 }).trim().withMessage('Item inválido'),
  body('amount').isInt({ min: 1, max: 999999 }).withMessage('Quantidade inválida'),
  handleValidationErrors,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { item, amount } = req.body;

      // Buscar Datatable atual
      const [userData] = await pool.query(
        'SELECT dvalue FROM vrp_user_data WHERE user_id = ? AND dkey = ?',
        [id, 'Datatable']
      );

      let datatable = {};
      if (userData.length > 0) {
        try {
          datatable = JSON.parse(userData[0].dvalue);
        } catch {}
      }

      // Inicializar inventário se não existir
      if (!datatable.inventorys) {
        datatable.inventorys = {};
      }

      // Encontrar próximo slot livre ou slot existente do mesmo item
      let targetSlot = null;
      let existingAmount = 0;

      // Verificar se já existe o item
      for (const [slot, data] of Object.entries(datatable.inventorys)) {
        if (data.item && data.item.toLowerCase() === item.toLowerCase()) {
          targetSlot = slot;
          existingAmount = data.amount || 0;
          break;
        }
      }

      // Se não encontrou, procurar slot livre
      if (!targetSlot) {
        for (let i = 1; i <= 100; i++) {
          if (!datatable.inventorys[i.toString()]) {
            targetSlot = i.toString();
            break;
          }
        }
      }

      if (!targetSlot) {
        return res.status(400).json({ error: 'Inventário cheio' });
      }

      // Adicionar item
      datatable.inventorys[targetSlot] = {
        item: item.toUpperCase(),
        amount: existingAmount + parseInt(amount)
      };

      // Atualizar no banco
      if (userData.length > 0) {
        await pool.query(
          'UPDATE vrp_user_data SET dvalue = ? WHERE user_id = ? AND dkey = ?',
          [JSON.stringify(datatable), id, 'Datatable']
        );
      } else {
        await pool.query(
          'INSERT INTO vrp_user_data (user_id, dkey, dvalue) VALUES (?, ?, ?)',
          [id, 'Datatable', JSON.stringify(datatable)]
        );
      }

      const ip = getClientIp(req);
      await logAction(req.user.id, req.user.username, 'ADD_ITEM', `Adicionou ${amount}x ${item.toUpperCase()} para jogador ID ${id}`, 'player', id, ip);

      res.json({ success: true, message: 'Item adicionado com sucesso' });
    } catch (error) {
      console.error('Erro ao adicionar item:', error.message);
      res.status(500).json({ error: 'Erro ao adicionar item' });
    }
  }
);

app.delete('/api/players/:id/inventory/:slot', authMiddleware, async (req, res) => {
  try {
    const { id, slot } = req.params;
    const { amount } = req.query;

    // Buscar Datatable atual
    const [userData] = await pool.query(
      'SELECT dvalue FROM vrp_user_data WHERE user_id = ? AND dkey = ?',
      [id, 'Datatable']
    );

    if (userData.length === 0) {
      return res.status(404).json({ error: 'Dados não encontrados' });
    }

    let datatable = {};
    try {
      datatable = JSON.parse(userData[0].dvalue);
    } catch {
      return res.status(400).json({ error: 'Erro ao processar dados' });
    }

    if (!datatable.inventorys || !datatable.inventorys[slot]) {
      return res.status(404).json({ error: 'Item não encontrado' });
    }

    const currentAmount = datatable.inventorys[slot].amount || 0;
    const itemName = datatable.inventorys[slot].item;
    const removeAmount = amount ? parseInt(amount) : currentAmount;

    if (removeAmount >= currentAmount) {
      // Remover item completamente
      delete datatable.inventorys[slot];
    } else {
      // Reduzir quantidade
      datatable.inventorys[slot].amount = currentAmount - removeAmount;
    }

    // Atualizar no banco
    await pool.query(
      'UPDATE vrp_user_data SET dvalue = ? WHERE user_id = ? AND dkey = ?',
      [JSON.stringify(datatable), id, 'Datatable']
    );

    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    await logAction(req.user.id, req.user.username, 'REMOVE_ITEM', `Removeu ${removeAmount}x ${itemName} do jogador ID ${id}`, 'player', id, ip);

    res.json({ success: true, message: 'Item removido com sucesso' });
  } catch (error) {
    console.error('Erro ao remover item:', error);
    res.status(500).json({ error: 'Erro ao remover item' });
  }
});

// ==================== ROTAS DE PERMISSÕES (GRUPOS vRP) ====================

app.post('/api/players/:id/groups', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { group, dias } = req.body;
    if (!group || !group.trim()) return res.status(400).json({ error: 'Nome da permissão é obrigatória' });

    const permiss = group.trim();
    const [existing] = await pool.query('SELECT 1 FROM vrp_permissions WHERE user_id = ? AND permiss = ?', [id, permiss]);
    if (existing.length > 0) return res.status(400).json({ error: 'Permissão já existe' });

    await pool.query('INSERT INTO vrp_permissions (user_id, permiss) VALUES (?, ?)', [id, permiss]);

    if (dias && parseInt(dias) > 0) {
      const dataExpiracao = new Date(Date.now() + parseInt(dias) * 24 * 60 * 60 * 1000 - 3 * 60 * 60 * 1000);
      const dataStr = dataExpiracao.toISOString().slice(0, 19).replace('T', ' ');
      await pool.query('DELETE FROM grupos_temporarios WHERE user_id = ? AND grupo = ?', [id, permiss]);
      await pool.query('INSERT INTO grupos_temporarios (user_id, grupo, data_expiracao) VALUES (?, ?, ?)', [id, permiss, dataStr]);
    }

    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const logMsg = dias && parseInt(dias) > 0
      ? `Adicionou permissão temporária "${permiss}" (${dias} dias) ao jogador ID ${id}`
      : `Adicionou permissão "${permiss}" ao jogador ID ${id}`;
    await logAction(req.user.id, req.user.username, 'ADD_GROUP', logMsg, 'player', id, ip);
    res.json({ success: true });
  } catch (error) {
    console.error('Erro ao adicionar permissão:', error);
    res.status(500).json({ error: 'Erro ao adicionar permissão' });
  }
});

app.delete('/api/players/:id/groups/:group', authMiddleware, async (req, res) => {
  try {
    const { id, group } = req.params;
    await pool.query('DELETE FROM vrp_permissions WHERE user_id = ? AND permiss = ?', [id, group]);
    await pool.query('DELETE FROM grupos_temporarios WHERE user_id = ? AND grupo = ?', [id, group]);

    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    await logAction(req.user.id, req.user.username, 'REMOVE_GROUP', `Removeu permissão "${group}" do jogador ID ${id}`, 'player', id, ip);
    res.json({ success: true });
  } catch (error) {
    console.error('Erro ao remover permissão:', error);
    res.status(500).json({ error: 'Erro ao remover permissão' });
  }
});

// ==================== ROTAS DE VEÍCULOS (DETALHE JOGADOR) ====================

app.post('/api/players/:id/vehicles', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { vehicle, plate, dias } = req.body;

    if (!vehicle) {
      return res.status(400).json({ error: 'Modelo do veículo é obrigatório' });
    }

    const finalPlate = (plate || generatePlate()).toUpperCase();

    const [result] = await pool.query(
      `
        INSERT INTO vrp_vehicles
        (user_id, vehicle, plate, arrest, isFavorite, time, premiumtime, rentaltime, engine, body, fuel, work, doors, windows, tyres, alugado, data_alugado, ipva, estado)
        VALUES (?, ?, ?, 0, 0, 0, 0, 0, 1000, 1000, 100, 'false', '', '', '', 0, NULL, '', '[]')
      `,
      [id, vehicle, finalPlate]
    );

    if (dias && parseInt(dias) > 0) {
      const dataExpiracao = new Date(Date.now() + parseInt(dias) * 24 * 60 * 60 * 1000 - 3 * 60 * 60 * 1000);
      const dataStr = dataExpiracao.toISOString().slice(0, 19).replace('T', ' ');
      await pool.query('INSERT INTO veiculos_temporarios (user_id, vehicle_id, data_expiracao) VALUES (?, ?, ?)', [id, result.insertId, dataStr]);
    }

    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const logMsg = dias && parseInt(dias) > 0
      ? `Adicionou veículo temporário ${vehicle} (${finalPlate}) por ${dias} dias para jogador ID ${id}`
      : `Adicionou veículo ${vehicle} (${finalPlate}) para jogador ID ${id}`;
    await logAction(req.user.id, req.user.username, 'ADD_VEHICLE', logMsg, 'vehicle', result.insertId.toString(), ip);

    res.json({ success: true, message: 'Veículo adicionado com sucesso', id: result.insertId });
  } catch (error) {
    console.error('Erro ao adicionar veículo:', error);
    res.status(500).json({ error: 'Erro ao adicionar veículo' });
  }
});

app.delete('/api/players/:id/vehicles/:vehicleId', authMiddleware, async (req, res) => {
  try {
    const { id, vehicleId } = req.params;

    const [vehicle] = await pool.query('SELECT * FROM vrp_vehicles WHERE id = ? AND user_id = ?', [vehicleId, id]);
    if (vehicle.length === 0) {
      return res.status(404).json({ error: 'Veículo não encontrado para este jogador' });
    }

    await pool.query('DELETE FROM vrp_vehicles WHERE id = ?', [vehicleId]);
    await pool.query('DELETE FROM veiculos_temporarios WHERE vehicle_id = ?', [vehicleId]);

    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    await logAction(req.user.id, req.user.username, 'DELETE_VEHICLE', `Removeu veículo ${vehicle[0].vehicle} (${vehicle[0].plate}) do jogador ID ${id}`, 'vehicle', vehicleId, ip);

    res.json({ success: true, message: 'Veículo removido com sucesso' });
  } catch (error) {
    console.error('Erro ao remover veículo do jogador:', error);
    res.status(500).json({ error: 'Erro ao remover veículo' });
  }
});

app.post('/api/players/:id/vehicles/:vehicleId/trunk', authMiddleware, async (req, res) => {
  try {
    const { id, vehicleId } = req.params;
    const { item, amount } = req.body;

    if (!item || !amount || parseInt(amount) <= 0) {
      return res.status(400).json({ error: 'Item e quantidade são obrigatórios' });
    }

    const [vehicles] = await pool.query('SELECT * FROM vrp_vehicles WHERE id = ? AND user_id = ?', [vehicleId, id]);
    if (vehicles.length === 0) {
      return res.status(404).json({ error: 'Veículo não encontrado para este jogador' });
    }

    const trunkKey = `chest:${id}:${(vehicles[0].vehicle || '').toLowerCase()}`;
    const [trunkRows] = await pool.query('SELECT dvalue FROM vrp_srv_data WHERE dkey = ?', [trunkKey]);
    const trunkData = safeJsonParse(trunkRows[0]?.dvalue, {});

    const itemName = item.trim();
    trunkData[itemName] = { amount: (parseInt(trunkData[itemName]?.amount) || 0) + parseInt(amount) };

    await pool.query(
      'INSERT INTO vrp_srv_data (dkey, dvalue) VALUES (?, ?) ON DUPLICATE KEY UPDATE dvalue = VALUES(dvalue)',
      [trunkKey, JSON.stringify(trunkData)]
    );

    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    await logAction(req.user.id, req.user.username, 'ADD_VEHICLE_TRUNK_ITEM', `Adicionou ${amount}x ${itemName} no baú do veículo ${vehicles[0].vehicle} (${vehicles[0].plate})`, 'player', id, ip);

    res.json({ success: true, message: 'Item adicionado no baú com sucesso' });
  } catch (error) {
    console.error('Erro ao adicionar item no baú:', error);
    res.status(500).json({ error: 'Erro ao adicionar item no baú' });
  }
});

app.delete('/api/players/:id/vehicles/:vehicleId/trunk/:slot', authMiddleware, async (req, res) => {
  try {
    const { id, vehicleId, slot } = req.params;
    const { amount } = req.query;

    const [vehicles] = await pool.query('SELECT * FROM vrp_vehicles WHERE id = ? AND user_id = ?', [vehicleId, id]);
    if (vehicles.length === 0) {
      return res.status(404).json({ error: 'Veículo não encontrado para este jogador' });
    }

    const trunkKey = `chest:${id}:${(vehicles[0].vehicle || '').toLowerCase()}`;
    const [trunkRows] = await pool.query('SELECT dvalue FROM vrp_srv_data WHERE dkey = ?', [trunkKey]);
    const trunkData = safeJsonParse(trunkRows[0]?.dvalue, {});

    // slot = nome do item (formato named inventory)
    const itemName = slot;
    if (!trunkData[itemName]) {
      return res.status(404).json({ error: 'Item não encontrado no baú' });
    }

    const currentAmount = parseInt(trunkData[itemName].amount || 0);
    const removeAmount = amount ? parseInt(amount) : currentAmount;

    if (removeAmount >= currentAmount) {
      delete trunkData[itemName];
    } else {
      trunkData[itemName].amount = currentAmount - removeAmount;
    }

    await pool.query(
      'INSERT INTO vrp_srv_data (dkey, dvalue) VALUES (?, ?) ON DUPLICATE KEY UPDATE dvalue = VALUES(dvalue)',
      [trunkKey, JSON.stringify(trunkData)]
    );

    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    await logAction(req.user.id, req.user.username, 'REMOVE_VEHICLE_TRUNK_ITEM', `Removeu ${removeAmount}x ${itemName} do baú do veículo ${vehicles[0].vehicle} (${vehicles[0].plate})`, 'player', id, ip);

    res.json({ success: true, message: 'Item removido do baú com sucesso' });
  } catch (error) {
    console.error('Erro ao remover item do baú:', error);
    res.status(500).json({ error: 'Erro ao remover item do baú' });
  }
});

// ==================== HELPER: VAULT SIZE POR NOME DA CASA ====================
function getVaultByHomeName(houseName) {
  const n = houseName.toLowerCase();
  // Casos exatos
  if (n === 'hoteleclipse') return 10;
  // Mansão
  if (n.startsWith('mansao')) return 2500;
  // Motel / Hotel (quartos de motel)
  if (n.startsWith('motel_') || n.startsWith('hotel_')) return 120;
  // Trailer
  if (n.startsWith('trailer')) return 250;
  // Beach
  if (n.startsWith('beach')) return 200;
  // MiddlePremium
  if (n.startsWith('middlepremium')) return 250;
  // MiddleGold: 339+ = 250, restantes = 100
  if (n.startsWith('middlegold')) {
    const num = parseInt(n.replace('middlegold', '')) || 0;
    return num >= 339 ? 250 : 100;
  }
  // Middle genérico (Middle072+)
  if (n.startsWith('middle')) return 150;
  // Casas numeradas especiais (ex: "284345")
  if (/^\d+$/.test(n)) return 250;
  return 0;
}

// ==================== ROTAS DE CASAS (DETALHE JOGADOR) ====================

app.post('/api/players/:id/houses', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { home } = req.body;

    if (!home || !home.trim()) {
      return res.status(400).json({ error: 'Nome da casa é obrigatório' });
    }

    const houseName = home.trim();

    // Verificar se jogador existe
    const [players] = await pool.query('SELECT id FROM vrp_users WHERE id = ?', [id]);
    if (players.length === 0) {
      return res.status(404).json({ error: 'Jogador não encontrado' });
    }

    // Verificar se jogador já possui esta casa
    const [existing] = await pool.query('SELECT id FROM vrp_homes WHERE user_id = ? AND home = ?', [id, houseName]);
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Jogador já possui esta casa' });
    }

    const vault = getVaultByHomeName(houseName);

    const [result] = await pool.query(
      'INSERT INTO vrp_homes (home, user_id, owner, vault) VALUES (?, ?, ?, ?)',
      [houseName, id, 1, vault]
    );

    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    await logAction(req.user.id, req.user.username, 'ADD_HOUSE', `Adicionou casa "${houseName}" para jogador ID ${id}`, 'house', result.insertId.toString(), ip);

    res.json({ success: true, message: 'Casa adicionada com sucesso', id: result.insertId });
  } catch (error) {
    console.error('Erro ao adicionar casa:', error);
    res.status(500).json({ error: 'Erro ao adicionar casa' });
  }
});

app.delete('/api/players/:id/houses/:homeId', authMiddleware, async (req, res) => {
  try {
    const { id, homeId } = req.params;

    const [homes] = await pool.query('SELECT * FROM vrp_homes WHERE id = ? AND user_id = ?', [homeId, id]);
    if (homes.length === 0) {
      return res.status(404).json({ error: 'Casa não encontrada para este jogador' });
    }

    const houseName = homes[0].home;

    await pool.query('DELETE FROM vrp_homes WHERE id = ?', [homeId]);

    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    await logAction(req.user.id, req.user.username, 'DELETE_HOUSE', `Removeu casa "${houseName}" do jogador ID ${id}`, 'house', homeId, ip);

    res.json({ success: true, message: 'Casa removida com sucesso' });
  } catch (error) {
    console.error('Erro ao remover casa:', error);
    res.status(500).json({ error: 'Erro ao remover casa' });
  }
});

app.post('/api/players/:id/houses/:homeId/stash', authMiddleware, async (req, res) => {
  try {
    const { id, homeId } = req.params;
    const { item, amount } = req.body;

    if (!item || !amount || parseInt(amount) <= 0) {
      return res.status(400).json({ error: 'Item e quantidade são obrigatórios' });
    }

    const [homes] = await pool.query('SELECT * FROM vrp_homes WHERE id = ? AND user_id = ?', [homeId, id]);
    if (homes.length === 0) {
      return res.status(404).json({ error: 'Casa não encontrada para este jogador' });
    }

    const houseName = homes[0].home;
    const vaultKey = `homesVault:${houseName}`;

    const [vaultRows] = await pool.query('SELECT dvalue FROM vrp_srv_data WHERE dkey = ?', [vaultKey]);
    const vaultData = safeJsonParse(vaultRows[0]?.dvalue, {});

    const itemName = item.trim();
    vaultData[itemName] = { amount: (parseInt(vaultData[itemName]?.amount) || 0) + parseInt(amount) };

    await pool.query(
      'INSERT INTO vrp_srv_data (dkey, dvalue) VALUES (?, ?) ON DUPLICATE KEY UPDATE dvalue = VALUES(dvalue)',
      [vaultKey, JSON.stringify(vaultData)]
    );

    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    await logAction(req.user.id, req.user.username, 'ADD_HOUSE_STASH_ITEM', `Adicionou ${amount}x ${itemName} no baú da casa ${houseName}`, 'house', homeId, ip);

    res.json({ success: true, message: 'Item adicionado no baú da casa com sucesso' });
  } catch (error) {
    console.error('Erro ao adicionar item na casa:', error);
    res.status(500).json({ error: 'Erro ao adicionar item na casa' });
  }
});

app.delete('/api/players/:id/houses/:homeId/stash/:slot', authMiddleware, async (req, res) => {
  try {
    const { id, homeId, slot } = req.params;
    const { amount } = req.query;

    const [homes] = await pool.query('SELECT * FROM vrp_homes WHERE id = ? AND user_id = ?', [homeId, id]);
    if (homes.length === 0) {
      return res.status(404).json({ error: 'Casa não encontrada para este jogador' });
    }

    const houseName = homes[0].home;
    const vaultKey = `homesVault:${houseName}`;

    const [vaultRows] = await pool.query('SELECT dvalue FROM vrp_srv_data WHERE dkey = ?', [vaultKey]);
    const vaultData = safeJsonParse(vaultRows[0]?.dvalue, {});

    // slot = nome do item (formato named inventory)
    const itemName = slot;
    if (!vaultData[itemName]) {
      return res.status(404).json({ error: 'Item não encontrado no baú da casa' });
    }

    const currentAmount = parseInt(vaultData[itemName].amount || 0);
    const removeAmount = amount ? parseInt(amount) : currentAmount;

    if (removeAmount >= currentAmount) {
      delete vaultData[itemName];
    } else {
      vaultData[itemName].amount = currentAmount - removeAmount;
    }

    await pool.query(
      'INSERT INTO vrp_srv_data (dkey, dvalue) VALUES (?, ?) ON DUPLICATE KEY UPDATE dvalue = VALUES(dvalue)',
      [vaultKey, JSON.stringify(vaultData)]
    );

    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    await logAction(req.user.id, req.user.username, 'REMOVE_HOUSE_STASH_ITEM', `Removeu ${removeAmount}x ${itemName} do baú da casa ${houseName}`, 'house', homeId, ip);

    res.json({ success: true, message: 'Item removido do baú da casa com sucesso' });
  } catch (error) {
    console.error('Erro ao remover item da casa:', error);
    res.status(500).json({ error: 'Erro ao remover item da casa' });
  }
});

// ==================== ROTAS DE CASAS (GLOBAL) ====================

app.get('/api/houses', authMiddleware, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const search = req.query.search || '';
    const offset = (page - 1) * limit;

    let query = `
      SELECT h.*, u.name, u.name2
      FROM vrp_homes h
      LEFT JOIN vrp_users u ON h.user_id = u.id
    `;
    let countQuery = 'SELECT COUNT(*) as total FROM vrp_homes';
    let params = [];

    if (search) {
      query += ' WHERE h.home LIKE ? OR u.name LIKE ? OR u.name2 LIKE ?';
      countQuery += ' LEFT JOIN vrp_users u ON vrp_homes.user_id = u.id WHERE vrp_homes.home LIKE ? OR u.name LIKE ? OR u.name2 LIKE ?';
      params = [`%${search}%`, `%${search}%`, `%${search}%`];
    }

    query += ' ORDER BY h.id DESC LIMIT ? OFFSET ?';

    const [houses] = await pool.query(query, [...params, limit, offset]);
    const [total] = await pool.query(countQuery, params);

    // Buscar contagem de itens no baú de cada casa
    if (houses.length > 0) {
      const vaultKeys = houses.map(h => `homesVault:${h.home}`);
      const placeholders = vaultKeys.map(() => '?').join(',');
      const [vaultRows] = await pool.query(
        `SELECT dkey, dvalue FROM vrp_srv_data WHERE dkey IN (${placeholders})`,
        vaultKeys
      );
      const vaultMap = {};
      for (const row of vaultRows) {
        const data = safeJsonParse(row.dvalue, {});
        vaultMap[row.dkey] = Object.values(data).filter(v => (parseInt(v?.amount ?? v) || 0) > 0).length;
      }
      for (const house of houses) {
        house.stashCount = vaultMap[`homesVault:${house.home}`] || 0;
      }
    }

    res.json({
      houses,
      pagination: {
        page,
        limit,
        total: total[0].total,
        totalPages: Math.ceil(total[0].total / limit)
      }
    });
  } catch (error) {
    console.error('Erro ao listar casas:', error);
    res.status(500).json({ error: 'Erro ao listar casas' });
  }
});

app.delete('/api/houses/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const [house] = await pool.query('SELECT home, user_id FROM vrp_homes WHERE id = ?', [id]);
    if (house.length === 0) return res.status(404).json({ error: 'Casa não encontrada' });

    await pool.query('DELETE FROM vrp_homes WHERE id = ?', [id]);

    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    await logAction(req.user.id, req.user.username, 'DELETE_HOUSE_GLOBAL', `Removeu casa "${house[0].home}" do jogador ID ${house[0].user_id}`, 'house', id, ip);

    res.json({ success: true, message: 'Casa removida com sucesso' });
  } catch (error) {
    console.error('Erro ao remover casa:', error);
    res.status(500).json({ error: 'Erro ao remover casa' });
  }
});

app.get('/api/houses/:id/stash', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const [houses] = await pool.query('SELECT * FROM vrp_homes WHERE id = ?', [id]);
    if (houses.length === 0) return res.status(404).json({ error: 'Casa não encontrada' });

    const house = houses[0];
    const vaultKey = `homesVault:${house.home}`;
    const [vaultRows] = await pool.query('SELECT dvalue FROM vrp_srv_data WHERE dkey = ?', [vaultKey]);
    const vaultData = safeJsonParse(vaultRows[0]?.dvalue, {});

    const stashItems = Object.entries(vaultData)
      .map(([itemName, data]) => ({
        slot: itemName,
        item: itemName,
        amount: parseInt(data?.amount ?? data ?? 0)
      }))
      .filter(i => i.amount > 0);

    res.json({ house: { ...house, stashItems } });
  } catch (error) {
    console.error('Erro ao buscar baú:', error);
    res.status(500).json({ error: 'Erro ao buscar baú da casa' });
  }
});

// ==================== ROTAS DE VEÍCULOS ====================

app.get('/api/vehicles', authMiddleware, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const search = req.query.search || '';
    const userId = req.query.userId || '';
    const offset = (page - 1) * limit;
    
    let query = `
      SELECT v.*, u.name, u.name2 
      FROM vrp_vehicles v 
      LEFT JOIN vrp_users u ON v.user_id = u.id
    `;
    let countQuery = 'SELECT COUNT(*) as total FROM vrp_vehicles v';
    let params = [];
    let conditions = [];
    
    if (search) {
      conditions.push('(v.plate LIKE ? OR v.vehicle LIKE ?)');
      params.push(`%${search}%`, `%${search}%`);
    }
    if (userId) {
      conditions.push('v.user_id = ?');
      params.push(userId);
    }
    if (conditions.length > 0) {
      const where = ' WHERE ' + conditions.join(' AND ');
      query += where;
      countQuery += where;
    }
    
    query += ' ORDER BY v.id DESC LIMIT ? OFFSET ?';
    
    const [vehicles] = await pool.query(query, [...params, limit, offset]);
    const [total] = await pool.query(countQuery, params);

    // Buscar itens do baú de cada veículo via vrp_srv_data
    if (vehicles.length > 0) {
      const dkeys = vehicles.map(v => `chest:${v.user_id}:${v.vehicle.toLowerCase()}`);
      const [trunkRows] = await pool.query(
        `SELECT dkey, dvalue FROM vrp_srv_data WHERE dkey IN (?)`,
        [dkeys]
      );
      const trunkMap = {};
      trunkRows.forEach(row => {
        try { trunkMap[row.dkey] = normalizeNamedInventory(JSON.parse(row.dvalue)); }
        catch { trunkMap[row.dkey] = []; }
      });
      vehicles.forEach(v => {
        v.trunkItems = trunkMap[`chest:${v.user_id}:${v.vehicle.toLowerCase()}`] || [];
      });
    }

    res.json({
      vehicles,
      pagination: {
        page,
        limit,
        total: total[0].total,
        totalPages: Math.ceil(total[0].total / limit)
      }
    });
  } catch (error) {
    console.error('Erro ao listar veículos:', error);
    res.status(500).json({ error: 'Erro ao listar veículos' });
  }
});

app.delete('/api/vehicles/:id', authMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Buscar info do veiculo antes de deletar
    const [vehicle] = await pool.query('SELECT vehicle, plate, user_id FROM vrp_vehicles WHERE id = ?', [id]);
    
    await pool.query('DELETE FROM vrp_vehicles WHERE id = ?', [id]);
    
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    if (vehicle.length > 0) {
      await logAction(req.user.id, req.user.username, 'DELETE_VEHICLE', `Removeu veículo ${vehicle[0].vehicle} (${vehicle[0].plate}) do jogador ID ${vehicle[0].user_id}`, 'vehicle', id, ip);
    }
    
    res.json({ success: true, message: 'Veículo removido com sucesso' });
  } catch (error) {
    console.error('Erro ao remover veículo:', error);
    res.status(500).json({ error: 'Erro ao remover veículo' });
  }
});

// ==================== ROTAS DE BANIMENTOS ====================

app.get('/api/bans', authMiddleware, async (req, res) => {
  try {
    const [bans] = await pool.query(`
      SELECT b.*, u.id as numeric_id, u.name, u.name2
      FROM characters_bans b
      LEFT JOIN vrp_users u ON b.user_id = u.steam
      ORDER BY b.rowid DESC
    `);
    res.json({ bans });
  } catch (error) {
    // fallback sem rowid
    try {
      const [bans] = await pool.query(`
        SELECT b.*, u.id as numeric_id, u.name, u.name2
        FROM characters_bans b
        LEFT JOIN vrp_users u ON b.user_id = u.steam
      `);
      res.json({ bans });
    } catch (e) {
      console.error('Erro ao listar banimentos:', e);
      res.json({ bans: [] });
    }
  }
});

app.post('/api/bans', authMiddleware, async (req, res) => {
  try {
    const { user_id, motivo, desbanimento } = req.body;

    // Buscar steam hex do jogador (igual ao Lua: user_id em characters_bans é o steam)
    const [players] = await pool.query('SELECT id, steam FROM vrp_users WHERE id = ?', [user_id]);
    if (players.length === 0 || !players[0].steam) {
      return res.status(404).json({ error: 'Jogador não encontrado ou sem Steam registrado' });
    }
    const steamId = players[0].steam;

    // Formato idêntico ao Lua: os.date("%d/%m/%Y as %H:%M")
    const now = new Date();
    const pad = (n) => String(n).padStart(2, '0');
    const banimento = `${pad(now.getDate())}/${pad(now.getMonth()+1)}/${now.getFullYear()} as ${pad(now.getHours())}:${pad(now.getMinutes())}`;

    await pool.query(
      'INSERT IGNORE INTO characters_bans (user_id, motivo, desbanimento, banimento, time, hwid) VALUES (?, ?, ?, ?, ?, ?)',
      [steamId, motivo, desbanimento || 'Nunca', banimento, 0, 1]
    );

    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    await logAction(req.user.id, req.user.username, 'BAN_PLAYER', `Baniu jogador | ID: ${user_id} | Steam: ${steamId} | Motivo: ${motivo}`, 'player', user_id.toString(), ip);
    
    res.json({ success: true, message: 'Jogador banido com sucesso' });
  } catch (error) {
    console.error('Erro ao banir jogador:', error);
    res.status(500).json({ error: 'Erro ao banir jogador' });
  }
});

app.delete('/api/bans/:user_id', authMiddleware, async (req, res) => {
  try {
    const { user_id } = req.params;
    // user_id pode ser steam hex ou ID numérico
    let steamId = user_id;
    let numericId = null;
    if (/^\d+$/.test(user_id)) {
      numericId = user_id;
      const [players] = await pool.query('SELECT id, steam FROM vrp_users WHERE id = ?', [user_id]);
      if (players.length > 0 && players[0].steam) steamId = players[0].steam;
    } else {
      // recebeu steam hex, busca ID numérico
      const [players] = await pool.query('SELECT id FROM vrp_users WHERE steam = ?', [user_id]);
      if (players.length > 0) numericId = players[0].id;
    }
    await pool.query('DELETE FROM characters_bans WHERE user_id = ?', [steamId]);
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    const logTarget = numericId ? numericId.toString() : steamId;
    const logDetails = numericId
      ? `Desbaniu jogador | ID: ${numericId} | Steam: ${steamId}`
      : `Desbaniu jogador | Steam: ${steamId}`;
    await logAction(req.user.id, req.user.username, 'UNBAN_PLAYER', logDetails, 'player', logTarget, ip);
    res.json({ success: true, message: 'Banimento removido com sucesso' });
  } catch (error) {
    console.error('Erro ao remover banimento:', error);
    res.status(500).json({ error: 'Erro ao remover banimento' });
  }
});

// ==================== ROTAS DE WHITELIST ====================

app.get('/api/whitelist', authMiddleware, async (req, res) => {
  try {
    const [whitelist] = await pool.query('SELECT * FROM whitelist ORDER BY id DESC');
    res.json({ whitelist });
  } catch (error) {
    res.json({ whitelist: [] });
  }
});

// ==================== ROTAS DE LOGS ====================

app.get('/api/logs', authMiddleware, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const [logs] = await pool.query('SELECT * FROM logs ORDER BY id DESC LIMIT ?', [limit]);
    res.json({ logs });
  } catch (error) {
    res.json({ logs: [] });
  }
});

// ==================== ROTAS DE USUÁRIOS DO PAINEL (APENAS DONO) ====================

// Listar usuários do painel
app.get('/api/panel-users', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const [users] = await pool.query(`
      SELECT id, username, role, created_at, last_login, active,
        (SELECT username FROM panel_users p2 WHERE p2.id = panel_users.created_by) as created_by_name
      FROM panel_users 
      ORDER BY created_at DESC
    `);
    res.json({ users });
  } catch (error) {
    console.error('Erro ao listar usuários:', error);
    res.status(500).json({ error: 'Erro ao listar usuários' });
  }
});

// Criar usuário do painel
app.post('/api/panel-users', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const { username, password, role } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username e senha são obrigatórios' });
    }
    
    // Verificar se já existe
    const [existing] = await pool.query('SELECT id FROM panel_users WHERE username = ?', [username]);
    if (existing.length > 0) {
      return res.status(400).json({ error: 'Usuário já existe' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const validRole = ['dono', 'admin'].includes(role) ? role : 'admin';
    
    const [result] = await pool.query(
      'INSERT INTO panel_users (username, password, role, created_by) VALUES (?, ?, ?, ?)',
      [username, hashedPassword, validRole, req.user.id]
    );
    
    await logAction(req.user.id, req.user.username, 'CREATE_USER', `Criou usuário: ${username} (${validRole})`, 'panel_user', result.insertId.toString(), ip);
    
    res.json({ success: true, message: 'Usuário criado com sucesso', id: result.insertId });
  } catch (error) {
    console.error('Erro ao criar usuário:', error);
    res.status(500).json({ error: 'Erro ao criar usuário' });
  }
});

// Atualizar usuário do painel
app.put('/api/panel-users/:id', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const { password, role, active } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    const updates = [];
    const values = [];
    const changes = [];
    
    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      updates.push('password = ?');
      values.push(hashedPassword);
      changes.push('senha alterada');
    }
    
    if (role !== undefined) {
      const validRole = ['dono', 'admin'].includes(role) ? role : 'admin';
      updates.push('role = ?');
      values.push(validRole);
      changes.push(`role: ${validRole}`);
    }
    
    if (active !== undefined) {
      updates.push('active = ?');
      values.push(active);
      changes.push(active ? 'ativado' : 'desativado');
    }
    
    if (updates.length === 0) {
      return res.status(400).json({ error: 'Nenhum campo para atualizar' });
    }
    
    values.push(id);
    await pool.query(`UPDATE panel_users SET ${updates.join(', ')} WHERE id = ?`, values);
    
    await logAction(req.user.id, req.user.username, 'UPDATE_USER', `Atualizou usuário ID ${id}: ${changes.join(', ')}`, 'panel_user', id, ip);
    
    res.json({ success: true, message: 'Usuário atualizado com sucesso' });
  } catch (error) {
    console.error('Erro ao atualizar usuário:', error);
    res.status(500).json({ error: 'Erro ao atualizar usuário' });
  }
});

// Deletar usuário do painel
app.delete('/api/panel-users/:id', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const { id } = req.params;
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    // Não permitir deletar a si mesmo
    if (parseInt(id) === req.user.id) {
      return res.status(400).json({ error: 'Não é possível deletar seu próprio usuário' });
    }
    
    const [user] = await pool.query('SELECT username FROM panel_users WHERE id = ?', [id]);
    if (user.length === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }
    
    await pool.query('DELETE FROM panel_users WHERE id = ?', [id]);
    
    await logAction(req.user.id, req.user.username, 'DELETE_USER', `Deletou usuário: ${user[0].username}`, 'panel_user', id, ip);
    
    res.json({ success: true, message: 'Usuário removido com sucesso' });
  } catch (error) {
    console.error('Erro ao deletar usuário:', error);
    res.status(500).json({ error: 'Erro ao deletar usuário' });
  }
});

// ==================== ROTAS DE LOGS DO PAINEL (APENAS DONO) ====================

app.get('/api/panel-logs', authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;
    const search = req.query.search || '';
    const action = req.query.action || '';
    
    let query = 'SELECT * FROM panel_logs WHERE 1=1';
    let countQuery = 'SELECT COUNT(*) as total FROM panel_logs WHERE 1=1';
    const params = [];
    
    if (search) {
      query += ' AND (username LIKE ? OR details LIKE ? OR target_id LIKE ?)';
      countQuery += ' AND (username LIKE ? OR details LIKE ? OR target_id LIKE ?)';
      params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }
    
    if (action) {
      query += ' AND action = ?';
      countQuery += ' AND action = ?';
      params.push(action);
    }
    
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    
    const [logs] = await pool.query(query, [...params, limit, offset]);
    const [total] = await pool.query(countQuery, params);
    
    // Listar tipos de ações para filtro
    const [actions] = await pool.query('SELECT DISTINCT action FROM panel_logs ORDER BY action');
    
    res.json({
      logs,
      actions: actions.map(a => a.action),
      pagination: {
        page,
        limit,
        total: total[0].total,
        totalPages: Math.ceil(total[0].total / limit)
      }
    });
  } catch (error) {
    console.error('Erro ao listar logs:', error);
    res.status(500).json({ error: 'Erro ao listar logs' });
  }
});

// ==================== ROTAS DE BAÚS (vrp_chests) ====================

// Listar todos os baús com stashCount
app.get('/api/chests', authMiddleware, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 30;
    const offset = (page - 1) * limit;
    const search = req.query.search || '';

    let where = 'WHERE 1=1';
    const params = [];
    if (search) {
      where += ' AND (name LIKE ? OR permiss LIKE ?)';
      params.push(`%${search}%`, `%${search}%`);
    }

    const [chests] = await pool.query(
      `SELECT * FROM vrp_chests ${where} ORDER BY id ASC LIMIT ? OFFSET ?`,
      [...params, limit, offset]
    );
    const [[{ total }]] = await pool.query(
      `SELECT COUNT(*) as total FROM vrp_chests ${where}`,
      params
    );

    // Buscar stashCount de cada baú em vrp_srv_data
    if (chests.length > 0) {
      const keys = chests.map(c => `chest:${c.name}`);
      const [srvRows] = await pool.query(
        `SELECT dkey, dvalue FROM vrp_srv_data WHERE dkey IN (?)`,
        [keys]
      );
      const srvMap = {};
      for (const row of srvRows) {
        try {
          const inv = JSON.parse(row.dvalue);
          srvMap[row.dkey] = Object.keys(inv).length;
        } catch { srvMap[row.dkey] = 0; }
      }
      for (const c of chests) {
        c.stashCount = srvMap[`chest:${c.name}`] || 0;
      }
    }

    res.json({ chests, pagination: { page, limit, total, totalPages: Math.ceil(total / limit) } });
  } catch (error) {
    console.error('Erro ao listar baús:', error);
    res.status(500).json({ error: 'Erro ao listar baús' });
  }
});

// Obter stash de um baú específico
app.get('/api/chests/:id/stash', authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM vrp_chests WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Baú não encontrado' });
    const chest = rows[0];

    const dkey = `chest:${chest.name}`;
    const [srvRows] = await pool.query('SELECT dvalue FROM vrp_srv_data WHERE dkey = ?', [dkey]);
    let stashItems = [];
    if (srvRows.length > 0 && srvRows[0].dvalue) {
      try {
        const inv = JSON.parse(srvRows[0].dvalue);
        stashItems = Object.entries(inv).map(([slot, data]) => ({
          slot,
          item: slot,
          amount: typeof data === 'object' ? (data.amount || 0) : data
        }));
      } catch {}
    }
    res.json({ chest: { ...chest, stashItems } });
  } catch (error) {
    console.error('Erro ao buscar stash do baú:', error);
    res.status(500).json({ error: 'Erro ao buscar stash' });
  }
});

// Adicionar item ao baú
app.post('/api/chests/:id/stash', authMiddleware, async (req, res) => {
  try {
    const { item, amount } = req.body;
    if (!item || !amount || amount <= 0) return res.status(400).json({ error: 'Item e quantidade são obrigatórios' });

    const [rows] = await pool.query('SELECT * FROM vrp_chests WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Baú não encontrado' });
    const chest = rows[0];
    const dkey = `chest:${chest.name}`;

    const [srvRows] = await pool.query('SELECT dvalue FROM vrp_srv_data WHERE dkey = ?', [dkey]);
    let inv = {};
    if (srvRows.length > 0 && srvRows[0].dvalue) {
      try { inv = JSON.parse(srvRows[0].dvalue); } catch {}
    }
    if (inv[item]) {
      inv[item].amount = (inv[item].amount || 0) + parseInt(amount);
    } else {
      inv[item] = { amount: parseInt(amount) };
    }
    await pool.query(
      'INSERT INTO vrp_srv_data (dkey, dvalue) VALUES (?, ?) ON DUPLICATE KEY UPDATE dvalue = VALUES(dvalue)',
      [dkey, JSON.stringify(inv)]
    );

    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    await logAction(req.user.id, req.user.username, 'EDIT_CHEST', `Adicionou ${amount}x ${item} no baú ${chest.name}`, 'chest', chest.id.toString(), ip);
    res.json({ success: true });
  } catch (error) {
    console.error('Erro ao adicionar item ao baú:', error);
    res.status(500).json({ error: 'Erro ao adicionar item' });
  }
});

// Remover item do baú
app.delete('/api/chests/:id/stash/:slot', authMiddleware, async (req, res) => {
  try {
    const { slot } = req.params;
    const amount = req.query.amount ? parseInt(req.query.amount) : null;

    const [rows] = await pool.query('SELECT * FROM vrp_chests WHERE id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Baú não encontrado' });
    const chest = rows[0];
    const dkey = `chest:${chest.name}`;

    const [srvRows] = await pool.query('SELECT dvalue FROM vrp_srv_data WHERE dkey = ?', [dkey]);
    if (srvRows.length === 0) return res.status(404).json({ error: 'Baú vazio' });

    let inv = {};
    try { inv = JSON.parse(srvRows[0].dvalue); } catch {}
    if (!inv[slot]) return res.status(404).json({ error: 'Item não encontrado' });

    if (amount && amount < (inv[slot].amount || 0)) {
      inv[slot].amount -= amount;
    } else {
      delete inv[slot];
    }
    await pool.query(
      'INSERT INTO vrp_srv_data (dkey, dvalue) VALUES (?, ?) ON DUPLICATE KEY UPDATE dvalue = VALUES(dvalue)',
      [dkey, JSON.stringify(inv)]
    );

    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    await logAction(req.user.id, req.user.username, 'EDIT_CHEST', `Removeu item "${slot}" do baú ${chest.name}`, 'chest', chest.id.toString(), ip);
    res.json({ success: true });
  } catch (error) {
    console.error('Erro ao remover item do baú:', error);
    res.status(500).json({ error: 'Erro ao remover item' });
  }
});

// ==================== INICIAR SERVIDOR ====================

// Handler de erros global (404)
app.use((req, res) => {
  res.status(404).json({ error: 'Rota não encontrada' });
});

// Handler de erros global (500)
app.use((err, req, res, next) => {
  console.error('Erro não tratado:', err.message);
  
  // Não expor detalhes do erro em produção
  if (process.env.NODE_ENV === 'production') {
    return res.status(500).json({ error: 'Erro interno do servidor' });
  }
  
  return res.status(500).json({ 
    error: 'Erro interno do servidor',
    details: err.message 
  });
});

// Tratamento de sinais de encerramento
const gracefulShutdown = async (signal) => {
  console.log(`\n${signal} recebido. Encerrando graciosamente...`);
  try {
    await pool.end();
    console.log('✅ Conexões com banco encerradas');
    process.exit(0);
  } catch (err) {
    console.error('Erro ao encerrar:', err);
    process.exit(1);
  }
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Tratamento de erros não capturados
process.on('uncaughtException', (err) => {
  console.error('❌ Exceção não capturada:', err);
  gracefulShutdown('uncaughtException');
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Promise não tratada:', reason);
});

// Criar tabela de veículos temporários se não existir
pool.query(`CREATE TABLE IF NOT EXISTS veiculos_temporarios (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  vehicle_id INT NOT NULL,
  data_expiracao DATETIME NOT NULL,
  INDEX idx_user_id (user_id),
  INDEX idx_vehicle_id (vehicle_id)
)`).catch(err => console.error('Erro ao criar tabela veiculos_temporarios:', err));

// Job: remover veículos temporários vencidos a cada 10 minutos
async function removerVeiculosVencidos() {
  try {
    const [vencidos] = await pool.query(
      'SELECT vehicle_id FROM veiculos_temporarios WHERE data_expiracao <= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 3 HOUR)'
    );
    if (vencidos.length > 0) {
      for (const row of vencidos) {
        await pool.query('DELETE FROM vrp_vehicles WHERE id = ?', [row.vehicle_id]);
        await pool.query('DELETE FROM veiculos_temporarios WHERE vehicle_id = ?', [row.vehicle_id]);
      }
      console.log(`[Veículos Temporários] ${vencidos.length} veículo(s) removido(s) por vencimento.`);
    }
  } catch (err) {
    console.error('[Veículos Temporários] Erro ao remover vencidos:', err);
  }
}
removerVeiculosVencidos();
setInterval(removerVeiculosVencidos, 10 * 60 * 1000);

// Job: remover cargos temporários vencidos a cada 10 minutos
async function removerCargosVencidos() {
  try {
    const [[{ utcNow }]] = await pool.query('SELECT DATE_SUB(UTC_TIMESTAMP(), INTERVAL 3 HOUR) as utcNow');
    const [vencidos] = await pool.query(
      'SELECT user_id, grupo, data_expiracao FROM grupos_temporarios WHERE data_expiracao <= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 3 HOUR)'
    );
    console.log(`[Cargos Temporários] BRT agora: ${utcNow} | Vencidos encontrados: ${vencidos.length}`);
    if (vencidos.length > 0) {
      for (const row of vencidos) {
        console.log(`[Cargos Temporários] Removendo user_id=${row.user_id} grupo="${row.grupo}" expirado em ${row.data_expiracao}`);
        const [r1] = await pool.query('DELETE FROM vrp_permissions WHERE user_id = ? AND permiss = ?', [row.user_id, row.grupo]);
        const [r2] = await pool.query('DELETE FROM grupos_temporarios WHERE user_id = ? AND grupo = ?', [row.user_id, row.grupo]);
        console.log(`[Cargos Temporários] vrp_permissions deletados: ${r1.affectedRows} | grupos_temporarios deletados: ${r2.affectedRows}`);
      }
      console.log(`[Cargos Temporários] ${vencidos.length} cargo(s) removido(s) por vencimento.`);
    }
  } catch (err) {
    console.error('[Cargos Temporários] Erro ao remover vencidos:', err);
  }
}
removerCargosVencidos();
setInterval(removerCargosVencidos, 10 * 60 * 1000);

app.listen(PORT, () => {
  console.log(`\n🚀 Servidor rodando na porta ${PORT}`);
  console.log(`📊 API disponível em http://localhost:${PORT}/api`);
  console.log(`💾 Conectado ao banco: ${process.env.DB_NAME || 'high'}`);
  console.log(`🔒 Modo: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🛡️  Rate limiting: ${process.env.NODE_ENV === 'production' ? 'Ativado' : 'Ativado (dev)'}`);
  console.log('');
});
