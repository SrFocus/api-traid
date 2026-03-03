require('dotenv').config();
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');

async function setup() {
  const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || '',
  });

  try {
    // Criar tabela de usuários do painel
    await pool.query(`
      CREATE TABLE IF NOT EXISTS panel_users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role ENUM('dono', 'admin') NOT NULL DEFAULT 'admin',
        created_by INT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP NULL,
        active BOOLEAN DEFAULT TRUE
      )
    `);
    console.log('✅ Tabela panel_users criada');

    // Criar tabela de logs de ações
    await pool.query(`
      CREATE TABLE IF NOT EXISTS panel_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        username VARCHAR(50) NOT NULL,
        action VARCHAR(100) NOT NULL,
        details TEXT,
        target_type VARCHAR(50),
        target_id VARCHAR(50),
        ip_address VARCHAR(45),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_user_id (user_id),
        INDEX idx_action (action),
        INDEX idx_created_at (created_at)
      )
    `);
    console.log('✅ Tabela panel_logs criada');

    // Verificar se já existe um usuário dono
    const [users] = await pool.query('SELECT * FROM panel_users WHERE role = "dono"');
    
    if (users.length === 0) {
      // Usar credenciais do .env ou padrão seguro
      const adminUser = process.env.ADMIN_USER || 'admin';
      const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
      
      // Criar usuário dono padrão
      const hashedPassword = await bcrypt.hash(adminPassword, 12);
      await pool.query(
        'INSERT INTO panel_users (username, password, role) VALUES (?, ?, ?)',
        [adminUser, hashedPassword, 'dono']
      );
      console.log(`✅ Usuário dono criado: ${adminUser}`);
      console.log('⚠️  IMPORTANTE: Altere a senha após o primeiro login!');
    } else {
      console.log('ℹ️  Já existe um usuário dono:', users[0].username);
    }

    console.log('\n🎉 Setup concluído com sucesso!');
    process.exit(0);
  } catch (error) {
    console.error('❌ Erro:', error.message);
    process.exit(1);
  }
}

setup();

