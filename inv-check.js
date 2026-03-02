const mysql = require('mysql2/promise');
require('dotenv').config();
(async () => {
  const pool = await mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
  });

  // All chest keys
  const [chests] = await pool.query("SELECT dkey, dvalue FROM vrp_srv_data WHERE dkey LIKE 'chest%'");
  console.log('=== chest keys ===');
  chests.forEach(r => console.log('dkey:', JSON.stringify(r.dkey), '| dvalue:', r.dvalue));

  // Vehicles for user_id 1
  const [vehs] = await pool.query("SELECT id, user_id, vehicle, plate FROM vrp_vehicles WHERE user_id = 1 LIMIT 10");
  console.log('\n=== vehicles user 1 ===');
  vehs.forEach(r => {
    const expectedLower = `chest:1:${r.plate.toLowerCase()}`;
    const expectedUpper = `chest:1:${r.plate.toUpperCase()}`;
    const expectedExact = `chest:1:${r.plate}`;
    console.log(`id:${r.id} | vehicle:${r.vehicle} | plate:${JSON.stringify(r.plate)}`);
    console.log(`  expected lower: ${expectedLower}`);
    console.log(`  expected exact: ${expectedExact}`);
    const match = chests.find(c => c.dkey === expectedLower || c.dkey === expectedUpper || c.dkey === expectedExact);
    console.log(`  MATCH: ${match ? match.dkey + ' => ' + match.dvalue : 'NONE'}`);
  });

  await pool.end();
})();
