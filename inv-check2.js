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

  const [chests] = await pool.query("SELECT dkey, dvalue FROM vrp_srv_data WHERE dkey LIKE 'chest%'");
  const [vehs] = await pool.query("SELECT id, user_id, vehicle, plate FROM vrp_vehicles WHERE user_id = 1 LIMIT 10");

  console.log('=== Testing vehicle model as key ===');
  vehs.forEach(r => {
    const byModel = `chest:${r.user_id}:${r.vehicle.toLowerCase()}`;
    const match = chests.find(c => c.dkey === byModel);
    if (match) {
      console.log(`MATCH! vehicle:${r.vehicle} | dkey:${match.dkey} | dvalue:${match.dvalue}`);
    } else {
      console.log(`No match for vehicle:${r.vehicle} (tried: ${byModel})`);
    }
  });

  await pool.end();
})();
