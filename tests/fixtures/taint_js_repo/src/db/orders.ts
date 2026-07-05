import { Pool } from "pg";

const pool = new Pool();

export async function fetchOrder(orderId: string) {
  const client = await pool.connect();
  return client.query(`SELECT * FROM orders WHERE id = '${orderId}'`);
}
