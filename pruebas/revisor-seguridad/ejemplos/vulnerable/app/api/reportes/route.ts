import { db } from '@/lib/db';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const mes = searchParams.get('mes');
  const { rows } = await db.query(`SELECT * FROM ventas WHERE mes = '${mes}'`);
  return Response.json(rows);
}
