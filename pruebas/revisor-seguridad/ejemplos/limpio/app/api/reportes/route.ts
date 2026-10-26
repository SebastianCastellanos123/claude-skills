import { db } from '@/lib/db';
import { crearClienteServidor } from '@/lib/supabase-servidor';

export async function GET(request: Request) {
  const supabase = crearClienteServidor();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response('No autorizado', { status: 401 });

  const { searchParams } = new URL(request.url);
  const mes = searchParams.get('mes');
  const { rows } = await db.query('SELECT * FROM ventas WHERE mes = $1 AND tienda_id = $2', [mes, user.id]);
  return Response.json(rows);
}
