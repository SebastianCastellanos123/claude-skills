import { createClient } from '@supabase/supabase-js';

// La anon key es pública por diseño: lo que protege los datos son las políticas RLS.
export const supabase = createClient(
  'https://abcdefghijklmnop.supabase.co',
  '@@ANON_JWT@@'
);
