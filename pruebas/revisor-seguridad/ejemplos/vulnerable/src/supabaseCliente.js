import { createClient } from '@supabase/supabase-js';

// Se usa desde los componentes de React (navegador).
export const supabase = createClient(
  'https://abcdefghijklmnop.supabase.co',
  '@@SERVICE_ROLE_JWT@@'
);
