-- Perfiles públicos de la tienda
create table public.perfiles (
  id uuid primary key references auth.users,
  nombre text
);
alter table public.perfiles enable row level security;
create policy "perfiles visibles" on public.perfiles for select using (true);

-- Pedidos de los clientes (con dirección y total)
create table public.pedidos (
  id bigint generated always as identity primary key,
  usuario_id uuid references auth.users,
  total numeric,
  direccion text
);
