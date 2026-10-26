create table public.perfiles (
  id uuid primary key references auth.users,
  nombre text
);
alter table public.perfiles enable row level security;
create policy "cada quien ve su perfil" on public.perfiles
  for select using (auth.uid() = id);

create table public.pedidos (
  id bigint generated always as identity primary key,
  usuario_id uuid references auth.users,
  total numeric,
  direccion text
);
alter table public.pedidos enable row level security;
create policy "cada quien ve sus pedidos" on public.pedidos
  for select using (auth.uid() = usuario_id);
create policy "cada quien crea sus pedidos" on public.pedidos
  for insert with check (auth.uid() = usuario_id);
