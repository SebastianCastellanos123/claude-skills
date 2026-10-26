# Proyecto de ejemplo LIMPIO

La misma tienda del ejemplo vulnerable, pero hecha bien. La skill no debe
reportar ningún hallazgo aquí. Incluye a propósito cosas que parecen
peligrosas y no lo son, para probar que no hay falsos positivos:

- un `.env` con una clave real que SÍ está en `.gitignore`;
- la `anon key` de Supabase escrita en el código (es pública por diseño);
- la `apiKey` de Firebase en la configuración web (también pública);
- consultas SQL con parámetros, incluido un `LIKE` con f-string en el valor.
