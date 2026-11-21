import { createMapFunction } from './handler.mjs';

const projectUrl = Deno.env.get('SUPABASE_URL');
const secretKeys = JSON.parse(Deno.env.get('SUPABASE_SECRET_KEYS') ?? '{}');
const secretKey = secretKeys.default || Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');

Deno.serve(createMapFunction({
  projectUrl,
  secretKey,
  password: Deno.env.get('MAP_ADMIN_PASSWORD'),
  sessionSecret: Deno.env.get('MAP_ADMIN_SESSION_SECRET')
}));
