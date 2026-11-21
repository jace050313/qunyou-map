export function createSupabaseStore(projectUrl, secretKey) {
  const columns = 'id,name,emoji,avatar_url,lat,lng,created_at,expires_at,owner_hash';

  async function query(path, method = 'GET', params = {}, body) {
    const url = new URL('/rest/v1/' + path, projectUrl);
    url.search = new URLSearchParams(params);
    const headers = { apikey: secretKey };
    if (!secretKey.startsWith('sb_secret_')) {
      headers.Authorization = 'Bearer ' + secretKey;
    }
    if (body) headers['Content-Type'] = 'application/json';
    if (method !== 'GET') headers.Prefer = 'return=representation';

    const result = await fetch(url, {
      method, headers, body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(10_000)
    });
    if (!result.ok) throw new Error('Supabase HTTP ' + result.status);
    return result.json();
  }

  function condition(id, ownerHash) {
    const params = { id: 'eq.' + id, select: columns };
    if (ownerHash) params.owner_hash = 'eq.' + ownerHash;
    return params;
  }

  return {
    list({ all, ownerHash, timestamp, after, limit }) {
      const params = { select: columns, order: 'id.asc', limit: String(limit) };
      if (after) params.id = 'gt.' + after;
      if (!all) {
        const filters = ['expires_at.is.null', 'expires_at.gt.' + timestamp];
        if (ownerHash) filters.push('owner_hash.eq.' + ownerHash);
        params.or = '(' + filters.join(',') + ')';
      }
      return query('qunyou_markers', 'GET', params);
    },
    async insert(record) {
      const rows = await query('qunyou_markers', 'POST', { select: columns }, record);
      return rows[0];
    },
    async update(id, ownerHash, fields) {
      const rows = await query('qunyou_markers', 'PATCH', condition(id, ownerHash), fields);
      return rows[0];
    },
    async remove(id, ownerHash) {
      const rows = await query('qunyou_markers', 'DELETE', condition(id, ownerHash));
      return rows[0];
    },
    recordAttempt(key, bucket) {
      return query('rpc/qunyou_admin_attempt', 'POST', {}, { attempt_key: key, attempt_bucket: bucket });
    }
  };
}
