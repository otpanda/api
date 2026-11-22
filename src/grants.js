// Pure authorization policy only. This does NOT authenticate a token.
// The caller must first verify a stored token digest and derive this record server-side.
export function permitsCodeRead(grant, request, now) {
  if (!Number.isSafeInteger(now) || now < 0) return false;
  if (!grant || !request || !grant.ownerId || !grant.clientId || !grant.serviceId) return false;
  if (grant.revokedAt !== null || !Number.isSafeInteger(grant.expiresAt) || grant.expiresAt <= now) return false;
  if (!Number.isSafeInteger(grant.notBefore) || grant.notBefore > now) return false;
  if (grant.ownerId !== request.ownerId || grant.clientId !== request.clientId || grant.serviceId !== request.serviceId) return false;
  return Array.isArray(grant.scopes) && grant.scopes.includes('codes:read');
}
