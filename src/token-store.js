// Access-token record storage contract plus an in-memory reference store.
//
// A TokenRecord is:
//   {
//     tokenId: string,          // public identifier; safe to log
//     tokenDigest: Uint8Array,  // SHA-256 of the secret; the secret is NEVER stored
//     ownerId: string,          // account that owns the grant
//     clientId: string,         // device/client the grant is bound to
//     serviceId: string,        // relying service the grant is bound to
//     scopes: string[],         // e.g. ['codes:read']
//     createdAt: number,        // epoch milliseconds
//     notBefore: number,        // epoch milliseconds
//     expiresAt: number,        // epoch milliseconds
//     revokedAt: number | null, // epoch milliseconds once revoked
//   }
//
// The store interface is async so a Cloudflare D1/KV implementation can drop
// in later without changing the verifier:
//   getByTokenId(tokenId) -> Promise<TokenRecord | undefined>
//   insert(record)        -> Promise<void>  // must fail on a duplicate tokenId
//   save(record)          -> Promise<void>  // must fail on an unknown tokenId
//
// A store must never persist or log the raw token or secret, and must not hand
// out internal references that callers could mutate. This reference store
// copies records on the way in and out.

export class MemoryTokenStore {
  #records = new Map();

  async getByTokenId(tokenId) {
    const record = this.#records.get(tokenId);
    return record ? structuredClone(record) : undefined;
  }

  async insert(record) {
    if (this.#records.has(record.tokenId)) throw new Error(`Duplicate tokenId: ${record.tokenId}`);
    this.#records.set(record.tokenId, structuredClone(record));
  }

  async save(record) {
    if (!this.#records.has(record.tokenId)) throw new Error(`Unknown tokenId: ${record.tokenId}`);
    this.#records.set(record.tokenId, structuredClone(record));
  }

  // Test and development aid only; not part of the storage contract.
  get size() {
    return this.#records.size;
  }
}
