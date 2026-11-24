import {SESSION_METHOD_JOIN as MJ,SESSION_METHOD_ACTIVE as MA} from './session-method.js';
const MAX_BYTES = 131072;
function identifier(v) { if(typeof v!=='string'||!v.trim()||v.length>256||/[\x00-\x1f\x7f]/.test(v))throw new TypeError('Invalid organization identifier'); return v; }
function exact(v,keys) { if(!v||typeof v!=='object'||Array.isArray(v)||Object.keys(v).length!==keys.length||keys.some(k=>!Object.hasOwn(v,k)))throw new TypeError('Invalid organization document'); }
function validate(document) {
 exact(document,['tags','entries']);
 if(!Array.isArray(document.tags)||document.tags.length>100||!Array.isArray(document.entries)||document.entries.length>1000)throw new TypeError('Invalid organization size');
 const ids=new Set(),labels=new Set();
 const tags=document.tags.map(t=>{
  exact(t,['id','label']);identifier(t.id);
  if(typeof t.label!=='string'||t.label!==t.label.trim().replace(/\s+/g,' ')||!t.label||[...t.label].length>80||/[\x00-\x1f\x7f]/.test(t.label)||ids.has(t.id)||labels.has(t.label.toLowerCase()))throw new TypeError('Invalid personal tag');
  ids.add(t.id);labels.add(t.label.toLowerCase());return {id:t.id,label:t.label};
 });
 const entriesSeen=new Set();
 const entries=document.entries.map(e=>{
  exact(e,['entryId','pinned','tagIds']);identifier(e.entryId);
  if(entriesSeen.has(e.entryId)||typeof e.pinned!=='boolean'||!Array.isArray(e.tagIds)||e.tagIds.length>100||new Set(e.tagIds).size!==e.tagIds.length||e.tagIds.some(id=>!ids.has(id)))throw new TypeError('Invalid entry preferences');
  entriesSeen.add(e.entryId);return {entryId:e.entryId,pinned:e.pinned,tagIds:[...e.tagIds]};
 });
 const value={tags,entries};if(new TextEncoder().encode(JSON.stringify(value)).byteLength>MAX_BYTES)throw new TypeError('Organization document too large');return value;
}
const ACCESS = `EXISTS (SELECT 1 FROM entries e WHERE e.entry_id=p.value->>'$.entryId' AND (e.owner_id=?1 OR EXISTS(SELECT 1 FROM entry_shares s WHERE s.entry_id=e.entry_id AND s.recipient_id=?1 AND s.revoked_at IS NULL)))`;
function guardJson(guard,viewerId) {
 if(guard===undefined)return null; // Trusted internal calls only; HTTP always supplies a guard.
 if(!guard||guard.ownerId!==viewerId||typeof guard.deviceId!=='string'||!Number.isSafeInteger(guard.generation)||!Number.isSafeInteger(guard.expiresAt))throw new TypeError('Invalid session guard');
 return JSON.stringify(guard);
}
function sessionGuard(param,now) {
 return `(?${param} IS NULL OR EXISTS(SELECT 1 FROM device_sessions d ${MJ} JOIN account_security s ON s.owner_id=d.owner_id WHERE d.device_id=json_extract(?${param},'$.deviceId') AND d.owner_id=?1 AND d.generation=json_extract(?${param},'$.generation') AND s.generation=d.generation AND d.revoked_at IS NULL AND ${MA} AND d.client_kind='web' AND d.created_at<=?${now} AND d.expires_at>?${now} AND json_extract(?${param},'$.expiresAt')>?${now}))`;
}
// Internal service only, not an HTTP route. viewerId must come from validated
// session identity, never from body/path or the owner of a shared entry. Tags
// and pins grant no access. Frequency policy is deliberately not encoded here.
export class PersonalOrganizationStore {
 #db; #clock;
 constructor(db,{clock=Date.now}={}) {this.#db=db;this.#clock=clock;}
 async read(viewerId) {
  identifier(viewerId);
  const row=await this.#db.prepare('SELECT revision,document FROM personal_organization WHERE viewer_id=?1').bind(viewerId).first();
  if(!row)return {revision:0,tags:[],entries:[]};
  const document=validate(JSON.parse(row.document));
  const accessible=await this.#db.prepare(`SELECT p.value->>'$.entryId' AS entry_id FROM json_each(?2,'$.entries') p WHERE ${ACCESS}`).bind(viewerId,row.document).all();
  const known=new Set(accessible.results.map(e=>e.entry_id));
  return {revision:row.revision,tags:document.tags,entries:document.entries.filter(e=>known.has(e.entryId))};
 }
 async replace(viewerId,expectedRevision,input,guard) {
  identifier(viewerId);
  if(!Number.isSafeInteger(expectedRevision)||expectedRevision<0||expectedRevision>=Number.MAX_SAFE_INTEGER)throw new TypeError('Invalid organization revision');
  const document=JSON.stringify(validate(input)),guardValue=guardJson(guard,viewerId);
  const now=this.#clock();if(!Number.isSafeInteger(now)||now<0)throw new TypeError('Invalid clock');
  const result=await this.#db.batch([
   this.#db.prepare(`INSERT INTO personal_organization(viewer_id,revision,document,updated_at) SELECT ?1,0,'{"tags":[],"entries":[]}',?2 WHERE ${sessionGuard(3,2)} ON CONFLICT(viewer_id) DO NOTHING`).bind(viewerId,now,guardValue),
   this.#db.prepare(`UPDATE personal_organization SET revision=revision+1,document=?2,updated_at=?3 WHERE viewer_id=?1 AND revision=?4 AND ${sessionGuard(5,3)} AND NOT EXISTS(SELECT 1 FROM json_each(?2,'$.entries') p WHERE NOT ${ACCESS})`).bind(viewerId,document,now,expectedRevision,guardValue)
  ]);
  return result[1].meta.changes===1 ? {ok:true,revision:expectedRevision+1} : {ok:false};
 }
 async recordSuccessfulCopy(viewerId,{entryId,receiptId,createdAt},guard) {
  identifier(viewerId);identifier(entryId);
  const guardValue=guardJson(guard,viewerId);
  const now=this.#clock();
  if(typeof receiptId!=='string'||!/^[A-Za-z0-9_-]{22,64}$/.test(receiptId)||!Number.isSafeInteger(createdAt)||createdAt<now-300000||createdAt>now+30000)throw new TypeError('Invalid copy receipt');
  const day=Math.floor(now/86400000);
  const access=`EXISTS(SELECT 1 FROM entries e WHERE e.entry_id=?2 AND (e.owner_id=?1 OR EXISTS(SELECT 1 FROM entry_shares s WHERE s.entry_id=e.entry_id AND s.recipient_id=?1 AND s.revoked_at IS NULL)))`;
  const result=await this.#db.batch([
   this.#db.prepare('DELETE FROM personal_copy_receipts WHERE viewer_id=?1 AND accepted_at<?2').bind(viewerId,now-600000),
   this.#db.prepare(`INSERT INTO personal_copy_receipts(viewer_id,receipt_id,accepted_at) SELECT ?1,?3,?4 WHERE ${access} AND ${sessionGuard(6,4)} AND (SELECT count(*) FROM personal_copy_receipts WHERE viewer_id=?1)<1000 AND ((SELECT count(DISTINCT entry_id) FROM personal_copy_days WHERE viewer_id=?1 AND day>=?5)<1000 OR EXISTS(SELECT 1 FROM personal_copy_days WHERE viewer_id=?1 AND entry_id=?2 AND day>=?5)) ON CONFLICT DO NOTHING`).bind(viewerId,entryId,receiptId,now,day-89,guardValue),
   this.#db.prepare(`INSERT INTO personal_copy_days(viewer_id,entry_id,day,copies) SELECT ?1,?2,?3,1 WHERE changes()=1 ON CONFLICT(viewer_id,entry_id,day) DO UPDATE SET copies=MIN(copies+1,1000)`).bind(viewerId,entryId,day),
   this.#db.prepare('DELETE FROM personal_copy_days WHERE viewer_id=?1 AND day<?2').bind(viewerId,day-89)
  ]);
  return {accepted:result[1].meta.changes===1};
 }
 async ranking(viewerId) {
  identifier(viewerId);const today=Math.floor(this.#clock()/86400000);
  const rows=await this.#db.prepare(`SELECT c.entry_id,c.day,c.copies FROM personal_copy_days c JOIN entries e ON e.entry_id=c.entry_id WHERE c.viewer_id=?1 AND c.day>=?2 AND c.day<=?3 AND (e.owner_id=?1 OR EXISTS(SELECT 1 FROM entry_shares s WHERE s.entry_id=e.entry_id AND s.recipient_id=?1 AND s.revoked_at IS NULL)) ORDER BY c.entry_id,c.day LIMIT 90000`).bind(viewerId,today-89,today).all();
  const scores=new Map();
  for(const row of rows.results)scores.set(row.entry_id,(scores.get(row.entry_id)??0)+row.copies*Math.pow(0.5,(today-row.day)/7));
  return [...scores].map(([entryId,score])=>({entryId,score}));
 }
 toString(){return 'PersonalOrganizationStore(redacted)';}
}
