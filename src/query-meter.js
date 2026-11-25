// Counts D1 queries the way the Workers Free plan caps them per invocation (50): every run/all/first/raw is one query,
// db.batch and db.exec are one query each. The count is monotonic for the isolate, so a request measures
// (count after - count before). Concurrent requests only ADD to that difference, so it can only over-estimate the request's own use.
export function createQueryMeter(db){
 let count=0;
 const statement=s=>new Proxy(s,{get(t,k){
  const v=Reflect.get(t,k);
  if(k===Symbol.for('realtime.target'))return t;
  if(k==='bind')return(...a)=>statement(t.bind(...a));
  if(['run','all','first','raw'].includes(k))return(...a)=>{count++;return t[k](...a);};
  return typeof v==='function'?v.bind(t):v;}});
 const proxy=new Proxy(db,{get(t,k){
  const v=Reflect.get(t,k);
  if(k==='prepare')return sql=>statement(t.prepare(sql));
  if(k==='batch')return list=>{count++;return t.batch(list.map(s=>s[Symbol.for('realtime.target')]??s));};
  if(k==='exec')return(...a)=>{count++;return t.exec(...a);};
  return typeof v==='function'?v.bind(t):v;}});
 return {db:proxy,count:()=>count};
}
