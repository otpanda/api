import test from 'node:test';import assert from 'node:assert/strict';
import{database}from'./sqlite-helper.js';import{CodeCipher}from'../src/code-cipher.js';import{createSourceEntryStore}from'../src/source-entries.js';import{ServiceMetadata}from'../src/service-metadata.js';
const SECRET=Array.from({length:32},(_,i)=>(i*7+13).toString(16).padStart(2,'0')).join('');
const NOW=1800000000000,DAY=86400000;
async function fx(opts={}){
 const db=database(),key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),cipher=new CodeCipher({keys:new Map([['f',key]]),activeKeyId:'f'});
 const store=createSourceEntryStore(db,cipher,{matcher:new ServiceMetadata(db),templateSecret:SECRET,clock:()=>NOW,...opts});
 const o='o1';db.sqlite.prepare('INSERT INTO accounts(owner_id,created_at) VALUES(?,?)').run(o,NOW);
 return{db,store,o};
}
const ev=(sourceId,id,over={})=>({sourceId,eventId:id,code:'123456',receivedAt:NOW-1000,expiresAt:NOW+60000,sender:'noreply@bank.example',receiver:'me@x.test',accountHint:'me@x.test',text:'Bank code 123456',subject:'Your Bank code 123456',context:{kind:'email',text:'Your Bank code 123456'},...over});
test('retention on keeps one redacted row per sender, no code; off keeps none',async()=>{
 for(const on of [true,false]){
  const f=await fx(on?{contextRetentionMs:30*DAY,contextDigestSecret:SECRET}:{});
  try{
   const o=f.o;
   const s=await f.store.createSource(o,'gmail','G',NOW);
   await f.store.receive(o,ev(s,'a1'));await f.store.receive(o,ev(s,'a2'));
   const n=f.db.sqlite.prepare('SELECT count(*) c FROM unassigned_context').get().c;
   assert.equal(n,on?1:0);
   if(on){const ctx=await f.store.contextsForOwner(o,NOW);const t=JSON.stringify(ctx);assert.equal(ctx.length,1);assert.equal(t.includes('123456'),false);assert.equal(t.includes('v1:'),false);
    assert.equal(await f.store.cleanupContext(NOW+31*DAY),1);}
  }finally{f.db.sqlite.close();}
 }
});
