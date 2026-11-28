// Local workerd/D1 only. No remote binding, credentials, deploy or production config.
import {getPlatformProxy} from 'wrangler';
import {mkdtempSync,readdirSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
export async function localDatabase(){
 const dir=mkdtempSync(join(tmpdir(),'import-v2-local-d1-'));
 const proxy=await getPlatformProxy({configPath:'qualification/transfer/wrangler.json',persist:{path:dir},remoteBindings:false});
 const db=proxy.env.DB;
 try{
 for(const f of readdirSync(new URL('../migrations/',import.meta.url)).sort()){
 const sql=readFileSync(new URL('../migrations/'+f,import.meta.url),'utf8');let cur='',trigger=false;
 for(const line of sql.split('\n')){
 if(/^\s*--/.test(line)&&!cur.trim())continue;
 cur+=line+'\n';
 if(/^\s*CREATE TRIGGER/i.test(cur.trim().split('\n').find(l=>!/^\s*--/.test(l))??''))trigger=true;
 if(trigger?/^\s*END;\s*$/i.test(line):/;\s*$/.test(line)){if(cur.trim())await db.prepare(cur).run();cur='';trigger=false;}
 }
 if(cur.trim())await db.prepare(cur).run();
 }
 return{prepare:sql=>db.prepare(sql),batch:s=>db.batch(s),sqlite:{close:()=>proxy.dispose()}};
 }catch(e){await proxy.dispose();throw e;}
}
