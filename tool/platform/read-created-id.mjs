import {readFileSync,appendFileSync} from 'node:fs';
const text=readFileSync('qualification-evidence/create.log','utf8');const id=text.match(/database_id["\s:=]+([0-9a-f-]{36})/)?.[1];
if(!id)throw Error('Temporary database id missing; cleanup by fixed temporary name remains enabled');
appendFileSync(process.env.GITHUB_ENV,'QUALIFICATION_DB_ID='+id+'\n');
