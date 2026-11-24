import {randomBytes} from 'node:crypto';import {appendFileSync} from 'node:fs';
const key=randomBytes(16).toString('hex');console.log('::add-mask::'+key);appendFileSync(process.env.GITHUB_ENV,'QUALIFICATION_KEY='+key+'\n');
