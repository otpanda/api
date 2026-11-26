export function lazyHttp(factory){let value;return{fetch(...args){value??=factory();return value.fetch(...args);}};}
