// Where the browser leg of a signed-in Google link returns. Web sessions return to the web app exactly as before. A link started by an ANDROID device
// session returns to the already verified native App Link landing (/app-return) with the same fragment and state, so the app can pick it up
// without widening the Android overlay to the whole web app. The choice comes only from the stored client kind of the device the ticket was bound
// to (server-side, never a request parameter), and the target is a fixed constant.
export const WEB_LINK_RETURN='https://otpanda.github.io/app/',NATIVE_LINK_RETURN='https://otpanda-api.abrahammurciano.workers.dev/app-return';
export async function linkReturnBase(db,deviceId){
 try{const r=typeof deviceId==='string'?await db.prepare("SELECT client_kind k FROM device_sessions WHERE device_id=?1").bind(deviceId).first():undefined;return r?.k==='android'?NATIVE_LINK_RETURN:WEB_LINK_RETURN;}catch{return WEB_LINK_RETURN;}
}
