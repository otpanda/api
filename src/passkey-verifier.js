// Exact-origin, UV-required WebAuthn adapter. No persistence or HTTP endpoint.
// Caller supplies server-stored challenges and atomic credential state changes.
import { base64urlDecode } from './tokens.js';
import { generateRegistrationOptions, generateAuthenticationOptions, verifyRegistrationResponse, verifyAuthenticationResponse } from '@simplewebauthn/server';
const RP_ID = 'otpanda.github.io';
const WEB_ORIGIN = 'https://otpanda.github.io';
function checkedChallenge(value) {
  if (typeof value !== 'string' || !base64urlDecode(value, 32)) throw new TypeError('Server challenge required');
  return value;
}
const ALGORITHMS = Object.freeze([-7, -257]); // ES256 and RS256, explicit offer/verify parity.
export class PasskeyVerifier {
  constructor({ androidOrigins = [] } = {}) {
    if (!Array.isArray(androidOrigins) || androidOrigins.some(o => typeof o !== 'string' || !/^android:apk-key-hash:[A-Za-z0-9_-]{43}$/.test(o))) throw new TypeError('Verified signing origins required');
    this.origins = [WEB_ORIGIN, ...new Set(androidOrigins)];
  }
  async registrationOptions({ ownerId, email, challenge, excludeCredentials = [] }) {
    if (typeof ownerId !== 'string' || !ownerId || ownerId.length > 64 || typeof email !== 'string' || !email || typeof challenge !== 'string' || challenge.length < 32 || challenge.length > 256) throw new TypeError('Server registration binding required');
    return generateRegistrationOptions({ rpName:'OTPanda', rpID:RP_ID, userName:email, userID:new TextEncoder().encode(ownerId), challenge:base64urlDecode(checkedChallenge(challenge),32), timeout:120000, attestationType:'none', supportedAlgorithmIDs:[...ALGORITHMS], authenticatorSelection:{ residentKey:'required', userVerification:'required' }, excludeCredentials });
  }
  async authenticationOptions({ challenge, allowCredentials }) {
    if (typeof challenge !== 'string' || challenge.length < 32 || challenge.length > 256) throw new TypeError('Server challenge required');
    return generateAuthenticationOptions({ rpID:RP_ID, challenge:base64urlDecode(checkedChallenge(challenge),32), timeout:120000, userVerification:'required', ...(allowCredentials ? {allowCredentials} : {}) });
  }
  async verifyRegistration({ response, expectedChallenge }) {
    checkedChallenge(expectedChallenge);
    const result = await verifyRegistrationResponse({ response, expectedChallenge, expectedOrigin:this.origins, expectedRPID:RP_ID, requireUserPresence:true, requireUserVerification:true, supportedAlgorithmIDs:[...ALGORITHMS] });
    if (!result.verified || !result.registrationInfo.userVerified) return undefined;
    return result.registrationInfo;
  }
  async verifyAuthentication({ response, expectedChallenge, credential }) {
    checkedChallenge(expectedChallenge);
    const result = await verifyAuthenticationResponse({ response, expectedChallenge, expectedOrigin:this.origins, expectedRPID:RP_ID, credential, requireUserVerification:true });
    if (!result.verified || !result.authenticationInfo.userVerified) return undefined;
    return result.authenticationInfo;
  }
}
