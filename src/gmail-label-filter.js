// Optional label mode. Without it the mailbox is watched on INBOX and no setting is changed.
// With it the connection creates ONE label and ONE add-label-only filter in the owner's mailbox, and
// the watch, history and recovery follow that label. The query is the one tested on the OTPanda
// development mailbox (10 live arrivals: 5 of 6 OTPs labeled, the bare-number mail missed, 0 of 4
// negatives labeled). It is not a claim of general accuracy.
// Consent needed: gmail.readonly (read) + gmail.labels (labels.create/delete) + gmail.settings.basic
// (filters.create/delete). INACTIVE until a runtime passes it to GmailSync as `labelFilter`.
export const GMAIL_SCOPES_READ = Object.freeze(['https://www.googleapis.com/auth/gmail.readonly']);
export const GMAIL_SCOPES_LABEL_FILTER = Object.freeze(['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.labels', 'https://www.googleapis.com/auth/gmail.settings.basic']);
export const GMAIL_CODE_FILTER = Object.freeze({
  labelName: 'OTPanda codes', // chosen here, not by the experiment; change freely before activation
  query: "{(subject:code -subject:\"code review\" -subject:\"source code\" -subject:\"discount code\" -subject:\"promo code\") passcode OTP \"verification code\" \"security code\" \"authentication code\" \"confirmation code\" \"login code\" \"sign-in code\" \"sign in code\" \"one-time code\" \"one time code\" \"one-time password\" \"one time password\" \"your code\" \"code is\" \"קוד אימות\" \"קוד כניסה\" \"código de verificación\" \"código de acceso\" \"code de vérification\" \"Bestätigungscode\" \"验证码\" \"認証コード\"}",
});
