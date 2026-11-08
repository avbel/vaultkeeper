# Regenerates the fixtures in this directory from a disposable Vaultwarden:
#
#   docker run -d --rm --name vw -p 8099:80 -e SIGNUPS_ALLOWED=true \
#       -e I_REALLY_WANT_VOLATILE_STORAGE=true -e DOMAIN=http://localhost:8099 vaultwarden/server:latest
#   python3 -I crates/api/tests/fixtures/capture.py
#
# Access/refresh tokens have their JWT signature replaced by REDACTED_SIGNATURE. Every capture
# creates new user ids, so after re-capturing update USER_ID in tests/common/mod.rs and the
# expected subject in src/token.rs. token_rate_limited.json was captured separately (the login
# rate limiter answers 429 after about ten attempts per minute) and is not written by this script.
import base64, hashlib, hmac, json, os, re, struct, sys, time, urllib.parse, urllib.request, urllib.error, uuid

BASE = "http://localhost:8099"
OUT = os.path.dirname(os.path.abspath(__file__))
HDRS = {"Bitwarden-Client-Name": "desktop", "Bitwarden-Client-Version": "2025.12.0", "Device-Type": "7"}

def req(method, path, body=None, form=None, token=None, extra=None, raw=None):
    headers = dict(HDRS)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if raw is not None:
        headers["Content-Type"], data = raw
    if token:
        headers["Authorization"] = "Bearer " + token
    if extra:
        headers.update(extra)
    r = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(r, timeout=20) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

def b64(n):
    return base64.b64encode(os.urandom(n)).decode()

def encstr(n=24):
    return f"2.{b64(16)}|{b64(n)}|{b64(32)}"

def scrub(text):
    def jwt(m):
        parts = m.group(0).split(".")
        return ".".join(parts[:2] + ["REDACTED_SIGNATURE"])
    text = re.sub(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", jwt, text)
    return text

def save(name, text):
    try:
        text = json.dumps(json.loads(text), indent=2, sort_keys=False) + "\n"
    except ValueError:
        text = text if text.endswith("\n") else text + "\n"
    with open(f"{OUT}/{name}", "w") as f:
        f.write(scrub(text))

DEVICE = str(uuid.uuid4())

def register(email, kdf):
    s, t = req("POST", "/identity/accounts/register/send-verification-email", body={"email": email, "name": "Fixture User"}, extra={"Accept": "application/json"})
    assert s == 200, (s, t)
    token = json.loads(t)
    body = {
        "email": email, "masterPasswordHash": b64(32), **kdf, "key": encstr(64),
        "keys": {"encryptedPrivateKey": encstr(1200), "publicKey": b64(294)},
        "emailVerificationToken": token,
    }
    h = body["masterPasswordHash"]
    s, t = req("POST", "/identity/accounts/register/finish", body=body)
    assert s == 200, (s, t)
    return h

def login(email, h, extra=None):
    form = {"grant_type": "password", "username": email, "password": h, "scope": "api offline_access",
            "client_id": "desktop", "deviceType": "7", "deviceIdentifier": DEVICE, "deviceName": "macos"}
    if extra:
        form.update(extra)
    return req("POST", "/identity/connect/token", form=form)

def totp(secret_b32, t=None):
    key = base64.b32decode(secret_b32)
    counter = int((t or time.time()) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = digest[-1] & 0xF
    code = (struct.unpack(">I", digest[o:o + 4])[0] & 0x7FFFFFFF) % 1000000
    return f"{code:06d}"

# --- prelogin
s, t = req("POST", "/identity/accounts/prelogin", body={"email": "nobody@example.com"})
assert s == 200; save("prelogin_pbkdf2.json", t)

argon_email = "argon2@example.com"
register(argon_email, {"kdf": 1, "kdfIterations": 3, "kdfMemory": 64, "kdfParallelism": 4})
s, t = req("POST", "/identity/accounts/prelogin", body={"email": argon_email})
assert s == 200; save("prelogin_argon2id.json", t)

# --- main user
email = "vault@example.com"
h = register(email, {"kdf": 0, "kdfIterations": 600000})
s, t = req("POST", "/identity/accounts/prelogin", body={"email": email})
save("prelogin_registered.json", t)

s, t = login(email, b64(32)); assert s == 400, (s, t); save("token_invalid_password.json", t)
s, t = login(email, h); assert s == 200, (s, t); save("token_success.json", t)
tok = json.loads(t); access = tok["access_token"]; refresh = tok["refresh_token"]

s, t = req("POST", "/identity/connect/token", form={"grant_type": "refresh_token", "client_id": "desktop", "refresh_token": refresh})
assert s == 200, (s, t); save("token_refresh.json", t)
s, t = req("POST", "/identity/connect/token", form={"grant_type": "refresh_token", "client_id": "desktop", "refresh_token": "bogus"})
print("refresh invalid", s, t); save("token_refresh_invalid.json", t)

s, t = req("GET", "/api/sync?excludeDomains=true", token="bogus")
print("sync 401", s, repr(t)); save("sync_unauthorized.txt", t)

s, t = req("POST", "/api/two-factor/send-email-login", body={"email": email, "masterPasswordHash": h, "deviceIdentifier": DEVICE})
print("send-email-login", s, t); save("send_email_login_disabled.json", t)

# --- folders
s, t = req("POST", "/api/folders", body={"name": encstr(16)}, token=access)
assert s == 200, (s, t); save("folder_create.json", t); folder = json.loads(t)
s, t = req("PUT", f"/api/folders/{folder['id']}", body={"name": encstr(16)}, token=access)
assert s == 200, (s, t); save("folder_update.json", t)
s, t = req("PUT", "/api/folders/00000000-0000-0000-0000-000000000000", body={"name": encstr(16)}, token=access)
print("folder missing", s, t); save("folder_not_found.json", t)

me = json.loads(base64.urlsafe_b64decode(access.split(".")[1] + "==="))["sub"]
now = "2026-11-08T12:00:00.000Z"

def cipher_body(typ, **kw):
    base = {"type": typ, "encryptedFor": me, "name": encstr(), "notes": encstr(), "favorite": False, "reprompt": 0,
            "folderId": folder["id"], "organizationId": None, "key": encstr(64), "fields": [{"type": 0, "name": encstr(), "value": encstr(), "linkedId": None}],
            "passwordHistory": None, "login": None, "secureNote": None, "card": None, "identity": None, "sshKey": None}
    base.update(kw)
    return base

bodies = {
    1: cipher_body(1, login={"username": encstr(), "password": encstr(), "totp": encstr(), "passwordRevisionDate": None,
                              "uris": [{"uri": encstr(), "match": None}, {"uri": encstr(), "match": 3}]}),
    2: cipher_body(2, secureNote={"type": 0}, folderId=None),
    3: cipher_body(3, card={"cardholderName": encstr(), "brand": encstr(), "number": encstr(), "expMonth": encstr(), "expYear": encstr(), "code": encstr()}),
    4: cipher_body(4, identity={k: encstr() for k in ["title", "firstName", "middleName", "lastName", "address1", "address2", "address3", "city", "state", "postalCode", "country", "company", "email", "phone", "ssn", "username", "passportNumber", "licenseNumber"]}),
    5: cipher_body(5, sshKey={"privateKey": encstr(400), "publicKey": encstr(100), "keyFingerprint": encstr(40)}),
}
created = {}
for typ, body in bodies.items():
    s, t = req("POST", "/api/ciphers", body=body, token=access)
    assert s == 200, (typ, s, t)
    save(f"cipher_create_type{typ}.json", t); created[typ] = json.loads(t)

# update login with stale revision date then a good one
login_c = created[1]
upd = dict(bodies[1]); upd["name"] = encstr(); upd["lastKnownRevisionDate"] = login_c["revisionDate"]
s, t = req("PUT", f"/api/ciphers/{login_c['id']}", body=upd, token=access)
assert s == 200, (s, t); save("cipher_update.json", t)
stale = dict(upd); stale["lastKnownRevisionDate"] = "2020-01-01T00:00:00.000000Z"
s, t = req("PUT", f"/api/ciphers/{login_c['id']}", body=stale, token=access)
print("stale", s, t); save("cipher_update_stale.json", t)
no_ef = dict(upd); no_ef.pop("encryptedFor")
s, t = req("PUT", f"/api/ciphers/{login_c['id']}", body=no_ef, token=access)
print("no encryptedFor", s, t); save("cipher_update_missing_encrypted_for.txt", t)

# --- attachments (v2 flow)
def multipart(field, filename, data):
    boundary = "----bwlboundary" + uuid.uuid4().hex
    head = f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode()
    return f"multipart/form-data; boundary={boundary}", head + data + f"\r\n--{boundary}--\r\n".encode()

blob = os.urandom(2048)
s, t = req("POST", f"/api/ciphers/{login_c['id']}/attachment/v2", body={"key": encstr(64), "fileName": encstr(32), "fileSize": len(blob)}, token=access)
assert s == 200, (s, t); save("attachment_create_v2.json", t); att1 = json.loads(t)
s, t = req("POST", f"/api/ciphers/{login_c['id']}/attachment/{att1['attachmentId']}", raw=multipart("data", "blob", blob), token=access)
print("attachment upload", s, repr(t)); assert s == 200
s, t = req("GET", f"/api/ciphers/{login_c['id']}/attachment/{att1['attachmentId']}", token=access)
assert s == 200, (s, t); save("attachment_info.json", t); info = json.loads(t)
r = urllib.request.Request(info["url"])
with urllib.request.urlopen(r) as resp:
    assert resp.read() == blob
    print("download ok", resp.headers.get("content-type"), resp.headers.get("content-length"))
s, t = req("GET", f"/api/ciphers/{login_c['id']}/attachment/00000000000000000000000000000000", token=access)
print("attachment missing", s, t); save("attachment_not_found.json", t)
# second attachment, deleted again
s, t = req("POST", f"/api/ciphers/{login_c['id']}/attachment/v2", body={"key": encstr(64), "fileName": encstr(32), "fileSize": 10}, token=access)
att2 = json.loads(t)
s, t = req("POST", f"/api/ciphers/{login_c['id']}/attachment/{att2['attachmentId']}", raw=multipart("data", "blob", os.urandom(10)), token=access)
s, t = req("DELETE", f"/api/ciphers/{login_c['id']}/attachment/{att2['attachmentId']}", token=access)
print("attachment delete", s, t[:120]); save("attachment_delete.json", t)

# trash/restore/delete on the note (type 2) and secure note; keep others for sync
note = created[2]
s, t = req("PUT", f"/api/ciphers/{note['id']}/delete", token=access); print("trash", s, repr(t))
s, t = req("PUT", f"/api/ciphers/{note['id']}/restore", token=access); assert s == 200, (s, t); save("cipher_restore.json", t)
s, t = req("POST", "/api/ciphers", body=cipher_body(2, secureNote={"type": 0}, folderId=None), token=access)
tmp = json.loads(t)
s, t = req("DELETE", f"/api/ciphers/{tmp['id']}", token=access); print("delete", s, repr(t))
s, t = req("DELETE", f"/api/folders/{folder['id']}", token=access); print("folder delete", s, repr(t))
# folder deletion also: re-create folder for sync
s, t = req("POST", "/api/folders", body={"name": encstr(16)}, token=access)
folder2 = json.loads(t)
s, t = req("PUT", f"/api/ciphers/{created[1]['id']}", body={**upd, "folderId": folder2["id"], "lastKnownRevisionDate": None}, token=access)
s, t = req("PUT", f"/api/ciphers/{created[5]['id']}/delete", token=access)

s, t = req("GET", "/api/sync?excludeDomains=true", token=access)
assert s == 200, (s, t); save("sync_full.json", t)
# without client version header sshKey is hidden
r = urllib.request.Request(BASE + "/api/sync?excludeDomains=true", headers={"Authorization": "Bearer " + access})
with urllib.request.urlopen(r) as resp:
    save("sync_without_client_version.json", resp.read().decode())

# --- 2FA user
email2 = "totp@example.com"
h2 = register(email2, {"kdf": 0, "kdfIterations": 600000})
s, t = login(email2, h2); acc2 = json.loads(t)["access_token"]
s, t = req("POST", "/api/two-factor/get-authenticator", body={"masterPasswordHash": h2}, token=acc2)
assert s == 200, (s, t); ga = json.loads(t)
secret = ga["authenticator"]["key"]; uvt = ga["userVerificationToken"]
s, t = req("PUT", "/api/two-factor/authenticator", body={"key": secret, "token": totp(secret), "userVerificationToken": uvt, "masterPasswordHash": h2}, token=acc2)
assert s == 200, (s, t)
time.sleep(1)
s, t = login(email2, h2); assert s == 400, (s, t); save("token_two_factor_required.json", t)
s, t = login(email2, h2, {"twoFactorToken": "000000", "twoFactorProvider": "0", "twoFactorRemember": "0"}); print("bad 2fa", s, t); save("token_two_factor_invalid.json", t)
# next TOTP step: wait for a fresh code not used at activation
nxt = totp(secret, time.time() + 30)
time.sleep(0)
s, t = login(email2, h2, {"twoFactorToken": totp(secret, time.time() + 30), "twoFactorProvider": "0", "twoFactorRemember": "1"})
print("good 2fa", s, t[:80]); 
if s == 200:
    save("token_two_factor_success_remember.json", t)
