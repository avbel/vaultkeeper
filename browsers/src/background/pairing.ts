const DB_NAME = "vaultkeeper";
const STORE = "keys";
const KEY_NAME = "pairing";
const PROOF_PREFIX = "vaultkeeper-browser-v1\0";
const ECDSA_KEY = { name: "ECDSA", namedCurve: "P-256" } as const;
const ECDSA_SIGN = { name: "ECDSA", hash: "SHA-256" } as const;

export interface KeyStore {
  load(): Promise<CryptoKeyPair | undefined>;
  save(pair: CryptoKeyPair): Promise<void>;
}

function request<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => {
      resolve(req.result);
    };
    req.onerror = () => {
      reject(req.error ?? new Error("indexedDB request failed"));
    };
  });
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(DB_NAME, 1);
    open.onupgradeneeded = () => {
      open.result.createObjectStore(STORE);
    };
    open.onsuccess = () => {
      resolve(open.result);
    };
    open.onerror = () => {
      reject(open.error ?? new Error("indexedDB open failed"));
    };
  });
}

export function idbKeyStore(): KeyStore {
  return {
    async load() {
      const db = await openDb();
      try {
        const value = await request(
          db.transaction(STORE, "readonly").objectStore(STORE).get(KEY_NAME),
        );
        return (value as CryptoKeyPair | undefined) ?? undefined;
      } finally {
        db.close();
      }
    },
    async save(pair) {
      const db = await openDb();
      try {
        await request(db.transaction(STORE, "readwrite").objectStore(STORE).put(pair, KEY_NAME));
      } finally {
        db.close();
      }
    },
  };
}

let inFlight: Promise<CryptoKeyPair> | null = null;

/** Memoised so two concurrent first uses cannot create two different pairing keys. */
export function getOrCreateKeyPair(store: KeyStore = idbKeyStore()): Promise<CryptoKeyPair> {
  inFlight ??= (async () => {
    const existing = await store.load();
    if (existing) {
      return existing;
    }
    const pair = await crypto.subtle.generateKey(ECDSA_KEY, false, ["sign"]);
    await store.save(pair);
    return pair;
  })().catch((error: unknown) => {
    inFlight = null;
    throw error;
  });
  return inFlight;
}

export function resetKeyPairCache(): void {
  inFlight = null;
}

export async function exportPublicKey(pair: CryptoKeyPair): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
}

export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

export function fromBase64(text: string): Uint8Array {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function proofMessage(challenge: Uint8Array, caller: string): Uint8Array {
  const prefix = new TextEncoder().encode(PROOF_PREFIX);
  const callerBytes = new TextEncoder().encode(caller);
  const message = new Uint8Array(prefix.length + challenge.length + callerBytes.length);
  message.set(prefix, 0);
  message.set(challenge, prefix.length);
  message.set(callerBytes, prefix.length + challenge.length);
  return message;
}

/** Returns the 64-byte IEEE P1363 `r || s` signature WebCrypto produces for ECDSA. */
export async function signProof(
  pair: CryptoKeyPair,
  challenge: Uint8Array,
  caller: string,
): Promise<Uint8Array> {
  const signature = await crypto.subtle.sign(
    ECDSA_SIGN,
    pair.privateKey,
    proofMessage(challenge, caller) as BufferSource,
  );
  return new Uint8Array(signature);
}

/** First 8 bytes of SHA-256 over the raw public key as `A1B2-C3D4-E5F6-0718`. */
export async function fingerprint(rawPublicKey: Uint8Array): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", rawPublicKey as BufferSource),
  );
  const hex = [...digest.subarray(0, 8)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
  return hex.match(/.{4}/g)?.join("-") ?? hex;
}

/**
 * The string the host puts in HostHello and the daemon verifies the proof against.
 * Chrome: the host argv is `chrome-extension://<id>/`, kept with the trailing slash.
 * Firefox: the host argv is the add-on id, which is runtime.id (the gecko id).
 */
export function callerString(runtime: { id: string; getURL(path: string): string }): string {
  if (runtime.getURL("/").startsWith("moz-extension:")) {
    return runtime.id;
  }
  return `chrome-extension://${runtime.id}/`;
}
