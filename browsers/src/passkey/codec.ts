// WebAuthn options and results <-> their JSON form (binary as base64url), the shape the app reads
// and returns. The page script runs in the page's own world, so this module has no imports.

export type Json = null | boolean | number | string | Json[] | JsonObject;
export type JsonObject = { [key: string]: Json };

export function toBase64Url(source: BufferSource): string {
  const bytes =
    source instanceof ArrayBuffer
      ? new Uint8Array(source)
      : new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(text: string): ArrayBuffer {
  const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64 + "=".repeat((4 - (base64.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function descriptors(list: readonly PublicKeyCredentialDescriptor[] | undefined): Json[] {
  return (list ?? []).map((credential) => ({
    type: credential.type,
    id: toBase64Url(credential.id),
    ...(credential.transports ? { transports: [...credential.transports] } : {}),
  }));
}

function optional<T extends Json>(key: string, value: T | undefined): Record<string, T> {
  return value === undefined ? {} : { [key]: value };
}

export function encodeCreation(options: PublicKeyCredentialCreationOptions): JsonObject {
  const selection = options.authenticatorSelection;
  return {
    rp: { ...optional("id", options.rp.id), name: options.rp.name },
    user: {
      id: toBase64Url(options.user.id),
      name: options.user.name,
      displayName: options.user.displayName,
    },
    challenge: toBase64Url(options.challenge),
    // Keycloak sends `alg` as a string.
    pubKeyCredParams: options.pubKeyCredParams
      .map((param) => ({ type: param.type, alg: Number(param.alg) }))
      .filter((param) => !Number.isNaN(param.alg)),
    ...optional("timeout", options.timeout),
    excludeCredentials: descriptors(options.excludeCredentials),
    authenticatorSelection: {
      ...optional("authenticatorAttachment", selection?.authenticatorAttachment),
      ...optional("residentKey", selection?.residentKey),
      ...optional("requireResidentKey", selection?.requireResidentKey),
      ...optional("userVerification", selection?.userVerification),
    },
    ...optional("attestation", options.attestation),
    extensions: optional("credProps", options.extensions?.credProps),
  };
}

export function encodeRequest(options: PublicKeyCredentialRequestOptions): JsonObject {
  return {
    challenge: toBase64Url(options.challenge),
    ...optional("timeout", options.timeout),
    ...optional("rpId", options.rpId),
    allowCredentials: descriptors(options.allowCredentials),
    ...optional("userVerification", options.userVerification),
  };
}

/** The app's answer to `create`: RegistrationResponseJSON plus the authenticator data. */
export interface RegistrationJson {
  id: string;
  rawId: string;
  type: "public-key";
  authenticatorAttachment: string;
  response: {
    clientDataJSON: string;
    attestationObject: string;
    authenticatorData: string;
    publicKey: string;
    publicKeyAlgorithm: number;
    transports: string[];
  };
  clientExtensionResults: Record<string, Json>;
}

/** The app's answer to `get`: AuthenticationResponseJSON. */
export interface AssertionJson {
  id: string;
  rawId: string;
  type: "public-key";
  authenticatorAttachment: string;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle: string | null;
  };
  clientExtensionResults: Record<string, Json>;
}

/** The native prototypes, so `instanceof` checks on the results hold. */
export interface Prototypes {
  credential: object | undefined;
  attestation: object | undefined;
  assertion: object | undefined;
}

function adopt<T extends object>(value: T, prototype: object | undefined): T {
  if (prototype) {
    Object.setPrototypeOf(value, prototype);
  }
  return value;
}

/** Own properties shadow the prototype's getters, which would throw on a non-native object. */
function credential(
  json: RegistrationJson | AssertionJson,
  response: object,
  prototypes: Prototypes,
): PublicKeyCredential {
  const extensions = json.clientExtensionResults;
  return adopt(
    {
      id: json.id,
      rawId: fromBase64Url(json.rawId),
      type: json.type,
      authenticatorAttachment: json.authenticatorAttachment,
      response,
      getClientExtensionResults: () => structuredClone(extensions),
      toJSON: () => structuredClone(json),
    },
    prototypes.credential,
  ) as unknown as PublicKeyCredential;
}

export function decodeRegistration(
  json: RegistrationJson,
  prototypes: Prototypes,
): PublicKeyCredential {
  const r = json.response;
  const response = adopt(
    {
      clientDataJSON: fromBase64Url(r.clientDataJSON),
      attestationObject: fromBase64Url(r.attestationObject),
      getAuthenticatorData: () => fromBase64Url(r.authenticatorData),
      getPublicKey: () => fromBase64Url(r.publicKey),
      getPublicKeyAlgorithm: () => r.publicKeyAlgorithm,
      getTransports: () => [...r.transports],
    },
    prototypes.attestation,
  );
  return credential(json, response, prototypes);
}

export function decodeAssertion(json: AssertionJson, prototypes: Prototypes): PublicKeyCredential {
  const r = json.response;
  const response = adopt(
    {
      clientDataJSON: fromBase64Url(r.clientDataJSON),
      authenticatorData: fromBase64Url(r.authenticatorData),
      signature: fromBase64Url(r.signature),
      userHandle: r.userHandle === null ? null : fromBase64Url(r.userHandle),
    },
    prototypes.assertion,
  );
  return credential(json, response, prototypes);
}
