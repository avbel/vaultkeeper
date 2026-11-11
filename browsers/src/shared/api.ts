// Firefox exposes the promise API as `browser`; Chrome MV3 supports promises on `chrome`.
export const api: typeof chrome =
  (globalThis as { browser?: typeof chrome }).browser ?? globalThis.chrome;
