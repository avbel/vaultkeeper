export function workspaceVersion(cargoToml: string): string;
export function mergeManifest(
  base: Record<string, unknown>,
  target: Record<string, unknown>,
  version: string,
): Record<string, unknown>;
