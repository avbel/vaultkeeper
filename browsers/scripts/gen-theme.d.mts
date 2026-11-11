export const SLINT_PATH: string;
export const CSS_PATH: string;
export function parseTokens(slint: string): { name: string; dark: string; light: string }[];
export function generateCss(slint: string): string;
