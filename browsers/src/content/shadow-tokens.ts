// theme.css targets :root; inside the closed shadow root the same tokens must hang off the host,
// which receives data-theme from the app (absent means follow the system).
export function toShadowTokens(themeCss: string): string {
  return themeCss
    .replace(/:root\[data-theme="(\w+)"\]/g, ':host([data-theme="$1"])')
    .replace(/:root:not\(\[data-theme="light"\]\)/g, ':host(:not([data-theme="light"]))')
    .replace(/:root/g, ":host");
}
