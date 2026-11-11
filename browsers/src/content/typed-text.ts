const INSERT_TYPES = new Set([
  "insertText",
  "insertFromPaste",
  "insertFromPasteAsQuotation",
  "insertFromDrop",
  "insertFromYank",
]);

// Rebuilds what the user typed from trusted input events alone, never from `el.value`, which a page
// can rewrite from a `beforeinput` handler. Returns null once an edit cannot be modelled (cursor in
// the middle, selection replaced, IME); the model recovers when the field becomes empty.
export function applyInput(
  previous: string | null | undefined,
  event: Event,
  value: string,
): string | null {
  if (value === "") {
    return "";
  }
  if (previous === null) {
    return null;
  }
  const base = previous ?? "";
  const { inputType, data, dataTransfer } = event as InputEvent;
  if (INSERT_TYPES.has(inputType)) {
    const inserted = data ?? dataTransfer?.getData("text/plain") ?? null;
    return inserted === null ? null : base + inserted;
  }
  if (inputType === "deleteContentBackward") {
    return Array.from(base).slice(0, -1).join("");
  }
  return null;
}
