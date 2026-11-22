export const RESCAN_DEBOUNCE_MS = 200;
/** A page that never stops mutating still gets its forms scanned this often. */
export const RESCAN_MAX_WAIT_MS = 1_000;

// Custom elements may render a form inside a shadow root, which the document's observer never
// sees, so adding or changing one counts as well.
function hostsShadow(el: Element): boolean {
  return el.shadowRoot !== null || el.localName.includes("-");
}

function mayHoldField(node: Node): boolean {
  if (node.nodeType !== Node.ELEMENT_NODE) {
    return false;
  }
  const el = node as Element;
  if (el.localName === "input" || hostsShadow(el) || el.querySelector("input") !== null) {
    return true;
  }
  const walker = el.ownerDocument.createTreeWalker(el, NodeFilter.SHOW_ELEMENT);
  for (let next = walker.nextNode(); next; next = walker.nextNode()) {
    if (hostsShadow(next as Element)) {
      return true;
    }
  }
  return false;
}

/** Whether any record can change which login forms the page has or which fields are visible. */
export function affectsForms(records: readonly MutationRecord[]): boolean {
  return records.some((record) =>
    record.type === "attributes"
      ? mayHoldField(record.target)
      : [...record.addedNodes, ...record.removedNodes].some(mayHoldField),
  );
}

export interface RescanScheduler {
  /** `relevant`: the change may affect login forms; the flush is told whether any did. */
  schedule: (relevant: boolean) => void;
  cancel: () => void;
}

// Trailing debounce with a deadline: a burst of mutations is flushed once it settles, or at the
// latest RESCAN_MAX_WAIT_MS after its first mutation.
export function createRescanScheduler(flush: (relevant: boolean) => void): RescanScheduler {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let firstAt: number | undefined;
  let relevant = false;

  const cancel = (): void => {
    clearTimeout(timer);
    timer = undefined;
    firstAt = undefined;
    relevant = false;
  };

  return {
    schedule(isRelevant) {
      const now = Date.now();
      const start = firstAt ?? now;
      firstAt = start;
      relevant = relevant || isRelevant;
      clearTimeout(timer);
      timer = setTimeout(
        () => {
          const any = relevant;
          cancel();
          flush(any);
        },
        Math.min(RESCAN_DEBOUNCE_MS, start + RESCAN_MAX_WAIT_MS - now),
      );
    },
    cancel,
  };
}
