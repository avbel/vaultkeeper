export function composedParent(node: Node): Element | null {
  if (node.parentElement) {
    return node.parentElement;
  }
  const root = node.getRootNode();
  if (root instanceof ShadowRoot) {
    return root.host;
  }
  return null;
}

export function composedContains(container: Element, node: Node): boolean {
  let current: Node | null = node;
  while (current) {
    if (current === container) {
      return true;
    }
    current = composedParent(current);
  }
  return false;
}

export function composedClosest(node: Element, localName: string): Element | null {
  let current: Element | null = node;
  while (current) {
    if (current.localName === localName) {
      return current;
    }
    current = composedParent(current);
  }
  return null;
}

export function eventTarget(event: Event): Element | null {
  const first = event.composedPath()[0];
  return first instanceof Element ? first : null;
}

export function isInput(node: unknown): node is HTMLInputElement {
  return node instanceof Element && node.localName === "input";
}
