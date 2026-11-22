/**
 * Sends `message` to the background and resolves whether it accepted it. A refusal, a rejection
 * and a synchronous throw all resolve false: a content script left behind by an extension update
 * gets "Extension context invalidated" thrown, not a rejected promise.
 */
export function forwardToBackground<T>(
  sendMessage: (message: T) => unknown,
  message: T,
): Promise<boolean> {
  return new Promise<unknown>((resolve) => {
    resolve(sendMessage(message));
  }).then(
    (reply) => (reply as { accepted?: unknown } | null | undefined)?.accepted === true,
    () => false,
  );
}
