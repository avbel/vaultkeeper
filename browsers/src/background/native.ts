import { NATIVE_HOST_NAME } from "../shared/ids.ts";
import {
  NATIVE_REQUEST_TIMEOUT_MS,
  type ErrorCode,
  type NativeEvent,
  type RequestMap,
  type RequestType,
} from "../shared/protocol.ts";

export type NativeErrorCode = ErrorCode | "unavailable";

export class NativeError extends Error {
  readonly code: NativeErrorCode;
  readonly reason: string | undefined;

  constructor(code: NativeErrorCode, reason?: string) {
    super(reason ? `${code}: ${reason}` : code);
    this.name = "NativeError";
    this.code = code;
    this.reason = reason;
  }
}

export interface PortLike {
  postMessage(message: unknown): void;
  disconnect(): void;
  onMessage: { addListener(listener: (message: unknown) => void): void };
  onDisconnect: { addListener(listener: (port: PortLike) => void): void };
  error?: { message?: string } | null;
}

export interface NativeDeps {
  connectNative(name: string): PortLike;
  /** Chrome reports a failed connect through runtime.lastError inside onDisconnect. */
  lastError?(): string | undefined;
  timeoutMs?: number;
}

type Pending = {
  resolve(result: unknown): void;
  reject(error: NativeError): void;
  timer: ReturnType<typeof setTimeout>;
};

export type EventListener = (event: NativeEvent) => void;

export class NativeClient {
  #port: PortLike | null = null;
  #nextId = 1;
  #pending = new Map<number, Pending>();
  #listeners = new Set<EventListener>();
  #unavailableReason: string | undefined;
  readonly #deps: NativeDeps;

  constructor(deps: NativeDeps) {
    this.#deps = deps;
  }

  get connected(): boolean {
    return this.#port !== null;
  }

  onEvent(listener: EventListener): () => void {
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }

  connect(): void {
    if (this.#port) {
      return;
    }
    this.#unavailableReason = undefined;
    const port = this.#deps.connectNative(NATIVE_HOST_NAME);
    this.#port = port;
    port.onMessage.addListener((message) => {
      if (this.#port === port) {
        this.#handleMessage(message);
      }
    });
    port.onDisconnect.addListener((closed) => {
      if (this.#port !== port) {
        return;
      }
      const reason = closed.error?.message ?? this.#deps.lastError?.();
      this.#handleDisconnect(reason);
    });
  }

  disconnect(): void {
    const port = this.#port;
    if (!port) {
      return;
    }
    this.#port = null;
    try {
      port.disconnect();
    } catch {
      // The port may already be gone.
    }
    this.#rejectAll(new NativeError("unavailable", "disconnected"));
  }

  request<T extends RequestType>(
    type: T,
    fields: RequestMap[T]["fields"],
  ): Promise<RequestMap[T]["result"]> {
    this.connect();
    const port = this.#port;
    if (!port) {
      return Promise.reject(new NativeError("unavailable", "not_connected"));
    }
    const id = this.#nextId++;
    const timeoutMs = this.#deps.timeoutMs ?? NATIVE_REQUEST_TIMEOUT_MS;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.#pending.delete(id);
        reject(new NativeError("timeout"));
      }, timeoutMs);
      this.#pending.set(id, {
        resolve: resolve as (result: unknown) => void,
        reject,
        timer,
      });
      try {
        port.postMessage({ id, type, ...fields });
      } catch (error) {
        clearTimeout(timer);
        this.#pending.delete(id);
        reject(new NativeError("unavailable", errorText(error)));
      }
    });
  }

  #handleMessage(message: unknown): void {
    if (typeof message !== "object" || message === null) {
      return;
    }
    const record = message as Record<string, unknown>;
    if (typeof record.event === "string") {
      this.#handleEvent(record as unknown as NativeEvent);
      return;
    }
    if (typeof record.id !== "number") {
      return;
    }
    const pending = this.#pending.get(record.id);
    if (!pending) {
      return;
    }
    this.#pending.delete(record.id);
    clearTimeout(pending.timer);
    if (record.ok === true) {
      pending.resolve(record.result ?? {});
    } else {
      const code = typeof record.error === "string" ? (record.error as ErrorCode) : "internal";
      pending.reject(new NativeError(code));
    }
  }

  #handleEvent(event: NativeEvent): void {
    if (event.event === "ping") {
      return;
    }
    if (event.event === "unavailable") {
      this.#unavailableReason = event.reason;
    }
    for (const listener of this.#listeners) {
      listener(event);
    }
  }

  #handleDisconnect(reason: string | undefined): void {
    this.#port = null;
    const detail = this.#unavailableReason ?? reason ?? "disconnected";
    this.#rejectAll(new NativeError("unavailable", detail));
    for (const listener of this.#listeners) {
      listener({ event: "unavailable", reason: detail });
    }
  }

  #rejectAll(error: NativeError): void {
    const pending = [...this.#pending.values()];
    this.#pending.clear();
    for (const entry of pending) {
      clearTimeout(entry.timer);
      entry.reject(error);
    }
  }
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
