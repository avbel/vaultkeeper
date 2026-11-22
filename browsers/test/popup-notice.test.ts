import { describe, expect, it } from "vite-plus/test";
import {
  NOTICE_FAILED,
  NOTICE_NO_FORM,
  NOTICE_NO_RESPONSE,
  NOTICE_UNREACHABLE,
  replyNotice,
} from "../src/ui/notice.ts";

describe("popup reply notice", () => {
  it("explains a fill that did not happen", () => {
    const fill = { kind: "popup_fill", choose: false } as const;
    expect(replyNotice(fill, undefined)).toBe(NOTICE_NO_RESPONSE);
    expect(replyNotice(fill, { ok: false, reason: "unreachable" })).toBe(NOTICE_UNREACHABLE);
    expect(replyNotice(fill, { ok: true, found: false })).toBe(NOTICE_NO_FORM);
    expect(replyNotice(fill, { ok: true, found: true })).toBeNull();
  });

  it("reports a failed unlock, open or reset instead of closing silently", () => {
    for (const request of [
      { kind: "popup_unlock" },
      { kind: "popup_open_app", view: "manager" },
      { kind: "popup_reset_pairing" },
    ] as const) {
      expect(replyNotice(request, { ok: false })).toBe(NOTICE_FAILED);
      expect(replyNotice(request, { ok: true })).toBeNull();
    }
  });
});
