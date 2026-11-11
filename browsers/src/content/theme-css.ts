import themeCss from "../ui/theme.css?raw";
import { toShadowTokens } from "./shadow-tokens.ts";

export const SHADOW_TOKENS = toShadowTokens(themeCss);
