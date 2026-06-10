// FALSE POSITIVE — not secrets.
// Resembles: hex token rules (runs of [0-9a-f]).
// Why benign: a design-system color palette. The hex strings are CSS colors, not keys.

export const palette = {
  primary:   "#1d4ed8",
  secondary: "#9333ea",
  surface:   "#0f172a",
  // packed ARGB constants used by the canvas renderer
  gridLines:  0xff2a2a3c,
  highlight:  0xfff59e0b,
  shadowRamp: [0x00000000, 0x33000000, 0x66000000, 0x99000000, 0xcc000000],
} as const;
