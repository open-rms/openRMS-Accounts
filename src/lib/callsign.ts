// Amateur callsign helpers. Account callsigns are bare (no SSID, no /P);
// gateway callsigns may carry an SSID (-0..-15) as Winlink lists them.

const BASE = /^[A-Z0-9]{1,3}[0-9][A-Z0-9]{0,3}[A-Z]$/;

export function normalizeCallsign(input: string): string {
  return input.trim().toUpperCase();
}

export function isValidBaseCallsign(call: string): boolean {
  return BASE.test(call) && /[A-Z]/.test(call) && call.length <= 10;
}

const GRID = /^[A-R]{2}[0-9]{2}([A-X]{2}([0-9]{2})?)?$/i;

export function isValidGrid(g: string): boolean {
  return GRID.test(g);
}
