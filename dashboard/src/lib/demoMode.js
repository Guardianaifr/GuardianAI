/**
 * Single source of truth for explicit Demo Mode detection.
 * Only the search parameter '?demo=true' activates demo mode,
 * preventing hash-router collisions when navigating tabs.
 */
export function isDemoModeActive() {
  if (typeof window === 'undefined') return false;
  try {
    const params = new URLSearchParams(window.location.search);
    return params.get('demo') === 'true';
  } catch {
    return false;
  }
}
