/**
 * Linear-time O(n) iterative wildcard matcher supporting '*' (zero or more chars)
 * and '?' (single char). Avoids dynamic RegExp compilation to eliminate ReDoS vectors.
 */
export function matchesGlob(pattern: string, candidate: string): boolean {
  if (pattern === "*") {
    return true;
  }

  let pIdx = 0;
  let cIdx = 0;
  let lastStarIdx = -1;
  let starMatchIdx = 0;

  while (cIdx < candidate.length) {
    if (
      pIdx < pattern.length &&
      (pattern.charCodeAt(pIdx) === 63 /* '?' */ ||
        pattern.charCodeAt(pIdx) === candidate.charCodeAt(cIdx))
    ) {
      pIdx += 1;
      cIdx += 1;
    } else if (
      pIdx < pattern.length &&
      pattern.charCodeAt(pIdx) === 42 /* '*' */
    ) {
      lastStarIdx = pIdx;
      starMatchIdx = cIdx;
      pIdx += 1;
    } else if (lastStarIdx !== -1) {
      pIdx = lastStarIdx + 1;
      starMatchIdx += 1;
      cIdx = starMatchIdx;
    } else {
      return false;
    }
  }

  while (pIdx < pattern.length && pattern.charCodeAt(pIdx) === 42 /* '*' */) {
    pIdx += 1;
  }

  return pIdx === pattern.length;
}

/**
 * Returns true if `candidate` matches at least one glob pattern in `patterns`.
 */
export function matchesAnyGlob(
  patterns: readonly string[],
  candidate: string
): boolean {
  for (let i = 0; i < patterns.length; i += 1) {
    const pattern = patterns[i];
    if (pattern !== undefined && matchesGlob(pattern, candidate)) {
      return true;
    }
  }
  return false;
}

/**
 * Evaluates whether a caller's assigned roles intersect with a policy rule's role list.
 * Supports '*' wildcard role matching all authenticated principals.
 */
export function matchesRole(
  ruleRoles: readonly string[],
  callerRoles: readonly string[]
): boolean {
  if (ruleRoles.length === 0) {
    return false;
  }

  for (let i = 0; i < ruleRoles.length; i += 1) {
    const requiredRole = ruleRoles[i];
    if (requiredRole === undefined) {
      continue;
    }
    if (requiredRole === "*") {
      return true;
    }
    if (callerRoles.includes(requiredRole)) {
      return true;
    }
  }

  return false;
}
