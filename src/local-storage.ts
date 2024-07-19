import {
  DelegationChain,
  DelegationIdentity,
  Ed25519KeyIdentity,
} from "@dfinity/identity";

import type { SiweIdentityStorage } from "./storage.type";

export const SIWP_STORAGE_KEY = "siwp-identity";

/**
 * Loads the SIWP identity from local storage.
 */
export function loadIdentity() {
  const storedState = localStorage.getItem(SIWP_STORAGE_KEY);

  if (!storedState) {
    throw new Error("No stored identity found.");
  }

  const s: SiweIdentityStorage = JSON.parse(storedState);
  if (!s.uid || !s.sessionIdentity || !s.delegationChain) {
    throw new Error("Stored state is invalid.");
  }

  const d = DelegationChain.fromJSON(JSON.stringify(s.delegationChain));
  const i = DelegationIdentity.fromDelegation(
    Ed25519KeyIdentity.fromJSON(JSON.stringify(s.sessionIdentity)),
    d
  );

  return [s.uid, i, d] as const;
}

/**
 * Saves the SIWP identity to local storage.
 */
export function saveIdentity(
  uid: string,
  sessionIdentity: Ed25519KeyIdentity,
  delegationChain: DelegationChain
) {
  localStorage.setItem(
    SIWP_STORAGE_KEY,
    JSON.stringify({
      uid: uid,
      sessionIdentity: sessionIdentity.toJSON(),
      delegationChain: delegationChain.toJSON(),
    })
  );
}

/**
 * Clears the SIWP identity from local storage.
 */
export function clearIdentity() {
  localStorage.removeItem(SIWP_STORAGE_KEY);
}
