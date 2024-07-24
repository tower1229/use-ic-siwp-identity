import type { DelegationChain, DelegationIdentity } from "@dfinity/identity";

import type { ActorSubclass } from "@dfinity/agent";
import type { IDENTITY_SERVICE } from "./service.interface";

export type PrepareLoginStatus = "error" | "preparing" | "success" | "idle";
export type LoginStatus = "error" | "logging-in" | "success" | "idle";
export type AnonymousActor = ActorSubclass<IDENTITY_SERVICE>;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type IdentityActor = ActorSubclass<Record<string, any>>;

export type State = {
  anonymousActor?: AnonymousActor;
  identityActor?: IdentityActor;
  isInitializing: boolean;
  prepareLoginStatus: PrepareLoginStatus;
  prepareLoginError?: Error;
  loginStatus: LoginStatus;
  loginError?: Error;
  identity?: DelegationIdentity;
  identityId?: string;
  delegationChain?: DelegationChain;
};
