import type { DelegationChain, DelegationIdentity } from "@dfinity/identity";

import type { ActorSubclass } from "@dfinity/agent";
import type { IDENTITY_SERVICE } from "./service.interface";

export type PrepareLoginStatus = "error" | "preparing" | "success" | "idle";
export type LoginStatus = "error" | "logging-in" | "success" | "idle";
export type AnonymousActor = ActorSubclass<IDENTITY_SERVICE>;

export type State = {
  anonymousActor?: AnonymousActor;
  isInitializing: boolean;
  prepareLoginStatus: PrepareLoginStatus;
  prepareLoginError?: Error;
  loginStatus: LoginStatus;
  loginError?: Error;
  identity?: DelegationIdentity;
  identityId?: string;
  delegationChain?: DelegationChain;
};
