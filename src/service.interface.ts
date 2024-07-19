import type { ActorMethod } from "@dfinity/agent";
import type { Principal } from "@dfinity/principal";

export type Username = string;

export type WebAuthnResponse = string;

export type AuthState = string;

export type CanisterPublicKey = PublicKey;

export type Expiration = [] | [bigint];

export interface Delegation {
  pubkey: PublicKey;
  targets: [] | [Array<Principal>];
  expiration: Timestamp;
}

export type StartAuthResponse = string | [string, string];

export type GetDelegationResponse = { Ok: SignedDelegation } | { Err: string };

export interface BindingDelegationDeatils {
  username: string;
  login_details: LoginDetails;
}

export interface LoginDetails {
  user_canister_pubkey: Uint8Array | number[];
  expiration: bigint;
}

export type LoginResponse = { Ok: BindingDelegationDeatils } | { Err: string };

export type PublicKey = Uint8Array | number[];

export type SessionKey = PublicKey;

export interface SignedDelegation {
  signature: Uint8Array | number[];
  delegation: Delegation;
}

export type Timestamp = bigint;

export interface IDENTITY_SERVICE {
  siwp_prepare_login_username: ActorMethod<[Username], StartAuthResponse>;
  siwp_prepare_login: ActorMethod<[], StartAuthResponse>;
  siwp_login: ActorMethod<
    [WebAuthnResponse, AuthState, SessionKey, Expiration],
    LoginResponse
  >;
  siwp_login_username: ActorMethod<
    [WebAuthnResponse, SessionKey, Expiration],
    LoginResponse
  >;
  siwp_get_delegation: ActorMethod<
    [Username, SessionKey, Timestamp],
    GetDelegationResponse
  >;
}
