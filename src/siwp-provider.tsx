import {
  HttpAgent,
  type ActorConfig,
  type HttpAgentOptions,
  Actor,
  type DerEncodedPublicKey,
  type ActorSubclass,
} from "@dfinity/agent";
import type { IDL } from "@dfinity/candid";
import type { IDENTITY_SERVICE } from "./service.interface";
import { startAuthentication } from "@simplewebauthn/browser";

/**
 * Creates an anonymous actor for interactions with the Internet Computer.
 * This is used primarily for the initial authentication process.
 */
export function createAnonymousActor({
  idlFactory,
  canisterId,
  httpAgentOptions,
  actorOptions,
  isLocalNetwork,
}: {
  idlFactory: IDL.InterfaceFactory;
  canisterId: string;
  httpAgentOptions?: HttpAgentOptions;
  actorOptions?: ActorConfig;
  isLocalNetwork?: boolean;
}) {
  if (!idlFactory || !canisterId) return;
  const agent = new HttpAgent({ retryTimes: 2, ...httpAgentOptions });

  if (isLocalNetwork) {
    agent.fetchRootKey().catch((err) => {
      console.warn(
        "Unable to fetch root key. Check to ensure that your local replica is running"
      );
      console.error(err);
    });
  }
  return Actor.createActor<IDENTITY_SERVICE>(idlFactory, {
    agent,
    canisterId,
    ...actorOptions,
  });
}

export async function callPrepareLogin(
  anonymousActor: ActorSubclass<IDENTITY_SERVICE>,
  username?: string
) {
  if (!anonymousActor) {
    throw new Error("Invalid actor");
  }

  const response =
    username !== undefined
      ? await anonymousActor.siwp_prepare_login_username(username)
      : await anonymousActor.siwp_prepare_login();

  if (!Array.isArray(response) && !response) {
    throw new Error("Invalid prepare response");
  }

  // webauthn
  const webauthnConfig = Array.isArray(response) ? response[0] : response;
  const authOptions = JSON.parse(webauthnConfig).publicKey;
  // step 2
  const asseResp = await startAuthentication({
    ...authOptions,
  }).catch(() => {
    throw new Error(`Webauthn fail`);
  });

  return Array.isArray(response)
    ? [JSON.stringify(asseResp), response[1]]
    : JSON.stringify(asseResp);
}

/**
 * Logs in the user by sending a signed SIWP message to the backend.
 */
export async function callLogin(
  anonymousActor: ActorSubclass<IDENTITY_SERVICE>,
  webauthnResponse: string,
  sessionPublicKey: DerEncodedPublicKey,
  authenticationState?: string,
  username?: string,
  expiration?: number
) {
  if (!anonymousActor) {
    throw new Error("Invalid actor");
  }

  let loginReponse;
  try {
    loginReponse =
      username === undefined && authenticationState
        ? await anonymousActor.siwp_login(
            webauthnResponse,
            authenticationState,
            new Uint8Array(sessionPublicKey),
            !expiration ? [] : [BigInt(expiration * 1000000)]
          )
        : await anonymousActor.siwp_login_username(
            webauthnResponse,
            new Uint8Array(sessionPublicKey),
            !expiration ? [] : [BigInt(expiration * 1000000)]
          );
  } catch (e) {
    throw new Error((e as Error).message);
  }

  if ("Err" in loginReponse) {
    throw new Error(loginReponse.Err);
  }

  return loginReponse.Ok;
}

/**
 * Retrieves a delegation from the backend for the current session.
 */
export async function callGetDelegation(
  anonymousActor: ActorSubclass<IDENTITY_SERVICE>,
  username: string | undefined,
  sessionPublicKey: DerEncodedPublicKey,
  expiration: bigint
) {
  if (!anonymousActor || !username) {
    throw new Error("Invalid actor or username");
  }

  const response = await anonymousActor.siwp_get_delegation(
    username,
    new Uint8Array(sessionPublicKey),
    expiration
  );

  if ("Err" in response) {
    throw new Error(response.Err);
  }

  return response.Ok;
}
