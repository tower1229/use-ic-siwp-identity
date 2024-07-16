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

/**
 * Creates an anonymous actor for interactions with the Internet Computer.
 * This is used primarily for the initial authentication process.
 */
export function createAnonymousActor({
  idlFactory,
  canisterId,
  httpAgentOptions,
  actorOptions,
}: {
  idlFactory: IDL.InterfaceFactory;
  canisterId: string;
  httpAgentOptions?: HttpAgentOptions;
  actorOptions?: ActorConfig;
}) {
  if (!idlFactory || !canisterId) return;
  const agent = new HttpAgent({ ...httpAgentOptions });

  if (process.env.DFX_NETWORK !== "ic") {
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

/**
 * Logs in the user by sending a signed SIWP message to the backend.
 */
export async function callLogin(
  anonymousActor: ActorSubclass<IDENTITY_SERVICE>,
  username: string | undefined,
  sessionPublicKey: DerEncodedPublicKey
) {
  if (!anonymousActor || !username) {
    throw new Error("Invalid actor or username");
  }

  const loginReponse = await anonymousActor.siwp_login(
    username,
    new Uint8Array(sessionPublicKey)
  );

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
  address: string | undefined,
  sessionPublicKey: DerEncodedPublicKey,
  expiration: bigint
) {
  if (!anonymousActor || !address) {
    throw new Error("Invalid actor or address");
  }

  const response = await anonymousActor.siwp_get_delegation(
    address,
    new Uint8Array(sessionPublicKey),
    expiration
  );

  if ("Err" in response) {
    throw new Error(response.Err);
  }

  return response.Ok;
}
