/* eslint-disable react-refresh/only-export-components */
import {
  createContext,
  useContext,
  type ReactNode,
  useEffect,
  useState,
  useRef,
} from "react";
import {
  type ActorConfig,
  type HttpAgentOptions,
  type DerEncodedPublicKey,
} from "@dfinity/agent";
import { DelegationIdentity, Ed25519KeyIdentity } from "@dfinity/identity";
import type {
  IdentityContextType,
  IdentityLoginResponse,
} from "./context.type";
import { IDL } from "@dfinity/candid";
import type {
  PublicKey,
  BindingDelegationDeatils,
  SignedDelegation as ServiceSignedDelegation,
} from "./service.interface";
import { clearIdentity, loadIdentity, saveIdentity } from "./local-storage";
import {
  callGetDelegation,
  callLogin,
  createAnonymousActor,
  callPrepareLogin,
} from "./siwp-provider";
import type { State, AnonymousActor } from "./state.type";
import { createDelegationChain } from "./delegation";
import { normalizeError } from "./error";

/**
 * Re-export types
 */
export * from "./context.type";
export * from "./service.interface";
export * from "./storage.type";
export * from "./local-storage";
export * from "./delegation";
export * from "./state.type";
/**
 * React context for managing SIWP (Sign-In with Passkey) identity.
 */
export const IdentityContext = createContext<IdentityContextType | undefined>(
  undefined
);

/**
 * Hook to access the IdentityContext.
 */
export const useIcIdentity = (): IdentityContextType => {
  const context = useContext(IdentityContext);
  if (!context) {
    throw new Error("useIcIdentity must be used within an IdentityProvider");
  }
  return context;
};

/**
 * Provider component for the SIWP identity context. Manages identity state and provides authentication-related functionalities.
 *
 * @prop {IDL.InterfaceFactory} idlFactory - Required. The Interface Description Language (IDL) factory for the canister. This factory is used to create an actor interface for the canister.
 * @prop {string} canisterId - Required. The unique identifier of the canister on the Internet Computer network. This ID is used to establish a connection to the canister.
 * @prop {HttpAgentOptions} httpAgentOptions - Optional. Configuration options for the HTTP agent used to communicate with the Internet Computer network.
 * @prop {ActorConfig} actorOptions - Optional. Configuration options for the actor. These options are passed to the actor upon its creation.
 * @prop {ReactNode} children - Required. The child components that the IdentityProvider will wrap. This allows any child component to access the authentication context provided by the IdentityProvider.
 *
 * @example
 * ```tsx
 * import { IdentityProvider } from 'useIcIdentity';
 * import {canisterId, idlFactory} from "path-to/siwp-enabled-canister/index";
 *
 * function App() {
 *   return (
 *     <IdentityProvider
 *       idlFactory={idlFactory}
 *       canisterId={canisterId}
 *       // ...other props
 *     >
 *       {... your app components}
 *     </App>
 *   );
 * }
 *
 *```
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export function IdentityProvider({
  httpAgentOptions,
  actorOptions,
  idlFactory,
  canisterId,
  isLocalNetwork,
  children,
}: {
  /** Configuration options for the HTTP agent used to communicate with the Internet Computer network. */
  httpAgentOptions?: HttpAgentOptions;

  /** Configuration options for the actor. These options are passed to the actor upon its creation. */
  actorOptions?: ActorConfig;

  /** The Interface Description Language (IDL) factory for the canister. This factory is used to create an actor interface for the canister. */
  idlFactory: IDL.InterfaceFactory;

  /** The unique identifier of the canister on the Internet Computer network. This ID is used to establish a connection to the canister. */
  canisterId: string;

  /**
   * If true, the provider will use the local network instead of the main network.
   * This is useful for testing purposes.
   */
  isLocalNetwork?: boolean;
  /** The child components that the IdentityProvider will wrap. This allows any child component to access the authentication context provided by the IdentityProvider. */
  children: ReactNode;
}) {
  const [state, setState] = useState<State>({
    isInitializing: true,
    prepareLoginStatus: "idle",
    loginStatus: "idle",
  });

  function updateState(newState: Partial<State>) {
    setState((prevState) => ({ ...prevState, ...newState }));
    // state = { ...state, ...newState };
  }

  // Keep track of the promise handlers for the login method during the async login process.
  const loginPromiseHandlers = useRef<{
    resolve: (
      value: IdentityLoginResponse | PromiseLike<IdentityLoginResponse>
    ) => void;
    reject: (error: Error) => void;
  } | null>(null);

  // Keep track of the promise handlers for the login method during the async login process.
  const loginWithPublicKeyPromiseHandlers = useRef<{
    resolve: (
      value: BindingDelegationDeatils | PromiseLike<BindingDelegationDeatils>
    ) => void;
    reject: (error: Error) => void;
  } | null>(null);

  async function rejectLoginWithError(
    error: Error | unknown,
    message?: string
  ) {
    const e = normalizeError(error);
    const errorMessage = message || e.message;

    console.error(e);

    updateState({
      loginStatus: "error",
      loginError: new Error(errorMessage),
    });

    loginPromiseHandlers.current?.reject(new Error(errorMessage));
  }

  /**
   * This function is called when the webauthn hook has settled, that is, when the
   * user has auth the challenge or canceled the signing process.
   */
  async function onWebauthnSettled(
    anonymousActor: AnonymousActor,
    webauthnResponse: string,
    authenticationState?: string,
    username?: string,
    customSessionPublicKey?: DerEncodedPublicKey
  ) {
    if (!anonymousActor) {
      rejectLoginWithError(new Error("Invalid actor or address."));
      return;
    }

    let loginOkResponse: BindingDelegationDeatils;

    if (customSessionPublicKey) {
      try {
        loginOkResponse = await callLogin(
          anonymousActor,
          webauthnResponse,
          customSessionPublicKey,
          authenticationState,
          username
        );
      } catch (e) {
        console.warn(e, customSessionPublicKey);
        rejectLoginWithError(e, "Login error with customSessionPublicKey.");
        return;
      }

      loginWithPublicKeyPromiseHandlers?.current?.resolve(loginOkResponse);
    } else {
      // Important for security! A random session identity is created on each login.
      const sessionIdentity = Ed25519KeyIdentity.generate();
      const sessionPublicKey = sessionIdentity.getPublicKey().toDer();

      // Logging in is a two-step process. First, the signed SIWP message is sent to the backend.
      // Then, the backend's siwp_get_delegation method is called to get the delegation.

      try {
        loginOkResponse = await callLogin(
          anonymousActor,
          webauthnResponse,
          sessionPublicKey,
          authenticationState,
          username
        );
      } catch (e) {
        rejectLoginWithError(e, "Unable to login.");
        return;
      }

      const response = await getDelegation(
        loginOkResponse.username,
        sessionPublicKey,
        sessionIdentity,
        loginOkResponse.login_details.expiration,
        loginOkResponse.login_details.user_canister_pubkey
      ).catch((e) => {
        rejectLoginWithError(e);
        return;
      });

      response && loginPromiseHandlers?.current?.resolve(response);
    }
  }

  /**
   * Call the backend's siwp_get_delegation method to get the delegation.
   */
  async function getDelegation(
    identityId: string,
    sessionPublicKey: DerEncodedPublicKey,
    sessionIdentity: Ed25519KeyIdentity,
    expiration: bigint,
    user_canister_pubkey: PublicKey
  ) {
    if (!state.anonymousActor) {
      throw new Error(
        "Hook not initialized properly. Make sure to supply all required props to the IdentityProvider."
      );
    }

    // Logging in is a two-step process. First, the signed SIWP message is sent to the backend.
    // Then, the backend's siwp_get_delegation method is called to get the delegation.

    // Call the backend's siwp_get_delegation method to get the delegation.
    let signedDelegation: ServiceSignedDelegation;
    try {
      signedDelegation = await callGetDelegation(
        state.anonymousActor,
        identityId,
        sessionPublicKey,
        expiration
      );
    } catch (e) {
      throw new Error("Unable to get identity.");
    }

    // Create a new delegation chain from the delegation.
    const delegationChain = createDelegationChain(
      signedDelegation,
      user_canister_pubkey
    );

    // Create a new delegation identity from the session identity and the
    // delegation chain.
    const identity = DelegationIdentity.fromDelegation(
      sessionIdentity,
      delegationChain
    );

    // Save the identity to local storage.
    saveIdentity(identityId, sessionIdentity, delegationChain);

    // Set the identity in state.
    updateState?.({
      loginStatus: "success",
      identityId,
      identity,
      delegationChain,
      identityActor: createAnonymousActor({
        idlFactory,
        canisterId,
        httpAgentOptions: { ...(httpAgentOptions || {}), identity },
        actorOptions,
        isLocalNetwork,
      }),
    });

    return {
      identity,
      username: identityId,
    };
  }

  /**
   * Initiates the login process.
   *
   * @returns {void} Login does not return anything. If an error occurs, the error is available in
   * the loginError property.
   */

  async function login(loginUid?: string) {
    const promise = new Promise<IdentityLoginResponse>((resolve, reject) => {
      loginPromiseHandlers.current = { resolve, reject };
    });
    // Set the promise handlers immediately to ensure they are available for error handling.

    if (!state.anonymousActor) {
      rejectLoginWithError(
        new Error(
          "Hook not initialized properly. Make sure to supply all required props to the IdentityProvider."
        )
      );
      return promise;
    }

    if (state.prepareLoginStatus === "preparing") {
      rejectLoginWithError(
        new Error("Don't call login while prepareLogin is running.")
      );
      return promise;
    }

    updateState({
      loginStatus: "logging-in",
      loginError: undefined,
    });

    updateState({
      prepareLoginStatus: "preparing",
      prepareLoginError: undefined,
    });

    let webauthnResponse: string = "";
    let authenticationState: string = "";

    try {
      const _prepareLoginResponse = await callPrepareLogin(
        state.anonymousActor,
        loginUid
      );

      if (loginUid && typeof _prepareLoginResponse === "string") {
        webauthnResponse = _prepareLoginResponse;

        updateState({
          prepareLoginStatus: "success",
        });
      } else if (
        Array.isArray(_prepareLoginResponse) &&
        _prepareLoginResponse[0] &&
        _prepareLoginResponse[1]
      ) {
        webauthnResponse = _prepareLoginResponse[0];
        authenticationState = _prepareLoginResponse[1];

        updateState({
          prepareLoginStatus: "success",
        });
      } else {
        throw new Error("Invalid authentication response");
      }
    } catch (e) {
      const error = normalizeError(e);
      console.error(error);
      updateState({
        prepareLoginStatus: "error",
        prepareLoginError: error,
      });

      rejectLoginWithError(error || new Error("Unable to login."));
      return promise;
    }

    await onWebauthnSettled(
      state.anonymousActor,
      webauthnResponse,
      authenticationState,
      loginUid
    );

    return promise;
  }

  /**
   * Initiates the loginWithSessionKey process.
   *
   * @returns {void} Login does not return anything. If an error occurs, the error is available in
   * the loginError property.
   */

  async function loginWithSessionKey(
    sessionPublicKey: DerEncodedPublicKey,
    loginUid?: string
  ) {
    const promise = new Promise<BindingDelegationDeatils>((resolve, reject) => {
      loginWithPublicKeyPromiseHandlers.current = { resolve, reject };
    });
    // Set the promise handlers immediately to ensure they are available for error handling.

    if (!state.anonymousActor) {
      rejectLoginWithError(
        new Error(
          "Hook not initialized properly. Make sure to supply all required props to the IdentityProvider."
        )
      );
      return promise;
    }

    if (state.prepareLoginStatus === "preparing") {
      rejectLoginWithError(
        new Error("Don't call login while prepareLogin is running.")
      );
      return promise;
    }

    updateState({
      loginStatus: "logging-in",
      loginError: undefined,
    });

    updateState({
      prepareLoginStatus: "preparing",
      prepareLoginError: undefined,
    });

    let webauthnResponse: string = "";
    let authenticationState: string = "";

    try {
      const _prepareLoginResponse = await callPrepareLogin(
        state.anonymousActor,
        loginUid
      );

      if (loginUid && typeof _prepareLoginResponse === "string") {
        webauthnResponse = _prepareLoginResponse;

        updateState({
          prepareLoginStatus: "success",
        });
      } else if (
        Array.isArray(_prepareLoginResponse) &&
        _prepareLoginResponse[0] &&
        _prepareLoginResponse[1]
      ) {
        webauthnResponse = _prepareLoginResponse[0];
        authenticationState = _prepareLoginResponse[1];

        updateState({
          prepareLoginStatus: "success",
        });
      } else {
        throw new Error("Invalid authentication response");
      }
    } catch (e) {
      const error = normalizeError(e);
      console.error(error);
      updateState({
        prepareLoginStatus: "error",
        prepareLoginError: error,
      });

      rejectLoginWithError(error || new Error("Unable to login."));
      return promise;
    }

    await onWebauthnSettled(
      state.anonymousActor,
      webauthnResponse,
      authenticationState,
      loginUid,
      sessionPublicKey
    );

    return promise;
  }

  /**
   * Clears the state and local storage. Effectively "logs the user out".
   */
  function clear() {
    updateState({
      isInitializing: false,
      prepareLoginStatus: "idle",
      prepareLoginError: undefined,
      loginStatus: "idle",
      loginError: undefined,
      identity: undefined,
      identityId: undefined,
      delegationChain: undefined,
      identityActor: undefined,
    });
    clearIdentity();
  }

  /**
   * Load the identity from local storage on mount.
   */
  useEffect(() => {
    try {
      const [a, i, d] = loadIdentity();
      updateState({
        identityId: a,
        identity: i,
        delegationChain: d,
        isInitializing: false,
        identityActor: createAnonymousActor({
          idlFactory,
          canisterId,
          httpAgentOptions: { ...(httpAgentOptions || {}), identity: i },
          actorOptions,
          isLocalNetwork,
        }),
      });
    } catch (e) {
      if (e instanceof Error) {
        console.log("Could not load identity from local storage: ", e.message);
      }
      updateState({
        isInitializing: false,
      });
    }
  }, []);

  /**
   * Create an anonymous actor on mount. This actor is used during the login
   * process.
   */
  useEffect(() => {
    const a = createAnonymousActor({
      idlFactory,
      canisterId,
      httpAgentOptions,
      actorOptions,
      isLocalNetwork,
    });
    updateState({
      anonymousActor: a,
    });
  }, [idlFactory, canisterId, httpAgentOptions, actorOptions, isLocalNetwork]);

  return (
    <IdentityContext.Provider
      value={{
        ...state,
        isPreparingLogin: state.prepareLoginStatus === "preparing",
        isPrepareLoginError: state.prepareLoginStatus === "error",
        isPrepareLoginSuccess: state.prepareLoginStatus === "success",
        isPrepareLoginIdle: state.prepareLoginStatus === "idle",
        login,
        loginWithSessionKey,
        getDelegation,
        isLoggingIn: state.loginStatus === "logging-in",
        isLoginError: state.loginStatus === "error",
        isLoginSuccess: state.loginStatus === "success",
        isLoginIdle: state.loginStatus === "idle",
        clear,
      }}
    >
      {children}
    </IdentityContext.Provider>
  );
}
