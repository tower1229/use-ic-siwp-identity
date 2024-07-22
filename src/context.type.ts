import { DelegationChain, DelegationIdentity } from "@dfinity/identity";
import type {
  LoginStatus,
  PrepareLoginStatus,
  AnonymousActor,
} from "./state.type";

export type IdentityLoginResponse = {
  identity?: DelegationIdentity;
  username: string;
  webauthnResponse: string;
  authenticationState?: string;
};

export type IdentityContextType = {
  anonymousActor?: AnonymousActor;
  /** Is set to `true` on mount until a stored identity is loaded from local storage or
   * none is found. */
  isInitializing: boolean;

  /** Reflects the current status of the prepareLogin process. */
  prepareLoginStatus: PrepareLoginStatus;

  /** `prepareLoginStatus === "loading"` */
  isPreparingLogin: boolean;

  /** `prepareLoginStatus === "error"` */
  isPrepareLoginError: boolean;

  /** `prepareLoginStatus === "success"` */
  isPrepareLoginSuccess: boolean;

  /** `prepareLoginStatus === "idle"` */
  isPrepareLoginIdle: boolean;

  /** Error that occurred during the prepareLogin process. */
  prepareLoginError?: Error;

  /** Initiates the login process by passkey authentication. */
  login: (
    uid?: string,
    JUST_PASSKEY?: boolean
  ) => Promise<IdentityLoginResponse>;

  /** Reflects the current status of the login process. */
  loginStatus: LoginStatus;

  /** `loginStatus === "logging-in"` */
  isLoggingIn: boolean;

  /** `loginStatus === "error"` */
  isLoginError: boolean;

  /** `loginStatus === "success"` */
  isLoginSuccess: boolean;

  /** `loginStatus === "idle"` */
  isLoginIdle: boolean;

  /** Error that occurred during the login process. */
  loginError?: Error;

  /** The delegation chain is available after successfully loading the identity from local
   * storage or completing the login process. */
  delegationChain?: DelegationChain;

  /** The identity is available after successfully loading the identity from local storage
   * or completing the login process. */
  identity?: DelegationIdentity;

  /** The uid with current identity. */
  identityId?: string;

  /** Clears the identity from the state and local storage. Effectively "logs the user out". */
  clear: () => void;
};
