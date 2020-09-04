import { SecurityService } from "@kaviar/security-bundle";
import { PasswordService } from "@kaviar/password-bundle";
import { RegistrationInput } from "../inputs/RegistrationInput";
import { ChangePasswordInput } from "../inputs/ChangePasswordInput";
import { LoginInput } from "../inputs/LoginInput";
import { ResetPasswordInput } from "../inputs/ResetPasswordInput";
import { ForgotPasswordInput } from "../inputs/ForgotPasswordInput";
import { VerifyEmailInput } from "../inputs/VerifyEmailInput";

export class XPasswordService {
  constructor(
    protected readonly securityService: SecurityService,
    protected readonly passwordService: PasswordService
  ) {}

  /**
   * Registers the user with email as username and
   * @param input
   */
  async register(input: RegistrationInput): Promise<{ token: string }> {
    const userId = await this.securityService.createUser();

    await this.passwordService.attach(userId, {
      username: input.email,
      password: input.password,
    });

    this.securityService.updateUser(userId, {
      isEmailVerified: false,
    });

    return {
      token: await this.securityService.login(userId, {
        authenticationStrategy: this.passwordService.method,
      }),
    };
  }

  async changePassword(input: ChangePasswordInput, userId: any) {
    const isValid = await this.passwordService.isPasswordValid(
      userId,
      input.oldPassword,
      {
        failedAuthenticationAttemptsProcessing: false,
      }
    );

    if (!isValid) {
      throw new Error("Old password was invalid");
    }

    await this.passwordService.setPassword(userId, input.newPassword);
  }

  async login(input: LoginInput): Promise<{ token: string }> {
    const userId = await this.passwordService.findUserIdByUsername(
      input.username
    );
    const isValid = await this.passwordService.isPasswordValid(
      userId,
      input.password
    );

    if (isValid) {
      return {
        token: await this.securityService.login(userId, {
          authenticationStrategy: this.passwordService.method,
        }),
      };
    }
  }

  async logout(input) {
    await this.securityService.logout(input.token);
  }

  async resetPassword(input: ResetPasswordInput) {
    await this.passwordService.resetPassword(
      input.username,
      input.token,
      input.newPassword
    );

    const userId = await this.passwordService.findUserIdByUsername(
      input.username
    );

    return {
      token: await this.securityService.login(userId, {
        authenticationStrategy: this.passwordService.method,
      }),
    };
  }

  async forgotPassword(input: ForgotPasswordInput) {
    const userId = await this.passwordService.findUserIdByUsername(
      input.username
    );

    const token = await this.passwordService.createTokenForPasswordReset(
      userId
    );

    return {
      token,
    };
  }

  async verifyEmail(input: VerifyEmailInput) {
    // TODO:
  }
}
