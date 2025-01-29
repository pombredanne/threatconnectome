import { render, screen } from "@testing-library/react";
import userEvent, { PointerEventsCheckLevel } from "@testing-library/user-event";
import React from "react";
import { Provider } from "react-redux";
import { BrowserRouter } from "react-router-dom";
import { useSendPasswordResetEmailMutation } from "../../../services/firebaseApi";
import { store } from "../../../store";
import { ResetPassword } from "../ResetPasswordPage";

const sendPasswordResetEmailMock = vi.fn();

vi.mock("../../../services/firebaseApi", async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    useSendPasswordResetEmailMutation: vi.fn(() => [sendPasswordResetEmailMock, {}]),
  };
});

const renderResetPassword = () => {
  render(
    <Provider store={store}>
      <BrowserRouter>
        <ResetPassword />
      </BrowserRouter>
    </Provider>,
  );
};

describe("ResetPassword Component", () => {
  describe("Rendering", () => {
    it("should render ResetPassword form", () => {
      renderResetPassword();
      console.log(store.getState());
      expect(screen.getByRole("textbox", { name: /email address/i })).toBeInTheDocument();
      expect(screen.getByRole("button", { name: /reset password/i })).toBeInTheDocument();
      expect(screen.getByText("Back to log in")).toBeInTheDocument();
    });
  });

  it("should call firebase API with correct parameters", async () => {
    const ue = userEvent.setup({ pointerEventsCheck: PointerEventsCheckLevel.Never });
    const sendPasswordResetEmailMock = vi.fn();

    vi.mocked(useSendPasswordResetEmailMutation).mockReturnValue([sendPasswordResetEmailMock]);

    renderResetPassword();

    sendPasswordResetEmailMock.mockResolvedValue();

    const emailField = screen.getByRole("textbox", { name: /email address/i });
    const resetButton = screen.getByRole("button", { name: /reset password/i });

    await ue.type(emailField, "test@example.com");
    await ue.click(resetButton);

    expect(sendPasswordResetEmailMock).toHaveBeenCalledWith({
      email: "test@example.com",
      actionCodeSettings: expect.any(Object),
    });

    expect(
      screen.getByText("An email with a password reset URL was sent to this address."),
    ).toBeInTheDocument();
  });

  describe("Form Submission", () => {
    // api成功時にメッセージ表示されることの検証
    it("should submit form and show success message when email is sent", async () => {
      const ue = userEvent.setup({ pointerEventsCheck: PointerEventsCheckLevel.Never });
      const sendPasswordResetEmailMock = vi.fn();
      vi.mocked(useSendPasswordResetEmailMutation).mockReturnValue([sendPasswordResetEmailMock]);

      renderResetPassword();

      sendPasswordResetEmailMock.mockResolvedValue();

      const emailField = screen.getByRole("textbox", { name: /email address/i });
      const resetButton = screen.getByRole("button", { name: /reset password/i });

      await ue.type(emailField, "test@example.com");
      await ue.click(resetButton);

      expect(
        screen.getByText("An email with a password reset URL was sent to this address."),
      ).toBeInTheDocument();
      expect(sendPasswordResetEmailMock).toHaveBeenCalledWith({
        email: "test@example.com",
        actionCodeSettings: expect.any(Object),
      });
    });
  });

  describe("Error Handling", () => {
    // api失敗時にエラーメッセージ表示されることの検証
    it("should show error message when email is invalid", async () => {
      const ue = userEvent.setup({ pointerEventsCheck: PointerEventsCheckLevel.Never });
      const sendPasswordResetEmailMock = vi.fn();
      vi.mocked(useSendPasswordResetEmailMutation).mockReturnValue([sendPasswordResetEmailMock]);

      sendPasswordResetEmailMock.mockRejectedValue({ code: "auth/invalid-email" });

      renderResetPassword();

      const emailField = screen.getByRole("textbox", { name: /email address/i });
      const resetButton = screen.getByRole("button", { name: /reset password/i });

      await ue.type(emailField, "invalid-email");
      await ue.click(resetButton);

      expect(screen.getByText("Invalid email format.")).toBeInTheDocument();
    });

    it("should show error message when user does not exist", async () => {
      const ue = userEvent.setup({ pointerEventsCheck: PointerEventsCheckLevel.Never });
      const sendPasswordResetEmailMock = vi.fn();
      vi.mocked(useSendPasswordResetEmailMutation).mockReturnValue([sendPasswordResetEmailMock]);

      sendPasswordResetEmailMock.mockRejectedValue({ code: "auth/user-not-found" });

      renderResetPassword();

      const emailField = screen.getByRole("textbox", { name: /email address/i });
      const resetButton = screen.getByRole("button", { name: /reset password/i });

      await ue.type(emailField, "nonexistentuser@example.com");
      await ue.click(resetButton);

      expect(screen.getByText("User does not exist. Check the email address.")).toBeInTheDocument();
    });
  });

  describe("Form Validation", () => {
    //Email address未入力時、Reset Passwordボタン無効であることの検証
    it("should disable the Reset Password button when the email input is empty", async () => {
      const ue = userEvent.setup({ pointerEventsCheck: PointerEventsCheckLevel.Never });

      renderResetPassword();

      const emailField = screen.getByRole("textbox", { name: /email address/i });
      const resetButton = screen.getByRole("button", { name: /reset password/i });

      expect(resetButton).toBeDisabled();

      await ue.type(emailField, "test@example.com");

      expect(resetButton).toBeEnabled();

      await ue.clear(emailField);
      expect(resetButton).toBeDisabled();
    });
  });
});
