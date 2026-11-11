import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import LoginPage from "@/app/(auth)/login/page";

const replace = vi.fn();
vi.mock("next/navigation", () => ({ useRouter: () => ({ replace, push: vi.fn() }), useSearchParams: () => new URLSearchParams() }));

describe("sign-in flow", () => {
  it("validates before calling the API", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    render(<LoginPage />);
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("Enter a valid email address")).toBeInTheDocument();
    expect(screen.getByText("Enter your password")).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("shows the server error on bad credentials and stays on the page", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { code: "unauthorized", message: "Invalid email or password" } }), { status: 401 })));
    render(<LoginPage />);
    await userEvent.type(screen.getByLabelText("Email"), "a@acme.test");
    await userEvent.type(screen.getByLabelText("Password"), "wrong-password");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("Invalid email or password")).toBeInTheDocument();
    expect(replace).not.toHaveBeenCalled();
  });

  it("asks for a verification code when MFA is required, then signs in", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ mfa_required: true, csrf_token: "c1" }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ mfa_required: false, csrf_token: "c2" }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    render(<LoginPage />);
    await userEvent.type(screen.getByLabelText("Email"), "a@acme.test");
    await userEvent.type(screen.getByLabelText("Password"), "Correct-Horse-Battery-9");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await userEvent.type(await screen.findByLabelText("Verification code"), "123456");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() => expect(replace).toHaveBeenCalledWith("/overview"));
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toMatchObject({ email: "a@acme.test", totp_code: "123456" });
    expect(window.sessionStorage.getItem("ctem.csrf")).toBe("c2");
  });
});
