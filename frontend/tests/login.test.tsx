import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import LoginPage from "@/app/(auth)/login/page";

const replace = vi.fn();
vi.mock("next/navigation", () => ({ useRouter: () => ({ replace, push: vi.fn() }), useSearchParams: () => new URLSearchParams() }));

// The page also asks /api/v1/demo whether this is a demo deployment; answer "no" unless a test says otherwise.
function stubFetch(handler: (...args: unknown[]) => unknown, demo: unknown = null) {
  vi.stubGlobal("fetch", (url: string, init?: RequestInit) =>
    String(url).includes("/api/v1/demo")
      ? Promise.resolve(new Response(JSON.stringify(demo ?? { error: { code: "not_found", message: "Not found" } }), { status: demo ? 200 : 404 }))
      : handler(url, init));
}

describe("sign-in flow", () => {
  it("validates before calling the API", async () => {
    const fetchMock = vi.fn();
    stubFetch(fetchMock);
    render(<LoginPage />);
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByText("Enter a valid email address")).toBeInTheDocument();
    expect(screen.getByText("Enter your password")).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("shows the server error on bad credentials and stays on the page", async () => {
    stubFetch(vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: { code: "unauthorized", message: "Invalid email or password" } }), { status: 401 })));
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
    stubFetch(fetchMock);
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

  it("lists the demo accounts and signs in with one click on a demo deployment", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ mfa_required: false, csrf_token: "c" }), { status: 200 }));
    stubFetch(fetchMock, { password: "Demo-pass-123!", restrictions: ["Data resets"],
                           accounts: [{ role: "auditor", email: "auditor@demo.example.com", name: "Demo Auditor", purpose: "Read" }] });
    render(<LoginPage />);
    expect(await screen.findByText("auditor@demo.example.com")).toBeInTheDocument();
    expect(screen.queryByText("Create an account")).not.toBeInTheDocument();
    await userEvent.click(screen.getAllByRole("button", { name: "Sign in" })[1]);
    await waitFor(() => expect(replace).toHaveBeenCalledWith("/overview"));
    expect(JSON.parse(String((fetchMock.mock.calls[0][1] as RequestInit).body))).toMatchObject({ email: "auditor@demo.example.com", password: "Demo-pass-123!" });
  });
});
