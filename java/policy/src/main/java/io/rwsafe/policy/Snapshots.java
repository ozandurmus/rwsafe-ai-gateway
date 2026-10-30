package io.rwsafe.policy;

import io.rwsafe.platform.verdict.DataClass;
import java.util.List;
import java.util.Map;

/** Snapshot sources available before the registry exists. */
public final class Snapshots {

    private Snapshots() {
    }

    /**
     * The built-in development snapshot: secrets block, customer identifiers are redacted (Q-7: they never reach an
     * external model), and the AI-category flow is fail-closed. Platform rows follow PLATFORM_MATRIX §2 (vendor-published
     * endpoints only).
     */
    public static PolicySnapshot builtinDevelopment() {
        return new PolicySnapshot(1, "builtin-development", Map.of(
            DataClass.SECRET, Action.BLOCK,
            DataClass.TCKN, Action.REDACT,
            DataClass.TR_IBAN, Action.REDACT,
            DataClass.PAYMENT_CARD, Action.REDACT), true, List.of(
            new PlatformRule("claude", List.of("claude.ai", "anthropic.com"), List.of("api.anthropic.com"), List.of()),
            new PlatformRule("copilot", List.of("githubcopilot.com", "copilot-proxy.githubusercontent.com"),
                List.of("api.githubcopilot.com", "copilot-proxy.githubusercontent.com"), List.of()),
            new PlatformRule("github", List.of("github.com"), List.of("api.github.com"), List.of()),
            new PlatformRule("openai", List.of("chatgpt.com", "openai.com"), List.of("api.openai.com"),
                List.of("auth.openai.com")),
            new PlatformRule("devin", List.of("devin.ai"), List.of("api.devin.ai"), List.of()),
            new PlatformRule("windsurf", List.of("windsurf.com", "codeium.com"), List.of("server.codeium.com"), List.of()),
            new PlatformRule("gemini", List.of("gemini.google.com", "generativelanguage.googleapis.com",
                "cloudcode-pa.googleapis.com", "aiplatform.googleapis.com"),
                List.of("generativelanguage.googleapis.com", "cloudcode-pa.googleapis.com", "aiplatform.googleapis.com"),
                List.of()),
            new PlatformRule("google-auth", List.of("accounts.google.com", "oauth2.googleapis.com"), List.of(),
                List.of("accounts.google.com", "oauth2.googleapis.com")),
            new PlatformRule("microsoft-auth", List.of("login.microsoftonline.com", "login.microsoft.com",
                "login.windows.net", "login.live.com"), List.of(), List.of("login.microsoftonline.com",
                "login.microsoft.com", "login.windows.net", "login.live.com"))));
    }
}
