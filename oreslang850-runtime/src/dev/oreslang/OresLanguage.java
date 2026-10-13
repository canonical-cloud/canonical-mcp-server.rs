package dev.oreslang;
/**
 * Isolated Maven verification module only. OresLanguage proper requires Truffle
 * instrumentation; ActorRuntime/IsolatePolicy only needs its language ID.
 * No actor, policy, or transport logic is substituted.
 */
public final class OresLanguage {
    private OresLanguage() {}
    public static final String ID = "ores";
}
