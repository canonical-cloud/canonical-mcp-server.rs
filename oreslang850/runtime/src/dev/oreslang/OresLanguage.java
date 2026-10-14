package dev.oreslang;
/** CI-only linker shim: full Truffle language launcher is not required to run
 * isolated ActorRuntime/JUnit transport tests; mirrors OresLanguage.ID only. */
public final class OresLanguage {
    private OresLanguage() {}
    public static final String ID = "ores";
}
