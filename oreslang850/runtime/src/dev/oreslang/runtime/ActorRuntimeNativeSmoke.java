package dev.oreslang.runtime;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * CI-only native executable entrypoint. ActorRuntime and all referenced
 * source classes are exact Git-blob copies from PR #850.
 * Not a replacement for native compilation of the entire Oreslang guest VM.
 */
public final class ActorRuntimeNativeSmoke {
    private ActorRuntimeNativeSmoke() { }

    public static void main(String[] args) {
        var nested = new LinkedHashMap<String, Object>();
        nested.put("foo", 3);
        nested.put("extra", new ArrayList<>(List.of("a", "b")));
        var row = new LinkedHashMap<String, Object>();
        row.put("inner", nested);
        @SuppressWarnings("unchecked")
        Map<String, Object> frozen = (Map<String, Object>) ActorRuntime.freeze(row);

        nested.put("foo", -1);
        @SuppressWarnings("unchecked")
        Map<String, Object> inside = (Map<String, Object>) frozen.get("inner");
        if (!Integer.valueOf(3).equals(inside.get("foo"))) {
            throw new AssertionError("actor freeze leaked mutable nested alias");
        }
        boolean immutable = false;
        try {
            inside.put("foo", 0);
        } catch (UnsupportedOperationException expected) {
            immutable = true;
        }
        if (!immutable) throw new AssertionError("frozen record is mutable");

        try (ActorRuntime runtime = new ActorRuntime()) {
            Map<String, Object> reply = runtime.invoke(
                    ActorRuntime.ActorKind.PRIVATE,
                    Map.of("foo", 42),
                    (message, context) -> message);
            if (!Integer.valueOf(42).equals(reply.get("foo"))) {
                throw new AssertionError("private actor invocation lost payload");
            }
            var untrusted = runtime.<Object>spawnUntrusted(
                    actorContext -> (message, context) -> {});
            var join = runtime.createActorGroup().joinCapability();
            boolean denied = false;
            try {
                untrusted.send(Map.of("nested", List.of(Map.of("join", join))));
            } catch (SecurityException expected) {
                denied = true;
            }
            if (!denied) throw new AssertionError("untrusted actor received join authority");
        }
        System.out.println("PASS PR850_ACTOR_NATIVE_SMOKE");
    }
}
