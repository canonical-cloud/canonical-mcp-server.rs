package dev.oreslang;

import dev.oreslang.runtime.ActorRuntime;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Actual mailbox/runtime copy checks for owned data-only record-shaped maps.
 * Static Oreslang shape matching never upgrades a nominal object to sendable.
 */
final class ActorStructuralRecordTransportTest {
    private static final class ShapedHostObject {
        @SuppressWarnings("unused")
        public final int foo = 3;
    }

    private static LinkedHashMap<String, Object> widerRecord() {
        LinkedHashMap<String, Object> inner = new LinkedHashMap<>();
        inner.put("foo", 3);
        inner.put("extra", "kept");
        LinkedHashMap<String, Object> row = new LinkedHashMap<>();
        row.put("inner", inner);
        row.put("values", new ArrayList<>(List.of(4, 5)));
        row.put("more", true);
        return row;
    }

    @Test
    void freezeKeepsExtraFieldsButDropsAllMutableAliases() {
        var original = widerRecord();
        @SuppressWarnings("unchecked")
        Map<String, Object> frozen = (Map<String, Object>) ActorRuntime.freeze(original);

        @SuppressWarnings("unchecked")
        Map<String, Object> originalInner = (Map<String, Object>) original.get("inner");
        originalInner.put("foo", -1);
        @SuppressWarnings("unchecked")
        List<Integer> originalList = (List<Integer>) original.get("values");
        originalList.add(6);
        original.remove("more");

        @SuppressWarnings("unchecked")
        Map<String, Object> frozenInner = (Map<String, Object>) frozen.get("inner");
        assertEquals(3, frozenInner.get("foo"));
        assertEquals("kept", frozenInner.get("extra"));
        assertEquals(List.of(4, 5), frozen.get("values"));
        assertEquals(true, frozen.get("more"));
        assertThrows(UnsupportedOperationException.class, () -> frozenInner.put("foo", 9));
        assertThrows(UnsupportedOperationException.class, () -> frozen.put("new", 1));
        @SuppressWarnings("unchecked")
        List<Integer> frozenList = (List<Integer>) frozen.get("values");
        assertThrows(UnsupportedOperationException.class, () -> frozenList.add(8));
    }

    @Test
    void privateActorInvocationCopiesNestedOwnedRecords() {
        try (ActorRuntime runtime = new ActorRuntime()) {
            var original = widerRecord();
            Map<String, Object> returned = runtime.invoke(
                    ActorRuntime.ActorKind.PRIVATE,
                    original,
                    (payload, context) -> payload);
            assertNotSame(original, returned);
            @SuppressWarnings("unchecked")
            Map<String, Object> originalInner = (Map<String, Object>) original.get("inner");
            originalInner.put("foo", 22);
            @SuppressWarnings("unchecked")
            Map<String, Object> receivedInner = (Map<String, Object>) returned.get("inner");
            assertEquals(3, receivedInner.get("foo"));
            assertEquals("kept", receivedInner.get("extra"));
            assertThrows(UnsupportedOperationException.class, () -> receivedInner.put("foo", 33));
        }
    }

    @Test
    void matchingPublicFieldOnNominalObjectDoesNotGrantSendability() {
        var nominal = new ShapedHostObject();
        IllegalArgumentException direct = assertThrows(
                IllegalArgumentException.class, () -> ActorRuntime.freeze(nominal));
        assertTrue(direct.getMessage().contains("not Sendable"), direct.getMessage());
        assertThrows(IllegalArgumentException.class, () ->
                ActorRuntime.freeze(Map.of("foo", nominal)));

        try (ActorRuntime runtime = new ActorRuntime()) {
            assertThrows(IllegalArgumentException.class, () -> runtime.invoke(
                    ActorRuntime.ActorKind.PRIVATE,
                    Map.of("foo", nominal),
                    (payload, context) -> "bad"));
        }
    }
}
