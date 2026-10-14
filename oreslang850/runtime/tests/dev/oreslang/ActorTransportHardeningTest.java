package dev.oreslang;

import dev.oreslang.runtime.ActorRuntime;
import dev.oreslang.runtime.OresMutex;
import org.junit.jupiter.api.Test;

import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

final class ActorTransportHardeningTest {
    /** An enum singleton is NOT necessarily immutable: host code can mutate its fields. */
    private enum MutableHostEnum {
        INSTANCE;
        private final ArrayList<String> mutableState = new ArrayList<>();
    }

    /** Return a different value only after preflight has inspected the list. */
    private static List<Object> changesAfterRead(
            int firstUnsafeRead, Object unsafeValue, AtomicInteger reads) {
        return new AbstractList<>() {
            @Override
            public Object get(int index) {
                if (index != 0) throw new IndexOutOfBoundsException(index);
                return reads.incrementAndGet() >= firstUnsafeRead ? unsafeValue : "safe";
            }

            @Override
            public int size() { return 1; }
        };
    }

    @Test
    void arbitraryHostEnumsCannotCrossActorsByMutableIdentity() {
        assertThrows(IllegalArgumentException.class,
                () -> ActorRuntime.freeze(MutableHostEnum.INSTANCE));
        // Known stateless runtime enum values still have stable representation.
        assertSame(ActorRuntime.ActorKind.PRIVATE,
                ActorRuntime.freeze(ActorRuntime.ActorKind.PRIVATE));

        try (ActorRuntime runtime = new ActorRuntime()) {
            var target = runtime.<Object>spawnPrivate(() -> (message, context) -> { });
            assertThrows(IllegalArgumentException.class,
                    () -> target.send(List.of(MutableHostEnum.INSTANCE)));
        }
    }

    @Test
    void publicFreezeRevalidatesCopiedSnapshotAgainstCapabilityLaundering() {
        try (ActorRuntime runtime = new ActorRuntime()) {
            var liveRef = runtime.<Object>spawnShared(() -> (message, context) -> { });
            AtomicInteger reads = new AtomicInteger();
            List<Object> changing = changesAfterRead(3, liveRef, reads);
            IllegalArgumentException denied = assertThrows(IllegalArgumentException.class,
                    () -> ActorRuntime.freeze(changing));
            assertTrue(denied.getMessage().contains("live actor/shared capabilities"),
                    denied::getMessage);
            assertTrue(reads.get() >= 3, "the live ref must appear during the copy pass");
        }
    }

    @Test
    void untrustedMailboxRevalidatesCopiedCapabilitySnapshot() {
        try (ActorRuntime runtime = new ActorRuntime()) {
            var group = runtime.createActorGroup();
            var joinAuthority = group.joinCapability();
            var target = runtime.<Object>spawnUntrusted(() -> (message, context) -> { });

            AtomicInteger reads = new AtomicInteger();
            List<Object> changing = changesAfterRead(7, joinAuthority, reads);
            SecurityException denied = assertThrows(SecurityException.class,
                    () -> target.send(changing));
            assertTrue(denied.getMessage().contains("live capabilities"),
                    denied::getMessage);
            assertTrue(reads.get() >= 7, "the group authority must appear after preflight");
        }
    }

    @Test
    void privateMailboxRevalidatesForeignActorRefAfterCopy() {
        try (ActorRuntime runtimeA = new ActorRuntime();
             ActorRuntime runtimeB = new ActorRuntime()) {
            var foreignRef = runtimeB.<Object>spawnShared(() -> (message, context) -> { });
            var target = runtimeA.<Object>spawnPrivate(() -> (message, context) -> { });

            AtomicInteger reads = new AtomicInteger();
            List<Object> changing = changesAfterRead(6, foreignRef, reads);
            IllegalArgumentException denied = assertThrows(IllegalArgumentException.class,
                    () -> target.send(changing));
            assertTrue(denied.getMessage().contains("different ActorRuntime"),
                    denied::getMessage);
            assertTrue(reads.get() >= 6, "foreign actor ref must appear after preflight");
        }
    }

    @Test
    void readonlySharedWrapperFreezesBeforePublication() {
        try (ActorRuntime runtime = new ActorRuntime()) {
            ArrayList<String> source = new ArrayList<>(List.of("a"));
            ActorRuntime.Shared<Object> shared = runtime.shareReadonly(source);

            source.add("b");

            assertInstanceOf(List.class, shared.value());
            @SuppressWarnings("unchecked")
            List<String> frozen = (List<String>) shared.value();
            assertEquals(List.of("a"), frozen);
            assertThrows(UnsupportedOperationException.class, () -> frozen.add("c"));
        }
    }

    @Test
    void actorRefsCannotCrossRuntimeCapabilityBoundaries() {
        try (ActorRuntime runtimeA = new ActorRuntime();
             ActorRuntime runtimeB = new ActorRuntime()) {
            var refA = runtimeA.<Object>spawn(() -> (message, context) -> { });
            var targetB = runtimeB.<Object>spawn(() -> (message, context) -> { });

            IllegalArgumentException wrongDestinationRuntime = assertThrows(
                    IllegalArgumentException.class,
                    () -> runtimeB.send(refA, "wrong-runtime"));
            assertTrue(wrongDestinationRuntime.getMessage().contains("different ActorRuntime"));

            IllegalArgumentException direct = assertThrows(
                    IllegalArgumentException.class,
                    () -> targetB.send(refA));
            assertTrue(direct.getMessage().contains("different ActorRuntime"));

            assertThrows(IllegalArgumentException.class, () -> ActorRuntime.freeze(refA));
            assertThrows(IllegalArgumentException.class, () -> runtimeA.shareReadonly(refA));
        }
    }

    @Test
    void cyclicMessageGraphsAreRejectedBeforeStackOverflow() {
        ArrayList<Object> cycle = new ArrayList<>();
        cycle.add(cycle);

        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> ActorRuntime.freeze(cycle));

        assertTrue(error.getMessage().contains("cyclic"));
    }

    @Test
    void excessivelyDeepMessageGraphsAreRejected() {
        Object nested = "leaf";
        for (int i = 0; i < 300; i++) nested = List.of(nested);
        Object tooDeep = nested;

        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> ActorRuntime.freeze(tooDeep));

        assertTrue(error.getMessage().contains("maximum nesting depth"));
    }

    @Test
    void hostileContainerSizeCannotForceEagerAllocation() {
        List<Object> hostile = new AbstractList<>() {
            @Override
            public Object get(int index) {
                throw new AssertionError("oversized container must be rejected before iteration");
            }

            @Override
            public int size() {
                return Integer.MAX_VALUE;
            }
        };

        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> ActorRuntime.freeze(hostile));

        assertTrue(error.getMessage().contains("maximum node count"));
    }

    @Test
    void oversizedMessageGraphsAreRejected() {
        List<Integer> tooManyNodes = Collections.nCopies(100_001, 1);

        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> ActorRuntime.freeze(tooManyNodes));

        assertTrue(error.getMessage().contains("maximum node count"));
    }

    @Test
    void sharedMutexCannotUseGenericFreezeTransport() {
        var shared = OresMutex.shared(new int[]{0});

        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> ActorRuntime.freeze(shared));

        assertTrue(error.getMessage().contains("live actor/shared capabilities"));
    }
    @Test
    void actorMailboxesRejectExecutableAndRawObjectReferencesTransitively() {
        try (ActorRuntime runtime = new ActorRuntime()) {
            var privateRef = runtime.<Object>spawnPrivate(() -> (message, context) -> { });
            var sharedRef = runtime.<Object>spawnShared(() -> (message, context) -> { });

            Runnable executable = () -> { };
            Object rawObject = new Object();

            assertThrows(IllegalArgumentException.class, () -> privateRef.send(executable));
            assertThrows(IllegalArgumentException.class, () -> sharedRef.send(executable));
            assertThrows(IllegalArgumentException.class, () -> privateRef.send(List.of(executable)));
            assertThrows(IllegalArgumentException.class, () -> sharedRef.send(List.of(executable)));

            assertThrows(IllegalArgumentException.class, () -> privateRef.send(rawObject));
            assertThrows(IllegalArgumentException.class, () -> sharedRef.send(rawObject));
            assertThrows(IllegalArgumentException.class, () -> privateRef.send(List.of(rawObject)));
            assertThrows(IllegalArgumentException.class, () -> sharedRef.send(List.of(rawObject)));
        }
    }

    @Test
    void actorStartupFailureDoesNotLeaveUsableRefOrActorQuota() throws Exception {
        try (ActorRuntime runtime = new ActorRuntime()) {
            java.util.concurrent.CountDownLatch attempted = new java.util.concurrent.CountDownLatch(1);

            var ref = runtime.<String>spawnPrivateTrusted(factoryContext -> {
                attempted.countDown();
                throw new IllegalStateException("startup failed");
            });

            ref.send("trigger");
            assertTrue(attempted.await(2, java.util.concurrent.TimeUnit.SECONDS));
            assertTrue(ref.awaitTermination(2, java.util.concurrent.TimeUnit.SECONDS));
            assertFalse(ref.isAlive());
            assertEquals(0, runtime.actorCount());
            assertTrue(ref.failure().isPresent());
            assertEquals("startup failed", ref.failure().orElseThrow().getMessage());
            assertThrows(ActorRuntime.ActorTerminatedException.class, () -> ref.send("after-failure"));
        }
    }


}
