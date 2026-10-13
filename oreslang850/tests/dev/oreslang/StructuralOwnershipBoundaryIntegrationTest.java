package dev.oreslang;

import dev.oreslang.parser.Parser;
import dev.oreslang.types.OwnershipChecker;
import dev.oreslang.types.TypeChecker;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Distinguishes immutable owned record data from actual loan provenance. */
final class StructuralOwnershipBoundaryIntegrationTest {
    @Test
    void ownedReadonlyValueIsNotABorrowedParameter() {
        String source = """
                fnc keep(record{foo: int} value): int { return value.foo; }
                fnc caller(): int {
                    const owned = infer struct{foo: 5, extra: "ok"};
                    return keep(owned);
                }
                """;
        assertDoesNotThrow(() -> TypeChecker.check(Parser.parse(source)));
        assertDoesNotThrow(() -> OwnershipChecker.check(Parser.parse(source)));
    }

    @Test
    void asyncOwnedRecordContractIsAdmittedByBothStaticPasses() {
        String source = """
                async fnc read(record{foo: int} v): int {
                    return v.foo;
                }
                """;
        assertDoesNotThrow(() -> TypeChecker.check(Parser.parse(source)));
        assertDoesNotThrow(() -> OwnershipChecker.check(Parser.parse(source)));
    }

    @Test
    void borrowedViewStillCannotBeAnAsyncParameter() {
        String source = """
                async fnc bad(structural {foo: int} v): int {
                    return v.foo;
                }
                """;
        assertThrows(IllegalArgumentException.class,
                () -> TypeChecker.check(Parser.parse(source)));
    }

    @Test
    void actorSendAcceptsOwnedRecordWithExtraFields() {
        String source = """
                actor fnc dispatch(record{foo: int} value): void { return; }
                fnc safe(): void {
                    dispatch(infer struct{foo: 3, extra: "kept"});
                    return;
                }
                """;
        assertDoesNotThrow(() -> TypeChecker.check(Parser.parse(source)));
    }

    @Test
    void structuralMatchCannotSendANominalClassThroughActorMailbox() {
        String source = """
                define class Candidate as
                    pub val int foo = 3;
                end
                actor fnc dispatch(record{foo: int} value): void { return; }
                fnc unsafe(): void {
                    dispatch(new Candidate());
                    return;
                }
                """;
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class, () -> TypeChecker.check(Parser.parse(source)));
        // The compiler may reject at the earlier owned-record assignment
        // boundary, before the actor transport-specific check runs.
        assertTrue(error.getMessage().contains("cannot implicitly convert")
                || error.getMessage().contains("class instance")
                || error.getMessage().contains("actor")
                || error.getMessage().contains("transport"), error.getMessage());
    }

    @Test
    void unresolvedNominalCannotBecomeActorMailboxPayload() {
        String source = """
                actor fnc dispatch(Phantom value): void { return; }
                """;
        var parsed = assertDoesNotThrow(() -> Parser.parse(source));
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> TypeChecker.check(parsed));
        assertTrue(error.getMessage().contains("unresolved/opaque nominal type 'Phantom'"),
                error.getMessage());
    }

    @Test
    void unresolvedNominalCannotHideInsideOwnedActorRecord() {
        String source = """
                actor fnc dispatch(record{foo: Phantom} value): void { return; }
                """;
        var parsed = assertDoesNotThrow(() -> Parser.parse(source));
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> TypeChecker.check(parsed));
        assertTrue(error.getMessage().contains("unresolved/opaque nominal type 'Phantom'"),
                error.getMessage());
    }

    @Test
    void unresolvedNominalCannotHideInsideActorSumType() {
        String source = """
                actor fnc dispatch(Option<Phantom> value): void { return; }
                """;
        var parsed = assertDoesNotThrow(() -> Parser.parse(source));
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> TypeChecker.check(parsed));
        assertTrue(error.getMessage().contains("unresolved/opaque nominal type 'Phantom'"),
                error.getMessage());
    }

    @Test
    void taggedOptionNeedsARealActorTransportCodec() {
        String source = """
                actor fnc deliver(Option<int> option): void { return; }
                """;
        var parsed = assertDoesNotThrow(() -> Parser.parse(source));
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> TypeChecker.check(parsed));
        assertTrue(error.getMessage().contains("canonical actor-safe tagged-value codec"),
                error.getMessage());
    }

    @Test
    void taggedResultCannotHideInNestedMailboxRecord() {
        String source = """
                actor fnc deliver(record{outcome: Result<int, string>} message): void {
                    return;
                }
                """;
        var parsed = assertDoesNotThrow(() -> Parser.parse(source));
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> TypeChecker.check(parsed));
        assertTrue(error.getMessage().contains("canonical actor-safe tagged-value codec"),
                error.getMessage());
    }

    @Test
    void scalarActorIdentityRemainsSendable() {
        String source = """
                actor fnc dispatch(ActorId target): ActorId { return target; }
                """;
        var parsed = assertDoesNotThrow(() -> Parser.parse(source));
        assertDoesNotThrow(() -> TypeChecker.check(parsed));
    }

    @Test
    void typedActorReferenceIsCapabilityNotAClassByValue() {
        String source = """
                define actor Worker as
                    receive(ActorMail<int> mail): void {
                        self.end();
                        return;
                    }
                end
                actor fnc forward(ActorRef<Worker> worker): void { return; }
                """;
        var parsed = assertDoesNotThrow(() -> Parser.parse(source));
        assertDoesNotThrow(() -> TypeChecker.check(parsed));
    }

    @Test
    void untrustedActorCannotReceiveActorReference() {
        String source = """
                define actor Worker as
                    receive(ActorMail<int> mail): void {
                        self.end();
                        return;
                    }
                end
                define untrusted actor Inbox as
                    receive(ActorMail<ActorRef<Worker>> mail): void {
                        self.end();
                        return;
                    }
                end
                """;
        var parsed = assertDoesNotThrow(() -> Parser.parse(source));
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> TypeChecker.check(parsed));
        // The existing same-file actor dependency rule may reject the
        // reference before the untrusted mailbox validator is reached.
        // Either is a fail-closed result; cross-file untrusted capability
        // admission needs a separate linked-import integration fixture.
        assertTrue(error.getMessage().contains("untrusted actor")
                || error.getMessage().contains("same-file type"),
                error.getMessage());
    }

    @Test
    void borrowingHiddenInsideOwnedShapeIsNotSendable() {
        String source = """
                async fnc bad(record{foo: &int} v): void { return; }
                """;
        assertThrows(IllegalArgumentException.class,
                () -> TypeChecker.check(Parser.parse(source)));
    }
}
