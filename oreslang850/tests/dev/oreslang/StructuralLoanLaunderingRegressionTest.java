package dev.oreslang;

import dev.oreslang.parser.Parser;
import dev.oreslang.types.OwnershipChecker;
import dev.oreslang.types.TypeChecker;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression: structural type compatibility does not imply value ownership.
 * These fixtures must parse before the relevant static pass rejects a leak.
 */
final class StructuralLoanLaunderingRegressionTest {
    @Test
    void borrowedStructuralParameterCannotBePassedAsOwnedArgument() {
        String source = """
                fnc own(record{foo: int} value): void { return; }
                fnc leak(structural {foo: int} view): void {
                    own(view);
                    return;
                }
                """;
        var parsed = assertDoesNotThrow(() -> Parser.parse(source));
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class, () -> OwnershipChecker.check(parsed));
        assertTrue(error.getMessage().contains("cannot transfer borrowed structural data"),
                error.getMessage());
    }

    @Test
    void explicitOwnedTypeAnnotationCannotEraseAnIncomingLoan() {
        String source = """
                fnc leak(structural {foo: int} view): void {
                    const alias: record{foo: int} = view;
                    return;
                }
                """;
        var parsed = assertDoesNotThrow(() -> Parser.parse(source));
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class, () -> OwnershipChecker.check(parsed));
        assertTrue(error.getMessage().contains("cannot be rebound as an owned value"),
                error.getMessage());
    }

    @Test
    void unannotatedAliasRemainsBorrowedAcrossCalls() {
        String source = """
                fnc own(record{foo: int} value): void { return; }
                fnc leak(structural {foo: int} view): void {
                    const alias = view;
                    own(alias);
                    return;
                }
                """;
        var parsed = assertDoesNotThrow(() -> Parser.parse(source));
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class, () -> OwnershipChecker.check(parsed));
        assertTrue(error.getMessage().contains("cannot transfer borrowed structural data"),
                error.getMessage());
    }

    @Test
    void aggregateDestructuringCannotLoseBorrowOwnership() {
        String source = """
                fnc leak(structural {foo: int} view): void {
                    const {foo} = view;
                    return;
                }
                """;
        var parsed = assertDoesNotThrow(() -> Parser.parse(source));
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class, () -> OwnershipChecker.check(parsed));
        assertTrue(error.getMessage().contains("provenance-aware"),
                error.getMessage());
    }

    @Test
    void borrowedStructuralParameterCannotBeReturnedAsOwnedRecord() {
        String source = """
                fnc leak(structural {foo: int} view): record{foo: int} {
                    return view;
                }
                """;
        var parsed = assertDoesNotThrow(() -> Parser.parse(source));
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class, () -> OwnershipChecker.check(parsed));
        assertTrue(error.getMessage().contains("cannot be returned as owned data"),
                error.getMessage());
    }

    @Test
    void borrowedStructuralParameterCannotBeForwardedIntoActorPayload() {
        String source = """
                actor fnc deliver(record{foo: int} value): void { return; }
                fnc leak(structural {foo: int} view): void {
                    deliver(view);
                    return;
                }
                """;
        var parsed = assertDoesNotThrow(() -> Parser.parse(source));
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class, () -> OwnershipChecker.check(parsed));
        assertTrue(error.getMessage().contains("cannot transfer borrowed structural data"),
                error.getMessage());
    }

    @Test
    void nominalClassCannotImplicitlyBecomeOwnedStructuralRecord() {
        String source = """
                define class Candidate as
                    pub val int foo = 3;
                end
                fnc own(record{foo: int} value): void { return; }
                fnc bad(): void {
                    own(new Candidate());
                    return;
                }
                """;
        var parsed = assertDoesNotThrow(() -> Parser.parse(source));
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class, () -> TypeChecker.check(parsed));
        assertTrue(error.getMessage().contains("cannot implicitly convert"),
                error.getMessage());
    }

    @Test
    void typedOwnedRecordBindingCannotHideNominalClassIdentity() {
        String source = """
                define class Candidate as
                    pub val int foo = 3;
                end
                fnc unsafe(): void {
                    const alias: record{foo: int} = new Candidate();
                    return;
                }
                """;
        var parsed = assertDoesNotThrow(() -> Parser.parse(source));
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class, () -> TypeChecker.check(parsed));
        assertTrue(error.getMessage().contains("cannot implicitly convert"),
                error.getMessage());
    }

    @Test
    void explicitBorrowReturnOfIncomingLoanIsStillValid() {
        String source = """
                fnc identity(&int value): &int {
                    return value;
                }
                """;
        var parsed = assertDoesNotThrow(() -> Parser.parse(source));
        assertDoesNotThrow(() -> OwnershipChecker.check(parsed));
    }

    @Test
    void unionWithRecordArmCannotHideNominalClassIdentity() {
        String source = """
                define class Candidate as
                    pub val int foo = 3;
                end
                fnc unsafe(): void {
                    const disguised: record{foo: int} | string = new Candidate();
                    return;
                }
                """;
        var parsed = assertDoesNotThrow(() -> Parser.parse(source));
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class, () -> TypeChecker.check(parsed));
        assertTrue(error.getMessage().contains("cannot implicitly convert"), error.getMessage());
    }

    @Test
    void unionWithExplicitNominalArmCanRetainNominalIdentity() {
        String source = """
                define class Candidate as
                    pub val int foo = 3;
                end
                fnc ok(): void {
                    const correct: Candidate | record{foo: int} = new Candidate();
                    return;
                }
                """;
        var parsed = assertDoesNotThrow(() -> Parser.parse(source));
        assertDoesNotThrow(() -> TypeChecker.check(parsed));
    }

    @Test
    void explicitBorrowedStructuralClassParameterRemainsAdmitted() {
        String source = """
                define class Candidate as
                    pub val int foo = 3;
                end
                fnc inspect(structural {foo: int} value): int { return value.foo; }
                fnc ok(): int { return inspect(new Candidate()); }
                """;
        var parsed = assertDoesNotThrow(() -> Parser.parse(source));
        assertDoesNotThrow(() -> TypeChecker.check(parsed));
        assertDoesNotThrow(() -> OwnershipChecker.check(parsed));
    }

    @Test
    void ownedRecordValueStillPassesOwnedRecordParameter() {
        String source = """
                fnc own(record{foo: int} value): int { return value.foo; }
                fnc ok(): int {
                    const value = infer struct{foo: 3, extra: "ok"};
                    return own(value);
                }
                """;
        var parsed = assertDoesNotThrow(() -> Parser.parse(source));
        assertDoesNotThrow(() -> TypeChecker.check(parsed));
        assertDoesNotThrow(() -> OwnershipChecker.check(parsed));
    }
}
