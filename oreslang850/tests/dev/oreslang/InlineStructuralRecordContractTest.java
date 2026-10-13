package dev.oreslang;

import dev.oreslang.ast.Ast;
import dev.oreslang.parser.Parser;
import dev.oreslang.types.TypeChecker;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Read-only inline shape contracts: struct{...}, record{...}, structural {...}. */
final class InlineStructuralRecordContractTest {
    @Test
    void structAndRecordTypeSpellingsNormalizeToTheSameReadonlyShape() {
        Ast.Program ast = Parser.parse("""
                fnc byStruct(struct{foo: int} value): int { return value.foo; }
                fnc byRecord(record{foo: int} value): int { return value.foo; }
                """);
        Ast.ModuleDecl root = ast.modules().getFirst();
        Ast.FunctionDecl byStruct = (Ast.FunctionDecl) root.declarations().get(0);
        Ast.FunctionDecl byRecord = (Ast.FunctionDecl) root.declarations().get(1);
        assertEquals(byStruct.parameters().getFirst().type(), byRecord.parameters().getFirst().type());
        assertTrue(byStruct.parameters().getFirst().type().isReadonlyRecordType());
    }

    @Test
    void extraFieldsAreAcceptedByAllThreeReadOnlyContracts() {
        assertDoesNotThrow(() -> TypeChecker.check(Parser.parse("""
                pub fnc byStruct(struct{foo: int} value): int {
                    return value.foo;
                }
                pub fnc byStructural(structural {foo: int} value): int {
                    return value.foo;
                }
                pub fnc byRecord(record{foo: int} value): int {
                    return value.foo;
                }
                fnc ok(): int {
                    const value = infer struct{foo: 3, bar: "seven"};
                    // Borrowed structural inspection may precede an owned move.
                    // But by-value calls consume a move-only owned struct:
                    // the final call must receive a fresh owned value.
                    return byStructural(value)
                            + byStruct(value)
                            + byRecord(infer struct{foo: 3, bar: "seven"});
                }
                """)));
    }

    @Test
    void explicitClosedStructWithExtraFieldsAlsoSatisfiesContract() {
        assertDoesNotThrow(() -> TypeChecker.check(Parser.parse("""
                fnc take(record{foo: int} value): int { return value.foo; }
                fnc ok(): int {
                    const value = struct{foo: int, bar: string}{foo: 3, bar: "seven"};
                    return take(value);
                }
                """)));
    }

    @Test
    void missingAndWronglyTypedRequiredFieldsAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> TypeChecker.check(Parser.parse("""
                fnc take(struct{foo: int} value): int { return value.foo; }
                fnc bad(): int { return take(infer struct{bar: 3}); }
                """)));
        assertThrows(IllegalArgumentException.class, () -> TypeChecker.check(Parser.parse("""
                fnc take(record{foo: int} value): int { return value.foo; }
                fnc bad(): int { return take(infer struct{foo: "three", bar: 4}); }
                """)));
    }

    @Test
    void readonlyContractNeverGrantsFieldWriteAuthority() {
        assertThrows(IllegalArgumentException.class, () -> TypeChecker.check(Parser.parse("""
                fnc bad(struct{foo: int} value): void {
                    value.foo = 9;
                    return;
                }
                """)));
        assertThrows(IllegalArgumentException.class, () -> TypeChecker.check(Parser.parse("""
                fnc bad(record{foo: int} mut value): void {
                    value.foo = 9;
                    return;
                }
                """)));
    }

    @Test
    void ownedReadonlyRecordCanCrossAsyncAndSuspendBoundaries() {
        assertDoesNotThrow(() -> TypeChecker.check(Parser.parse("""
                async fnc read(record{foo: int} value): int { return value.foo; }
                suspend fnc hold(struct{foo: int} value): int { return value.foo; }
                """)));
    }

    @Test
    void ownedNestedReadonlyRecordsCanCrossAsyncAndActorBoundaries() {
        assertDoesNotThrow(() -> TypeChecker.check(Parser.parse("""
                async fnc process(List<record{foo: int}> values): void { return; }
                actor fnc dispatch(List<struct{foo: int}> values): void { return; }
                """)));
    }

    @Test
    void borrowedStructuralViewsCannotEscapeAsyncSuspendOrActorBoundaries() {
        for (String source : java.util.List.of(
                "async fnc bad(structural {foo: int} v): int { return v.foo; }",
                "suspend fnc bad(structural {foo: int} v): int { return v.foo; }",
                "actor fnc bad(structural {foo: int} v): void { return; }")) {
            assertThrows(IllegalArgumentException.class,
                    () -> TypeChecker.check(Parser.parse(source)), source);
        }
    }

    @Test
    void actualBorrowsCannotEscapeViaNestedContainers() {
        for (String source : java.util.List.of(
                "suspend fnc bad(List<&int> values): void { return; }",
                "async fnc bad(List<&int> values): void { return; }",
                "actor fnc bad(List<&int> values): void { return; }",
                "suspend fnc bad(List<&record{foo: int}> values): void { return; }")) {
            assertThrows(IllegalArgumentException.class,
                    () -> TypeChecker.check(Parser.parse(source)), source);
        }
    }

    @Test
    void duplicateFieldNamesFailAtParseTime() {
        assertThrows(IllegalArgumentException.class, () -> Parser.parse("""
                fnc bad(record{foo: int, foo: string} v): void { return; }
                """));
        assertThrows(IllegalArgumentException.class, () -> Parser.parse("""
                fnc bad(struct{foo: int, foo: int} v): void { return; }
                """));
    }

    @Test
    void recordRemainsAnOrdinaryIdentifierOutsideTypeShapePosition() {
        assertDoesNotThrow(() -> TypeChecker.check(Parser.parse("""
                fnc record(): int { return 2; }
                fnc ok(): int { return record(); }
                """)));
    }
}
