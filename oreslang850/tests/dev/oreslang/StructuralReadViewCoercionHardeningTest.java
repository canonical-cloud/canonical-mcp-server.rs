package dev.oreslang;

import dev.oreslang.parser.Parser;
import dev.oreslang.types.TypeChecker;
import dev.oreslang.types.Types;
import org.junit.jupiter.api.Test;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

/**
 * A read-only structural shape is a field projection, not an implicit
 * numeric conversion or a proof of an unresolved field representation.
 */
final class StructuralReadViewCoercionHardeningTest {
    @Test
    void readonlyRecordIsNotNumericWidening() {
        Types.Record actual = new Types.Record(Map.of("foo", Types.Primitive.INT), true);
        Types.Record expectsFloat = new Types.Record(Map.of("foo", Types.Primitive.FLOAT), true);
        assertTrue(Types.isAssignable(Types.Primitive.INT, Types.Primitive.FLOAT),
                "scalar value promotion remains legal");
        assertFalse(Types.isAssignable(actual, expectsFloat),
                "field-view projection must not promote raw storage");
        assertFalse(Types.isAssignable(
                new Types.Record(Map.of("inner", actual), true),
                new Types.Record(Map.of("inner", expectsFloat), true)),
                "nested field-view projection cannot hide a coercion");
        assertFalse(Types.isAssignable(
                new Types.Record(Map.of("foo", new Types.Tuple(
                        java.util.List.of(Types.Primitive.INT))), true),
                new Types.Record(Map.of("foo", new Types.Tuple(
                        java.util.List.of(Types.Primitive.FLOAT))), true)),
                "tuple elements are not magically converted on projection");
    }

    @Test
    void unknownCanBeReadAsOpaqueButCannotProveConcreteFieldType() {
        Types.Record unresolved = new Types.Record(Map.of("foo", Types.Unknown.INSTANCE), true);
        Types.Record known = new Types.Record(Map.of("foo", Types.Primitive.INT), true);
        assertFalse(Types.isAssignable(unresolved, known));
        assertTrue(Types.isAssignable(known, unresolved),
                "opaque Unknown destination cannot be mistaken for a concrete proof");
        assertFalse(Types.isAssignable(
                new Types.Record(Map.of("foo", new Types.Generic("T")), true), known));
    }

    @Test
    void unknownOrGenericEntireValuesDoNotProveAnyRecordShape() {
        Types.Record required = new Types.Record(Map.of("foo", Types.Primitive.INT), true);
        assertFalse(Types.isAssignable(Types.Unknown.INSTANCE, required));
        assertFalse(Types.isAssignable(new Types.Generic("Unbound"), required));
        assertFalse(Types.isAssignable(
                Types.unionOf(Types.Primitive.INT, Types.Unknown.INSTANCE), required));
        assertTrue(Types.isAssignable(Types.Primitive.INT, Types.Unknown.INSTANCE));
    }

    @Test
    void unknownOrGenericCannotProveRecordHiddenInUnion() {
        Types.Record record = new Types.Record(Map.of("foo", Types.Primitive.INT), true);
        Types.Type union = Types.unionOf(record, Types.Primitive.STRING);
        assertFalse(Types.isAssignable(Types.Unknown.INSTANCE, union),
                "Unknown is not proof of a structural union alternative");
        assertFalse(Types.isAssignable(new Types.Generic("Unbound"), union),
                "unbound generic is not proof of a structural union alternative");
        assertTrue(Types.isAssignable(record, union),
                "a proven record still satisfies its explicit union arm");
        assertTrue(Types.isAssignable(Types.Primitive.STRING, union),
                "known non-record variants retain their valid union arm");
        assertTrue(Types.isAssignable(Types.Unknown.INSTANCE, Types.Primitive.STRING),
                "unrelated legacy inference behavior remains unchanged");
    }

    @Test
    void unknownCannotProveRecordCarriedByCollectionsOrFunctions() {
        Types.Record record = new Types.Record(Map.of("foo", Types.Primitive.INT), true);
        for (Types.Type expected : java.util.List.<Types.Type>of(
                new Types.ListType(record),
                new Types.Tuple(java.util.List.of(record)),
                new Types.Named("Option", java.util.List.of(record)),
                new Types.Borrow(record, false),
                new Types.Function(java.util.List.of(record), Types.Primitive.VOID),
                new Types.Function(java.util.List.of(), record))) {
            assertFalse(Types.isAssignable(Types.Unknown.INSTANCE, expected),
                    "Unknown lacks representation proof for " + expected);
            assertFalse(Types.isAssignable(new Types.Generic("T"), expected),
                    "unbound generic lacks representation proof for " + expected);
        }
        assertTrue(Types.isAssignable(Types.Primitive.INT,
                Types.Unknown.INSTANCE), "opaque destination remains supported");
    }

    @Test
    void invariantMutableListsCannotSmuggleUnknownOrGenericElementTypes() {
        Types.ListType unknown = new Types.ListType(Types.Unknown.INSTANCE);
        Types.ListType concrete = new Types.ListType(Types.Primitive.INT);
        Types.ListType generic = new Types.ListType(new Types.Generic("T"));
        assertFalse(Types.isAssignable(unknown, concrete));
        assertFalse(Types.isAssignable(concrete, unknown));
        assertFalse(Types.isAssignable(generic, concrete));
        assertFalse(Types.isAssignable(concrete, generic));
        assertTrue(Types.isAssignable(concrete, new Types.ListType(Types.Primitive.INT)));
    }

    @Test
    void genericContainersCannotForgeUnknownOrNumericParameterRepresentations() {
        Types.Named unknown = new Types.Named("Option", java.util.List.of(Types.Unknown.INSTANCE));
        Types.Named concrete = new Types.Named("Option", java.util.List.of(Types.Primitive.INT));
        Types.Named generic = new Types.Named("Option", java.util.List.of(new Types.Generic("T")));
        assertFalse(Types.isAssignable(unknown, concrete));
        assertFalse(Types.isAssignable(concrete, unknown));
        assertFalse(Types.isAssignable(generic, concrete));
        assertFalse(Types.isAssignable(
                concrete, new Types.Named("Option", java.util.List.of(Types.Primitive.FLOAT))));
        assertTrue(Types.isAssignable(concrete,
                new Types.Named("Option", java.util.List.of(Types.Primitive.INT))));
    }

    @Test
    void borrowedAliasesRequireExactTargetTypeProof() {
        Types.Borrow borrowUnknown = new Types.Borrow(Types.Unknown.INSTANCE, false);
        Types.Borrow borrowInt = new Types.Borrow(Types.Primitive.INT, false);
        Types.Borrow borrowMutInt = new Types.Borrow(Types.Primitive.INT, true);
        assertFalse(Types.isAssignable(borrowUnknown, borrowInt));
        assertFalse(Types.isAssignable(borrowInt, borrowUnknown));
        assertFalse(Types.isAssignable(borrowInt, borrowMutInt),
                "shared borrow cannot gain mutable authority");
        assertTrue(Types.isAssignable(borrowMutInt, borrowInt),
                "mutable borrow can lose, but never gain, write authority");
        assertTrue(Types.isAssignable(borrowInt, new Types.Borrow(Types.Primitive.INT, false)));
    }

    @Test
    void tupleViewsCannotSilentlyApplyNumericConversions() {
        Types.Tuple source = new Types.Tuple(java.util.List.of(Types.Primitive.INT));
        Types.Tuple widenedScalar = new Types.Tuple(java.util.List.of(Types.Primitive.FLOAT));
        Types.Tuple unionView = new Types.Tuple(java.util.List.of(
                Types.unionOf(Types.Primitive.INT, Types.Primitive.STRING)));
        assertFalse(Types.isAssignable(source, widenedScalar),
                "a tuple retyping is not an element-by-element numeric adapter");
        assertTrue(Types.isAssignable(source, unionView));
        assertFalse(Types.isAssignable(
                new Types.Tuple(java.util.List.of(Types.Primitive.INT), Types.TupleKind.FIXED_ARRAY),
                new Types.Tuple(java.util.List.of(
                        Types.unionOf(Types.Primitive.INT, Types.Primitive.STRING)), Types.TupleKind.FIXED_ARRAY)),
                "writable fixed array slots are invariant");
    }

    @Test
    void functionValueVarianceCannotInventNumericAbiAdapters() {
        Types.Function returnsInt = new Types.Function(
                java.util.List.of(), Types.Primitive.INT);
        Types.Function promisesFloat = new Types.Function(
                java.util.List.of(), Types.Primitive.FLOAT);
        Types.Function acceptsFloat = new Types.Function(
                java.util.List.of(Types.Primitive.FLOAT), Types.Primitive.VOID);
        Types.Function onlyAcceptsInt = new Types.Function(
                java.util.List.of(Types.Primitive.INT), Types.Primitive.VOID);
        assertFalse(Types.isAssignable(returnsInt, promisesFloat));
        assertFalse(Types.isAssignable(acceptsFloat, onlyAcceptsInt),
                "int caller input cannot be redirected without a scalar conversion");
        assertTrue(Types.isAssignable(
                new Types.Function(java.util.List.of(), new Types.StringLiteral("ok")),
                new Types.Function(java.util.List.of(), Types.Primitive.STRING)));
    }

    @Test
    void readonlyCovarianceStillAllowsSafeWidthAndUnionViews() {
        Types.Record actual = new Types.Record(
                Map.of("foo", Types.Primitive.INT, "bar", Types.Primitive.STRING), true);
        Types.Record required = new Types.Record(Map.of("foo",
                Types.unionOf(Types.Primitive.INT, Types.Primitive.STRING)), true);
        assertTrue(Types.isAssignable(actual, required));
    }

    @Test
    void sourceRejectsUnconvertedScalarAndNestedFields() {
        for (String shape : java.util.List.of(
                "record{foo: float}", "struct{foo: float}", "structural {foo: float}")) {
            String source = """
                    fnc read(SHAPE v): void { return; }
                    fnc bad(): void {
                        read(infer struct{foo: 3, extra: "kept"});
                        return;
                    }
                    """.replace("SHAPE", shape);
            var parsed = assertDoesNotThrow(() -> Parser.parse(source),
                    "negative regression must reach type checking, not merely fail to parse: " + shape);
            assertThrows(IllegalArgumentException.class,
                    () -> TypeChecker.check(parsed), shape);
        }

        String nested = """
                fnc read(record{inner: record{foo: float}} v): void { return; }
                fnc bad(): void {
                    read(infer struct{inner: infer struct{foo: 3, extra: true}});
                    return;
                }
                """;
        var parsedNested = assertDoesNotThrow(() -> Parser.parse(nested),
                "nested constructor syntax must parse to test the actual coercion rule");
        assertThrows(IllegalArgumentException.class,
                () -> TypeChecker.check(parsedNested));
    }

    @Test
    void methodSlotVarianceCannotInventNumericCallAdapters() {
        String key = "instance$read$arity0$generics0";
        Types.Function actual = new Types.Function(
                java.util.List.of(), Types.Primitive.INT);
        Types.Function expectsFloat = new Types.Function(
                java.util.List.of(), Types.Primitive.FLOAT);
        Types.Record implementation = new Types.Record(
                Map.of(key, actual), false, java.util.Set.of(key));
        Types.Record contract = new Types.Record(
                Map.of(key, expectsFloat), true, java.util.Set.of(key));
        assertFalse(Types.isAssignable(implementation, contract));
        assertFalse(Types.isAssignable(
                new Types.Record(Map.of(key, actual), true), contract));
    }

    @Test
    void sourceStructuralMethodReturnCannotBeNumericallyPromoted() {
        String source = """
                define interface Wants
                    fnc read() => float;
                end
                define class Candidate as
                    pub read(): int { return 3; }
                end
                fnc use(structural Wants candidate): float {
                    return candidate.read();
                }
                fnc bad(): float { return use(new Candidate()); }
                """;
        var parsed = assertDoesNotThrow(() -> Parser.parse(source),
                "method ABI regression must be syntactically valid");
        assertThrows(IllegalArgumentException.class,
                () -> TypeChecker.check(parsed));
    }

    @Test
    void sourcePreservesSafeReadonlyWidthViews() {
        assertDoesNotThrow(() -> TypeChecker.check(Parser.parse("""
                fnc read(record{foo: int | string} v): void { return; }
                fnc ok(): void {
                    const wider = infer struct{foo: 3, extra: "kept"};
                    read(wider);
                    return;
                }
                """)));
    }
}
