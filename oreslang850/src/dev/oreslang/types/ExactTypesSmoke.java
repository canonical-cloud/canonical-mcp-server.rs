package dev.oreslang.types;

import java.util.List;
import java.util.Map;

// Dependency-free assertions executed against the exact mirrored Types.java,
// NOT a reimplementation of its assignability algorithms.
// Original Oreslang PR #850 head: 80dac1f488ee8ebfe2d9a33e7e9e620877ff14cf
public final class ExactTypesSmoke {
    private static int checks;

    private static void yes(String name, boolean value) {
        checks++;
        if (!value) throw new AssertionError("FAIL: " + name);
        System.out.println("PASS " + name);
    }
    private static void no(String name, boolean value) {
        yes(name, !value);
    }

    public static void main(String[] args) {
        var intT = Types.Primitive.INT;
        var floatT = Types.Primitive.FLOAT;
        var stringT = Types.Primitive.STRING;
        var unknown = Types.Unknown.INSTANCE;
        var unbound = new Types.Generic("T");
        var read = new Types.Record(Map.of("foo", intT), true);
        var wide = new Types.Record(Map.of("foo", intT, "extra", stringT), true);
        var floatRecord = new Types.Record(Map.of("foo", floatT), true);
        var opaqueRecord = new Types.Record(Map.of("foo", unknown), true);
        var intOrString = Types.unionOf(intT, stringT);
        var readUnion = new Types.Record(Map.of("foo", intOrString), true);
        var recordOrString = Types.unionOf(read, stringT);

        yes("scalar int to float promotion", Types.isAssignable(intT, floatT));
        no("record projection cannot numerically promote", Types.isAssignable(read, floatRecord));
        yes("readonly record width subtyping", Types.isAssignable(wide, read));
        yes("readonly field union widening", Types.isAssignable(read, readUnion));
        no("readonly field cannot narrow from unknown", Types.isAssignable(opaqueRecord, read));
        yes("known field may be read opaque", Types.isAssignable(read, opaqueRecord));
        no("unknown entire value cannot prove record", Types.isAssignable(unknown, read));
        no("unbound generic entire value cannot prove record", Types.isAssignable(unbound, read));
        no("unknown cannot prove record branch of union", Types.isAssignable(unknown, recordOrString));
        no("generic cannot prove record branch of union", Types.isAssignable(unbound, recordOrString));
        yes("known scalar alternative of record union", Types.isAssignable(stringT, recordOrString));
        yes("known record alternative of record union", Types.isAssignable(read, recordOrString));
        yes("opaque nonrecord scalar admission remains", Types.isAssignable(unknown, stringT));

        var listInt = new Types.ListType(intT);
        var listUnknown = new Types.ListType(unknown);
        no("mutable list unknown to int", Types.isAssignable(listUnknown, listInt));
        no("mutable list int to unknown", Types.isAssignable(listInt, listUnknown));
        yes("mutable list exact element", Types.isAssignable(listInt, new Types.ListType(intT)));

        var optionInt = new Types.Named("Option", List.of(intT));
        var optionUnknown = new Types.Named("Option", List.of(unknown));
        no("nominal generic unknown to int", Types.isAssignable(optionUnknown, optionInt));
        no("nominal generic int to unknown", Types.isAssignable(optionInt, optionUnknown));
        no("nominal generic int to float", Types.isAssignable(optionInt, new Types.Named("Option", List.of(floatT))));
        yes("nominal generic same instantiation", Types.isAssignable(optionInt, new Types.Named("Option", List.of(intT))));

        var loanInt = new Types.Borrow(intT, false);
        var mutInt = new Types.Borrow(intT, true);
        var loanUnknown = new Types.Borrow(unknown, false);
        no("borrow unknown to int", Types.isAssignable(loanUnknown, loanInt));
        no("borrow int to unknown", Types.isAssignable(loanInt, loanUnknown));
        no("borrow cannot gain mutability", Types.isAssignable(loanInt, mutInt));
        yes("borrow can lose mutability", Types.isAssignable(mutInt, loanInt));

        var tupleInt = new Types.Tuple(List.of(intT));
        var tupleFloat = new Types.Tuple(List.of(floatT));
        var tupleUnion = new Types.Tuple(List.of(intOrString));
        no("tuple numeric shape widening forbidden", Types.isAssignable(tupleInt, tupleFloat));
        yes("tuple union representational widening", Types.isAssignable(tupleInt, tupleUnion));
        no("fixed array union element alias forbidden",
            Types.isAssignable(
                new Types.Tuple(List.of(intT), Types.TupleKind.FIXED_ARRAY),
                new Types.Tuple(List.of(intOrString), Types.TupleKind.FIXED_ARRAY)));

        var returnsInt = new Types.Function(List.of(), intT);
        var returnsFloat = new Types.Function(List.of(), floatT);
        no("first-class fn return numeric ABI adapter forbidden", Types.isAssignable(returnsInt, returnsFloat));
        no("first-class fn param numeric ABI adapter forbidden",
            Types.isAssignable(new Types.Function(List.of(floatT), Types.Primitive.VOID),
                new Types.Function(List.of(intT), Types.Primitive.VOID)));
        yes("first-class fn literal-string result as string",
            Types.isAssignable(new Types.Function(List.of(), new Types.StringLiteral("ok")),
                new Types.Function(List.of(), stringT)));

        for (var carrier : List.<Types.Type>of(
            new Types.ListType(read),
            new Types.Tuple(List.of(read)),
            new Types.Named("Option", List.of(read)),
            new Types.Borrow(read, false),
            new Types.Function(List.of(read), Types.Primitive.VOID),
            new Types.Function(List.of(), read)
        )) {
            no("unknown cannot prove embedded record " + carrier.getClass().getSimpleName(),
                Types.isAssignable(unknown, carrier));
            no("generic cannot prove embedded record " + carrier.getClass().getSimpleName(),
                Types.isAssignable(unbound, carrier));
        }

        System.out.println("PASS EXACT-TYPES-SMOKE total=" + checks);
    }
}
