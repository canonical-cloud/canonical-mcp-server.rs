package dev.oreslang.types;

import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class Types {
    private Types() { }

    public sealed interface Type permits Primitive, Named, SelfType, Borrow, ClassNamespace, Record, Function, ListType, Tuple, Union, Generic, StringLiteral, Unknown { }

    public enum Primitive implements Type {
        INT, FLOAT, DECIMAL, COMPLEX, BOOL, STRING, VOID, NULL
    }

    public record Named(String name, List<Type> arguments) implements Type {
        public Named { arguments = List.copyOf(arguments); }
    }

    /**
     * Receiver-polymorphic type carried by the implicit instance receiver.
     *
     * <p>The bound is the nominal type whose members are available while checking
     * the method body. A SelfType value may widen to that nominal type, but a
     * fresh value of the nominal type cannot narrow back to SelfType because the
     * actual receiver may be a more-derived subtype. Values already proven to
     * have the receiver-polymorphic self type may flow through aliases/parameters.
     */
    public record SelfType(Type bound) implements Type {
        public SelfType { Objects.requireNonNull(bound, "self bound"); }
    }

    /** Rust-style compile-time borrow; erased by the interpreter runtime. */
    public record Borrow(Type target, boolean mutable) implements Type { }

    /** Compile-time meta-value for access to static class functions. */
    public record ClassNamespace(String className) implements Type { }

    /**
     * Closed structural record type. readOnly is a value capability, not a
     * structural compatibility dimension: it prevents mutation from being
     * regained through aliases while preserving ordinary shape matching.
     */
    public record Record(Map<String, Type> members, boolean readOnly,
                         java.util.Set<String> methodKeys) implements Type {
        public Record {
            members = Map.copyOf(members);
            methodKeys = java.util.Set.copyOf(methodKeys);
            for (String key : methodKeys) {
                if (!(members.get(key) instanceof Function)) {
                    throw new IllegalArgumentException(
                            "compiler method slot '" + key + "' must contain a callable contract");
                }
            }
        }
        public Record(Map<String, Type> members, boolean readOnly) {
            this(members, readOnly, java.util.Set.of());
        }
        public Record(Map<String, Type> members) { this(members, false); }
        /** Preserve compiler-proven method identity during type transformations. */
        public Record withMembers(Map<String, Type> updated, boolean readonly) {
            java.util.Set<String> surviving = new java.util.HashSet<>(methodKeys);
            surviving.retainAll(updated.keySet());
            return new Record(updated, readonly, surviving);
        }
    }

    public record Function(
            List<Type> parameters,
            List<Boolean> mutableParameters,
            boolean async,
            Type result) implements Type {
        public Function {
            parameters = List.copyOf(parameters);
            mutableParameters = List.copyOf(mutableParameters);
            if (parameters.size() != mutableParameters.size()) {
                throw new IllegalArgumentException(
                        "function parameter mutability metadata must match parameter arity");
            }
        }

        /**
         * Source-level Fnc<...> types and built-in callables have no mutable
         * parameters and are synchronous unless a declaration explicitly says
         * otherwise.
         */
        public Function(List<Type> parameters, Type result) {
            this(parameters, java.util.Collections.nCopies(parameters.size(), false), false, result);
        }
    }

    public record ListType(Type element) implements Type { }

    public enum TupleKind {
        TUPLE,
        FIXED_ARRAY,
        FIXED_LIST
    }

    public record Tuple(List<Type> elements, TupleKind kind) implements Type {
        public Tuple {
            elements = List.copyOf(elements);
            kind = Objects.requireNonNull(kind, "kind");
        }

        public Tuple(List<Type> elements) {
            this(elements, TupleKind.TUPLE);
        }
    }

    public record Union(List<Type> options) implements Type {
        public Union {
            options = List.copyOf(options);
            if (options.size() < 2) throw new IllegalArgumentException("union needs at least two distinct types");
        }
    }

    public record Generic(String name) implements Type { }

    public record StringLiteral(String value) implements Type { }

    public enum Unknown implements Type { INSTANCE }

    public static boolean isAssignable(Type from, Type to) {
        Objects.requireNonNull(from);
        Objects.requireNonNull(to);
        // An unproven value cannot establish *any* structural field,
        // including one hidden behind a union. Keep unrelated gradual
        // inference compatibility for nonstructural target types.
        if ((from == Unknown.INSTANCE || from instanceof Generic)
                && containsRecordContract(to)) return false;
        if (from == Unknown.INSTANCE || to == Unknown.INSTANCE) return true;
        if (to instanceof Generic || from instanceof Generic) return true;
        if (from.equals(to)) return true;
        if (from instanceof SelfType source) {
            if (to instanceof SelfType target) {
                return isAssignable(source.bound(), target.bound())
                        && isAssignable(target.bound(), source.bound());
            }
            return isAssignable(source.bound(), to);
        }
        // A nominal base value cannot manufacture the receiver-polymorphic proof.
        if (to instanceof SelfType) return false;
        if (from instanceof StringLiteral && to == Primitive.STRING) return true;

        if (from instanceof Union source) {
            return source.options().stream().allMatch(option -> isAssignable(option, to));
        }
        if (to instanceof Union target) {
            return target.options().stream().anyMatch(option -> isAssignable(from, option));
        }

        if (from instanceof Borrow source && to instanceof Borrow target) {
            if (target.mutable() && !source.mutable()) return false;
            // No type-changing alias through a loan. Bidirectional assignability
            // is NOT type equality: Unknown/Generic can satisfy both directions.
            // Shared-borrow covariance needs an explicit lifetime/variance proof.
            return source.target().equals(target.target());
        }

        if (from instanceof Named source && to instanceof Named target && source.name().equals(target.name())) {
            // Until a declaration explicitly proves variance, generic
            // instantiations are invariant. Unknown/Generic inference is not
            // representation equivalence or permission to mutate storage.
            return source.arguments().equals(target.arguments());
        }

        if (from instanceof Record source && to instanceof Record target) {
            // A readonly view cannot recover write permission via a structural alias.
            if (source.readOnly() && !target.readOnly()) return false;
            for (Map.Entry<String, Type> required : target.members().entrySet()) {
                Type actual = source.members().get(required.getKey());
                if (actual == null) return false;
                // A callable-valued data field is not an instance method.
                if (source.methodKeys().contains(required.getKey())
                        != target.methodKeys().contains(required.getKey())) return false;
                boolean methodSlot = source.methodKeys().contains(required.getKey())
                        && target.methodKeys().contains(required.getKey())
                        && actual instanceof Function && required.getValue() instanceof Function;
                // A field read through a readonly shape view does not run a
                // conversion. In particular int -> float is an allowed value
                // conversion, but it cannot change the stored field's ABI.
                if (target.readOnly() || methodSlot) {
                    // Method dispatch uses the existing implementation ABI,
                    // not a synthesized adapter. It is just as unsafe to
                    // invent an int->float conversion for a method result.
                    if (!isRepresentationallyReadable(actual, required.getValue())) return false;
                } else if (!isAssignable(actual, required.getValue())) {
                    return false;
                }
                // Writable data slots require equal resolved types. Bidirectional
                // assignability is not enough: Unknown/Generic can match both
                // directions and would allow writes through an unsafe alias.
                // Compiler-owned callable selector slots describe methods, which
                // are immutable contracts and retain function variance.
                if (!target.readOnly() && !methodSlot && !actual.equals(required.getValue())) {
                    return false;
                }
            }
            return true;
        }

        if (from instanceof ListType source && to instanceof ListType target) {
            // Lists are mutable and cannot alias storage with a substituted
            // element type, including Unknown and unresolved generics.
            return source.element().equals(target.element());
        }

        if (from instanceof Tuple source && to instanceof Tuple target) {
            if (source.kind() != target.kind()) return false;
            if (source.elements().size() != target.elements().size()) return false;
            for (int i = 0; i < source.elements().size(); i++) {
                // Tuple projection does not synthesize numeric conversions.
                // Fixed arrays/lists are writable; those require invariance.
                Type a = source.elements().get(i), b = target.elements().get(i);
                if (source.kind() != TupleKind.TUPLE) {
                    if (!a.equals(b)) return false;
                } else if (!isRepresentationallyReadable(a, b)) {
                    return false;
                }
            }
            return true;
        }

        if (from instanceof Function source && to instanceof Function target) {
            if (source.parameters().size() != target.parameters().size()) return false;
            if (source.async() != target.async()) return false;
            // Parameter mutation authority is part of the callable contract.
            // Keep it invariant: callers and implementations must agree exactly
            // on which arguments may be mutated.
            if (!source.mutableParameters().equals(target.mutableParameters())) return false;
            for (int i = 0; i < source.parameters().size(); i++) {
                // Function subtyping does not synthesize argument adapters.
                // A primitive widening can be used for an evaluated scalar,
                // not to replace a function value with a different ABI.
                if (!isRepresentationallyReadable(
                        target.parameters().get(i), source.parameters().get(i))) return false;
            }
            return isRepresentationallyReadable(source.result(), target.result());
        }

        return numericWidening(from, to);
    }

    /**
     * An unproven whole value cannot establish a structural field contract,
     * even if the obligation is inside a union or an owned generic carrier.
     * This concerns *whole-value* Unknown/Generic inference only: ordinary
     * opaque reads of proven fields remain legal.
     */
    static boolean containsRecordContract(Type type) {
        if (type instanceof Record) return true;
        if (type instanceof Union union) {
            return union.options().stream().anyMatch(Types::containsRecordContract);
        }
        if (type instanceof Tuple tuple) {
            return tuple.elements().stream().anyMatch(Types::containsRecordContract);
        }
        if (type instanceof ListType list) {
            return containsRecordContract(list.element());
        }
        if (type instanceof Named named) {
            return named.arguments().stream().anyMatch(Types::containsRecordContract);
        }
        if (type instanceof Borrow loan) {
            return containsRecordContract(loan.target());
        }
        if (type instanceof SelfType receiver) {
            return containsRecordContract(receiver.bound());
        }
        if (type instanceof Function fn) {
            return fn.parameters().stream().anyMatch(Types::containsRecordContract)
                    || containsRecordContract(fn.result());
        }
        return false;
    }

    /**
     * Structural field views are projections, never implicit value casts.
     * Conservative without a named-type hierarchy: nominal widening is
     * proven by the context-aware TypeChecker, not fabricated here.
     * Unknown is accepted only as an opaque destination, never as a proof
     * of a required concrete field representation.
     */
    private static boolean isRepresentationallyReadable(Type actual, Type required) {
        if (actual.equals(required)) return true;
        if (required == Unknown.INSTANCE) return true;
        if (actual == Unknown.INSTANCE || actual instanceof Generic || required instanceof Generic) return false;
        if (actual instanceof Union source) {
            return source.options().stream().allMatch(option -> isRepresentationallyReadable(option, required));
        }
        if (required instanceof Union target) {
            return target.options().stream().anyMatch(option -> isRepresentationallyReadable(actual, option));
        }
        if (actual instanceof Record source && required instanceof Record target) {
            return isAssignable(source, target);
        }
        if (actual instanceof Tuple source && required instanceof Tuple target) {
            if (source.kind() != target.kind() || source.elements().size() != target.elements().size()) return false;
            for (int i = 0; i < source.elements().size(); i++) {
                if (!isRepresentationallyReadable(source.elements().get(i), target.elements().get(i))) return false;
            }
            return true;
        }
        if (actual instanceof Function source && required instanceof Function target) {
            if (source.async() != target.async()
                    || !source.mutableParameters().equals(target.mutableParameters())
                    || source.parameters().size() != target.parameters().size()) return false;
            for (int i = 0; i < source.parameters().size(); i++) {
                if (!isRepresentationallyReadable(target.parameters().get(i), source.parameters().get(i))) return false;
            }
            return isRepresentationallyReadable(source.result(), target.result());
        }
        if (actual instanceof Borrow source && required instanceof Borrow target) {
            if (target.mutable() && !source.mutable()) return false;
            return isRepresentationallyReadable(source.target(), target.target())
                    && (!target.mutable() || isRepresentationallyReadable(target.target(), source.target()));
        }
        if (actual instanceof StringLiteral && required == Primitive.STRING) return true;
        // No primitive widening, generic variance, or implicit conversions
        // for a raw field projection. A mutable ListType is invariant.
        return false;
    }

    private static boolean numericWidening(Type from, Type to) {
        if (from == Primitive.INT && (to == Primitive.FLOAT || to == Primitive.DECIMAL || to == Primitive.COMPLEX)) return true;
        if ((from == Primitive.FLOAT || from == Primitive.DECIMAL) && to == Primitive.COMPLEX) return true;
        return false;
    }

    public static Type numericJoin(Type left, Type right) {
        if (!isNumeric(left) || !isNumeric(right)) return Unknown.INSTANCE;
        if (left == Primitive.COMPLEX || right == Primitive.COMPLEX) return Primitive.COMPLEX;
        if (left == Primitive.DECIMAL || right == Primitive.DECIMAL) return Primitive.DECIMAL;
        if (left == Primitive.FLOAT || right == Primitive.FLOAT) return Primitive.FLOAT;
        return Primitive.INT;
    }

    public static Type unionOf(Type left, Type right) {
        return unionOf(List.of(left, right));
    }

    public static Type unionOf(List<Type> types) {
        java.util.ArrayList<Type> flattened = new java.util.ArrayList<>();
        for (Type type : types) {
            if (type == Unknown.INSTANCE) return Unknown.INSTANCE;
            if (type instanceof Union union) {
                for (Type option : union.options()) if (!flattened.contains(option)) flattened.add(option);
            } else if (!flattened.contains(type)) flattened.add(type);
        }
        if (flattened.isEmpty()) return Unknown.INSTANCE;
        if (flattened.size() == 1) return flattened.getFirst();
        flattened.sort(java.util.Comparator.comparing(Object::toString));
        return new Union(flattened);
    }

    /**
     * A deliberately bounded first phase of intersection semantics.
     *
     * No nominal/class/trait implementation is synthesized here. Prove a
     * representable intersection or fail closed, including for Generic/Unknown.
     * In particular, coercive numeric assignability is NOT set intersection:
     * int & float must not accidentally become int.
     */
    public static Type intersectOf(List<Type> types) {
        if (types.isEmpty()) throw new IllegalArgumentException("intersection type requires at least one operand");
        Type result = types.getFirst();
        for (int i = 1; i < types.size(); i++) result = intersectOf(result, types.get(i));
        return result;
    }

    public static Type intersectOf(Type left, Type right) {
        Objects.requireNonNull(left);
        Objects.requireNonNull(right);
        if (left.equals(right)) return left;
        if (left == Unknown.INSTANCE || right == Unknown.INSTANCE
                || left instanceof Generic || right instanceof Generic) {
            throw new IllegalArgumentException(
                    "intersection involving an unresolved generic or unknown type requires a proven runtime contract");
        }
        if (left instanceof Union union) return intersectUnion(union, right);
        if (right instanceof Union union) return intersectUnion(union, left);
        if (left instanceof StringLiteral && right == Primitive.STRING) return left;
        if (right instanceof StringLiteral && left == Primitive.STRING) return right;
        if (left instanceof Record a && right instanceof Record b) {
            if (a.readOnly() != b.readOnly()) {
                throw new IllegalArgumentException(
                        "intersection of readonly and mutable records requires per-member access capabilities");
            }
            java.util.TreeMap<String, Type> merged = new java.util.TreeMap<>(a.members());
            for (Map.Entry<String, Type> field : b.members().entrySet()) {
                Type existing = merged.get(field.getKey());
                if (existing != null && a.methodKeys().contains(field.getKey())
                        != b.methodKeys().contains(field.getKey())) {
                    throw new IllegalArgumentException(
                            "intersection field/method collision at '" + field.getKey() + "'");
                }
                if (existing == null) {
                    merged.put(field.getKey(), field.getValue());
                    continue;
                }
                if (!a.readOnly()) {
                    if (!existing.equals(field.getValue())) {
                        throw new IllegalArgumentException(
                                "intersection conflicting writable field '" + field.getKey()
                                        + "': " + existing + " vs " + field.getValue());
                    }
                } else {
                    try {
                        merged.put(field.getKey(), intersectOf(existing, field.getValue()));
                    } catch (IllegalArgumentException failure) {
                        throw new IllegalArgumentException(
                                "intersection conflicting readonly field '" + field.getKey()
                                        + "': " + failure.getMessage(), failure);
                    }
                }
            }
            java.util.Set<String> methodKeys = new java.util.HashSet<>(a.methodKeys());
            methodKeys.addAll(b.methodKeys());
            return new Record(merged, a.readOnly(), methodKeys);
        }
        throw new IllegalArgumentException(
                "intersection has no proven common value or supported representation: "
                        + left + " & " + right);
    }

    private static Type intersectUnion(Union union, Type other) {
        java.util.ArrayList<Type> common = new java.util.ArrayList<>();
        for (Type option : union.options()) {
            // Only identical alternatives are provably safe in this phase.
            if (option.equals(other)) common.add(option);
            if (other instanceof Union candidate && candidate.options().contains(option)
                    && !common.contains(option)) common.add(option);
        }
        if (common.isEmpty()) {
            throw new IllegalArgumentException("intersection has no common union alternative: "
                    + union + " & " + other);
        }
        return unionOf(common);
    }

    public static boolean isNumeric(Type type) {
        return type == Primitive.INT || type == Primitive.FLOAT || type == Primitive.DECIMAL || type == Primitive.COMPLEX;
    }
}
