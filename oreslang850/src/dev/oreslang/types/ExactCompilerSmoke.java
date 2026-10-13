package dev.oreslang.types;

import dev.oreslang.ast.Ast;
import dev.oreslang.parser.Parser;

/**
 * Exact-source parser + type checker + ownership assertions.
 * Sources mirror Oreslang Java PR #850 at 80dac1f488ee8ebfe2d9a33e7e9e620877ff14cf.
 * Intentional zero external dependencies, so this can run on an isolated
 * funded GitHub Actions runner without any cross-organization credentials.
 */
public final class ExactCompilerSmoke {
    private static int checks;

    private static Ast.Program parse(String source) {
        return Parser.parse(source);
    }

    private static void checked(String label, String source) {
        try {
            TypeChecker.check(parse(source));
            System.out.println("PASS full-check " + label);
            checks++;
        } catch (RuntimeException ex) {
            throw new AssertionError("Unexpected rejection in " + label + ": " + ex.getMessage(), ex);
        }
    }

    private static void rejectType(String label, String source, String messageContains) {
        Ast.Program ast = parse(source); // Parser failure must NOT make a negative test pass.
        try {
            TypeChecker.checkTypes(ast);
        } catch (IllegalArgumentException failure) {
            if (messageContains != null && !failure.getMessage().contains(messageContains)) {
                throw new AssertionError(label + " rejected for unrelated reason: " + failure.getMessage(), failure);
            }
            checks++;
            System.out.println("PASS type-rejected " + label + ": " + failure.getMessage());
            return;
        }
        throw new AssertionError(label + " was incorrectly type-admitted");
    }

    private static void rejectOwnership(String label, String source, String messageContains) {
        Ast.Program ast = parse(source); // A parse failure is not a borrow-safety proof.
        try {
            OwnershipChecker.check(ast);
        } catch (IllegalArgumentException failure) {
            if (messageContains != null && !failure.getMessage().contains(messageContains)) {
                throw new AssertionError(label + " rejected for unrelated reason: " + failure.getMessage(), failure);
            }
            checks++;
            System.out.println("PASS ownership-rejected " + label + ": " + failure.getMessage());
            return;
        }
        throw new AssertionError(label + " was incorrectly ownership-admitted");
    }

    public static void main(String[] args) {
        checked("owned readonly width", """
            fnc own(record{foo: int} x): int { return x.foo; }
            fnc test(): int {
                const value = infer struct{foo: 3, extra: "keep"};
                return own(value);
            }
            """);

        checked("explicit structural borrowed projection", """
            define class Candidate as
                pub val int foo = 3;
            end
            fnc inspect(structural {foo: int} x): int { return x.foo; }
            fnc test(): int { return inspect(new Candidate()); }
            """);

        checked("owned readonly async and actor function", """
            async fnc inspect(record{foo: int} x): int { return x.foo; }
            actor fnc publish(record{foo: int} x): void { return; }
            """);

        checked("safe record union read", """
            fnc read(record{foo: int | string} x): void { return; }
            fnc test(): void {
                const x = infer struct{foo: 3, extra: "keep"};
                read(x);
                return;
            }
            """);

        rejectType("numeric readonly field conversion", """
            fnc read(record{foo: float} x): void { return; }
            fnc test(): void {
                read(infer struct{foo: 3});
                return;
            }
            """, null);

        rejectType("nominal class to owned record", """
            define class Candidate as
                pub val int foo = 3;
            end
            fnc own(record{foo: int} x): void { return; }
            fnc test(): void {
                own(new Candidate());
                return;
            }
            """, "cannot implicitly convert");

        rejectType("nominal class into record-or-string union", """
            define class Candidate as
                pub val int foo = 3;
            end
            fnc test(): void {
                const bad: record{foo: int} | string = new Candidate();
                return;
            }
            """, "cannot implicitly convert");

        rejectOwnership("structural loan into owned call", """
            fnc own(record{foo: int} x): void { return; }
            fnc bad(structural {foo: int} x): void {
                own(x);
                return;
            }
            """, "cannot transfer borrowed structural data");

        rejectOwnership("structural loan into owned binding", """
            fnc bad(structural {foo: int} x): void {
                const copy: record{foo: int} = x;
                return;
            }
            """, "cannot be rebound as an owned value");

        rejectOwnership("structural loan into owned return", """
            fnc bad(structural {foo: int} x): record{foo: int} {
                return x;
            }
            """, "cannot be returned as owned data");

        rejectOwnership("borrowed aggregate destructuring provenance", """
            fnc bad(structural {foo: int} x): void {
                const {foo} = x;
                return;
            }
            """, "provenance-aware");

        System.out.println("PASS EXACT-COMPILER-SMOKE total=" + checks);
    }
}
