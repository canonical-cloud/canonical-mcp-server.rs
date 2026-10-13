package dev.oreslang;

import dev.oreslang.ast.Ast;
import dev.oreslang.parser.Parser;
import dev.oreslang.types.TypeChecker;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Linked-import tests deliberately use separate parsed source units. A
 * same-file actor reference is rejected earlier by lexical isolation, so
 * testing only one source unit cannot prove untrusted ActorRef admission.
 */
final class CrossFileActorCapabilityHardeningTest {
    private static Ast.ClassDecl exportedWorker() {
        Ast.Program worker = Parser.parse("""
                define pub actor Worker as
                    receive(ActorMail<int> mail): void {
                        self.end();
                        return;
                    }
                end
                """);
        return worker.modules().stream()
                .flatMap(module -> module.declarations().stream())
                .filter(decl -> decl instanceof Ast.ClassDecl)
                .map(decl -> (Ast.ClassDecl) decl)
                .filter(klass -> klass.name().equals("Worker"))
                .findFirst()
                .orElseThrow();
    }

    private static Ast.Program importer(String actorPrefix) {
        return Parser.parse("""
                import class Worker from "./worker.ores";

                define ACTOR_KIND actor Inbox as
                    receive(ActorMail<ActorRef<Worker>> mail): void {
                        self.end();
                        return;
                    }
                end
                """.replace("ACTOR_KIND ", actorPrefix));
    }

    @Test
    void importedWorkerActorRefIsAllowedForOrdinaryMailbox() {
        Ast.ClassDecl worker = exportedWorker();
        assertEquals(Ast.Visibility.PUBLIC, worker.visibility(),
                "the linked class must really be publicly exported");
        Ast.Program linked = importer("");
        assertDoesNotThrow(() ->
                TypeChecker.checkTypesWithImportedClasses(
                        linked, Map.of("Worker", worker), Map.of()));
    }

    @Test
    void importedWorkerActorRefIsRejectedForUntrustedMailbox() {
        Ast.ClassDecl worker = exportedWorker();
        Ast.Program linked = importer("untrusted ");
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> TypeChecker.checkTypesWithImportedClasses(
                        linked, Map.of("Worker", worker), Map.of()));
        assertTrue(error.getMessage().contains("untrusted actor"),
                "must reach untrusted transport guard, not same-file lexical rule: "
                        + error.getMessage());
    }

    @Test
    void unlinkedImportedActorRefNeverPassesAsUnknownNominal() {
        Ast.Program linked = importer("");
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> TypeChecker.checkTypesWithImportedClasses(
                        linked, Map.of(), Map.of()));
        assertTrue(error.getMessage().contains("not a known actor class")
                        || error.getMessage().contains("not a concrete actor class")
                        || error.getMessage().contains("unresolved"),
                error.getMessage());
    }
}
