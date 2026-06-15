import static ghidra.pcodeCPort.slghsymbol.symbol_type.context_symbol;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.antlr.runtime.tree.CommonTree;

import ghidra.pcodeCPort.slgh_compile.SleighCompile;
import ghidra.pcodeCPort.slghsymbol.SleighSymbol;
import ghidra.pcodeCPort.slghsymbol.ValueSymbol;
import ghidra.pcodeCPort.slghsymbol.VarnodeSymbol;
import ghidra.sleigh.grammar.SleighCompiler;

public class SleighParseTreeVisitor {
    private final SleighCompile sc;

    public SleighParseTreeVisitor(final SleighCompile sc) {
        this.sc = sc;
    }

    public void visitRoot(final CommonTree tree) {
        children(tree).forEach(this::visitStatements);
    }

    private void visitStatements(final CommonTree tree) {
        if (tree.getType() == SleighCompiler.OP_CONSTRUCTOR) {
            final CommonTree table = child(tree, SleighCompiler.OP_TABLE);
            final CommonTree display = child(table, SleighCompiler.OP_DISPLAY);
            final CommonTree id = child(display, SleighCompiler.OP_IDENTIFIER);
            final String name = child(id, SleighCompiler.IDENTIFIER).getText();

            final CommonTree bitPattern = child(tree, SleighCompiler.OP_BIT_PATTERN);
            if (bitPattern.getChildren().size() > 1) {
                throw new RuntimeException("TODO: OP_BIT_PATTERN length > 1");
            }
            final List<List<BitPattern>> bits = visitBitPattern(child(bitPattern, null));

            System.out.printf("%s: %s%n", name, bits);
        }
    }

    private List<List<BitPattern>> visitBitPattern(final CommonTree bitPattern) {
        final List<List<BitPattern>> bits = new ArrayList<>();
        switch (bitPattern.getType()) {
            case SleighCompiler.OP_BOOL_OR -> children(bitPattern)
                    .forEach(orBits -> bits.add(visitBitPattern(orBits).stream()
                            .flatMap(List::stream)
                            .toList()));
            case SleighCompiler.OP_PARENTHESIZED -> children(bitPattern)
                    .forEach(parenBits -> bits.addAll(visitBitPattern(parenBits)));
            case SleighCompiler.OP_EQUAL -> {
                final CommonTree id = child(bitPattern, SleighCompiler.OP_IDENTIFIER);
                final String name = child(id, SleighCompiler.IDENTIFIER).getText();
                final SleighSymbol sym = find(name);
                if (sym.getType() == context_symbol) {
                    // Context blocks set virtual bits, which are not part of assembled bit patterns.
                    break;
                }

                final int size = switch (sym.getType()) {
                    case value_symbol -> {
                        final long max = ((ValueSymbol) sym).getPatternValue().maxValue();
                        for (int i = 0; i < 1024; i++) {
                            if (((1L << i) - 1) == max) {
                                yield i;
                            }
                        }
                        throw new RuntimeException(String.format(
                                "Unexpected OP_BIT_PATTERN value_symbol '%s' max '%s'.",
                                name,
                                max));
                    }
                    case varnode_symbol -> ((VarnodeSymbol) sym).getFixedVarnode().size;
                    default -> throw new IllegalStateException(String.format(
                            "Unexpected OP_BIT_PATTERN name type '%s'.",
                            sym.getType().name()));
                };

                final List<Long> values = switch (sym.getType()) {
                    case value_symbol -> {
                        final CommonTree hexConstant = child(bitPattern, SleighCompiler.OP_HEX_CONSTANT);
                        yield List.of(Long.parseLong(
                                child(hexConstant, SleighCompiler.HEX_INT).getText().replaceFirst("0x", ""),
                                16));
                    }
                    case varnode_symbol -> List.of(0L, (1L << size) - 1);
                    default -> throw new IllegalStateException(String.format(
                            "Unexpected OP_BIT_PATTERN name type '%s'.",
                            sym.getType().name()));
                };

                bits.add(List.of(new BitPattern(size, values)));
            }
            default -> throw new IllegalStateException(String.format(
                    "Unexpected OP_BIT_PATTERN type '%s'.",
                    SleighCompiler.tokenNames[bitPattern.getType()]));
        }

        return bits;
    }

    private List<CommonTree> children(final CommonTree tree) {
        return tree.getChildren().stream()
                .filter(CommonTree.class::isInstance)
                .map(CommonTree.class::cast)
                .toList();
    }

    private CommonTree child(final CommonTree tree, final Integer type) {
        return children(tree).stream()
                .filter(child -> type == null || child.getType() == type)
                .findFirst()
                .orElseThrow(() -> new RuntimeException(String.format(
                        "Child '%s' not found.",
                        SleighCompiler.tokenNames[type == null
                                ? 0
                                : type])));
    }

    private SleighSymbol find(final String name) {
        final SleighSymbol sym = sc.findSymbol(name);
        if (sym == null) {
            throw new IllegalStateException(String.format("Unknown name '%s'.", name));
        }

        return switch (sym.getType()) {
            case context_symbol, value_symbol, varnode_symbol -> sym;
            default -> throw new IllegalStateException(String.format(
                    "Unexpected name '%s' of type '%s'.",
                    name,
                    sym.getType().name()));
        };
    }

    public record BitPattern(int size, List<Long> values) {
        public List<? extends Number> toList() {
            return Stream.concat(Stream.of(size), values.stream()).toList();
        }
    }
}
