package ghidra.isacrumbs;

import ghidra.pcodeCPort.slgh_compile.SleighCompile;
import ghidra.pcodeCPort.slghpatexpress.PatternExpression;
import ghidra.pcodeCPort.slghpatexpress.PatternValue;
import ghidra.pcodeCPort.slghpatexpress.TokenPattern;
import ghidra.pcodeCPort.slghpattern.ContextPattern;
import ghidra.pcodeCPort.slghpattern.InstructionPattern;
import ghidra.pcodeCPort.slghpattern.OrPattern;
import ghidra.pcodeCPort.slghpattern.Pattern;
import ghidra.pcodeCPort.slghsymbol.*;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.IntStream;

import static ghidra.isacrumbs.SleighInstructionsVisitor.BitPattern.KIND_CONST;
import static ghidra.isacrumbs.SleighInstructionsVisitor.BitPattern.KIND_RANGE;

public class SleighInstructionsVisitor {
    private final SleighCompile sc;

    public SleighInstructionsVisitor(final SleighCompile sc) {
        this.sc = sc;
    }

    public List<SubTableBitPatterns> visitRoot() {
        final String symName = "instruction";
        if (Objects.requireNonNull(this.sc.findSymbol(symName)) instanceof SubtableSymbol sym) {
            // Populate bit masks and patterns for this symbol and its children.
            final PrintStream ps = new PrintStream(new FileOutputStream(FileDescriptor.out));
            sym.buildPattern(ps);

            final List<SubTableBitPatterns> patterns = new ArrayList<>();
            for (int i = 0; i < sym.getNumConstructors(); i++) {
                final InMemoryEncoder encoder = new InMemoryEncoder();
                try {
                    sym.getConstructor(i).encode(encoder);
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                final String encodedInstruction = encoder.get("print.constructor.piece");
                patterns.add(new SubTableBitPatterns(encodedInstruction, visitCtor(sym.getConstructor(i))));
            }

            return patterns;
        } else {
            throw new IllegalStateException(String.format("Could not find name '%s'.", symName));
        }
    }

    private List<List<BitPattern>> visitCtor(final Constructor ctor) {
        final List<List<BitPattern>> patterns = new ArrayList<>();
        final BitPattern ctorBitPattern = new BitPattern(
                KIND_CONST,
                ctor.getPattern().getLeftEllipsis(),
                ctor.getPattern().getRightEllipsis(),
                expandPattern(ctor.getPattern())
        );
        for (int i = 0; i < ctor.getNumOperands(); i++) {
            final OperandSymbol op = ctor.getOperand(i);
            if (op.isOffsetIrrelevant()) {
                // This flag is set by SleighCompile#defineOperand when the operand
                // is not a self-definition, in which case it has no pattern
                // directly associated with it.
                continue;
            }

            final List<List<BitPattern>> opTokenPatterns = Optional.ofNullable(op.getDefiningSymbol())
                    .map(sym -> switch (sym) {
                        case SubtableSymbol ss -> visitOp(ss);
                        // Registers that aren't encoded as tokens aren't part of assembled bit patterns.
                        case VarnodeSymbol ignored -> List.<List<BitPattern>>of();
                        case TripleSymbol ts -> throw new IllegalStateException(String.format(
                                "Unexpected operand name '%s'.",
                                ts.getType()
                        ));
                    })
                    .orElseGet(() -> switch (op.getDefiningExpression()) {
                        case PatternValue patternValue -> List.of(List.of(new BitPattern(
                                KIND_RANGE,
                                false,
                                false,
                                List.of(
                                        patternValue.genPattern(patternValue.minValue()).getPattern(),
                                        patternValue.genPattern(patternValue.maxValue()).getPattern()
                                )
                        )));
                        case PatternExpression patternExpression -> throw new IllegalStateException(String.format(
                                "Unexpected operand expression '%s'.",
                                patternExpression.getClass().getSimpleName()
                        ));
                    });
            patterns.addAll(opTokenPatterns.stream()
                    .map(opPatterns -> {
                        if (ctorBitPattern.length() > 0) {
                            final List<BitPattern> expandedPatterns = new ArrayList<>();
                            expandedPatterns.add(ctorBitPattern);
                            expandedPatterns.addAll(opPatterns);
                            return expandedPatterns;
                        } else {
                            return opPatterns;
                        }
                    })
                    .toList()
            );
        }

        if (patterns.isEmpty() && ctorBitPattern.length() > 0) {
            patterns.add(List.of(ctorBitPattern));
        }

        return patterns;
    }

    private List<Pattern> expandPattern(final TokenPattern pattern) {
        return switch (pattern.getPattern()) {
            case OrPattern orPattern -> IntStream.range(0, orPattern.numDisjoint())
                    .mapToObj(i -> (Pattern) orPattern.getDisjoint(i))
                    .toList();
            case Pattern ignoredPattern -> List.of(pattern.getPattern());
        };
    }

    private List<List<BitPattern>> visitOp(final SubtableSymbol sym) {
        final List<List<BitPattern>> patterns = new ArrayList<>();
        final BitPattern symBitPattern = new BitPattern(
                KIND_CONST,
                sym.getPattern().getLeftEllipsis(),
                sym.getPattern().getRightEllipsis(),
                expandPattern(sym.getPattern())
        );
        for (int i = 0; i < sym.getNumConstructors(); i++) {
            patterns.addAll(visitCtor(sym.getConstructor(i)).stream()
                    .map(ctorPatterns -> {
                        if (symBitPattern.length() > 0) {
                            final List<BitPattern> extendedPatterns = new ArrayList<>();
                            extendedPatterns.add(symBitPattern);
                            extendedPatterns.addAll(ctorPatterns);
                            return extendedPatterns;
                        } else {
                            return ctorPatterns;
                        }
                    })
                    .toList()
            );
        }

        return patterns;
    }

    /**
     * Masked bit sequence that encodes an instruction, either partially or completely.
     *
     * @param length Length of the value.
     * @param value  Bits to encode.
     */
    public record BitSequence(int length, int value) {
    }

    /**
     * Bit pattern used to generate bit sequences.
     *
     * @param length Length of each value.
     * @param kind   What each value represents.
     * @param le     {@code true} if a left ellipsis is present (i.e. the previous pattern complements this pattern).
     * @param re     {@code true} if a right ellipsis is present (i.e. the next pattern complements this pattern).
     * @param values Bits to choose when encoding.
     */
    public record BitPattern(int length,
                             int kind,
                             boolean le,
                             boolean re,
                             List<Pattern> values) {
        // Values represent literal choices.
        public static int KIND_CONST = 0;
        // Values represent [start:end] boundaries for generating all possible choices.
        public static int KIND_RANGE = 1;

        public BitPattern(int kind, boolean le, boolean re, List<Pattern> values) {
            this(values.isEmpty() ? 0 : bitsLength(values.getFirst()), kind, le, re, values);
        }

        private static int bitsLength(Pattern pattern) {
            return 8 * switch (pattern) {
                // Context blocks set virtual bits, which are not part of assembled bit patterns.
                case ContextPattern ignoredContextPattern -> 0;
                case InstructionPattern instrPattern -> instrPattern.getBlock().getLength();
                case OrPattern orPattern -> bitsLength(orPattern.getDisjoint(0));
                case Pattern ignoredPattern -> throw new IllegalStateException(String.format(
                        "Unexpected ctor pattern '%s'.",
                        pattern.getClass().getSimpleName()
                ));
            };
        }
    }

    /**
     * Bit patterns for a given instruction.
     *
     * @param name     Instruction mnemonic.
     * @param patterns Bit patterns that completely encode the instruction.
     */
    public record SubTableBitPatterns(String name, List<List<BitPattern>> patterns) {
    }
}