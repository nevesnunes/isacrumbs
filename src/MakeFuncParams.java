//Make function parameters from input registers. 
//@author flib
//@category
//@keybinding 
//@menupath 
//@toolbar 

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;

import ghidra.app.cmd.function.UpdateFunctionCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.UnsignedInteger3DataType;
import ghidra.program.model.data.UnsignedInteger5DataType;
import ghidra.program.model.data.UnsignedInteger6DataType;
import ghidra.program.model.data.UnsignedInteger7DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ContextEvaluator;
import ghidra.program.util.ContextEvaluatorAdapter;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitorAdapter;

public class MakeFuncParams extends GhidraScript {

    private static final Map<String, Set<String>> ISA_REGS_BLACKLIST = Map.of(
            "x86",
            Set.of("CS", "DS", "ES", "FS", "GS", "SS"));

    private static final int PATTERN_REG = 0b0000_0001_0000_0000;
    private static final int PATTERN_SYM_SP = 0b0000_0000_0001_0000;
    private static final int PATTERN_VAR_01 = 0b0000_0000_0000_0001;
    private static final Map<String, List<PatternElement>> PATTERNS = Map.of(
            "push",
            List.of(
                    // TODO: Also switch order.
                    PatternElement.builder().opcode(PcodeOp.COPY).in(PATTERN_REG).build(),
                    PatternElement.builder().opcode(PcodeOp.INT_SUB).in(PATTERN_REG | PATTERN_SYM_SP).build(),
                    // Decompiler action `segmentize` can introduce a CALLOTHER to compute
                    // the segmented address, which is written to a unique var, then passed
                    // as input to the following STORE.
                    PatternElement.builder().opcode(PcodeOp.STORE).build()),
            "pop",
            List.of(
                    // Decompiler action `segmentize` can introduce a CALLOTHER to compute
                    // the segmented address, which is written to a unique var, then passed
                    // as input to the following LOAD.
                    PatternElement.builder().opcode(PcodeOp.LOAD).build(),
                    // TODO: Also switch order.
                    PatternElement.builder().opcode(PcodeOp.INT_ADD).in(PATTERN_REG | PATTERN_SYM_SP).build(),
                    PatternElement.builder().opcode(PcodeOp.COPY).out(PATTERN_REG).build()),
            "clear",
            List.of(
                    PatternElement.builder()
                            .opcode(PcodeOp.INT_XOR)
                            .in(PATTERN_REG | PATTERN_VAR_01)
                            .in(PATTERN_REG | PATTERN_VAR_01)
                            .build()));

    public Program prg;

    public Language lang;
    public Listing lst;
    public ReferenceManager refMgr;

    public void init(final Program prg) {
        if (prg == null) {
            throw new RuntimeException("No program loaded.");
        }
        this.prg = prg;

        this.lang = this.prg.getLanguage();
        this.lst = this.prg.getListing();
        this.refMgr = this.prg.getReferenceManager();

        if (this.monitor == null) {
            set(this.prg, new TaskMonitorAdapter());
        }
    }

    @Override
    public void run() throws Exception {
        init(currentProgram);

        final var func = lst.getFunctionContaining(currentAddress);
        if (func == null) {
            printerr("No function defined for selected address.");
            return;
        }

        resolveParams(func);
    }

    public void resolveParams(final Function func) throws Exception {
        final Map<Address, DataType> originalFuncDataTypes = new HashMap<>();
        final Map<Address, Set<Address>> srcToDstAddrs = new HashMap<>();
        final var funcAddrSet = addressSetWithCallees(
                func,
                func.getBody().getMinAddress(),
                func.getBody().getMaxAddress());
        final var bbModel = new SimpleBlockModel(prg);
        final var bbIt = bbModel.getCodeBlocksContaining(funcAddrSet, monitor);
        while (bbIt.hasNext()) {
            final var bbBlock = bbIt.next();
            final var bbDestRefIt = bbBlock.getDestinations(monitor);
            while (bbDestRefIt.hasNext()) {
                final CodeBlockReference bbRef = bbDestRefIt.next();
                final var src = bbRef.getReferent();
                final var dst = bbRef.getReference();
                srcToDstAddrs.computeIfAbsent(src, ignoredKey -> new HashSet<>());
                srcToDstAddrs.get(src).add(dst);
                println(String.format(
                        "@ (%06x..%06x) %06x -> %06x (%s)",
                        bbBlock.getMinAddress().getUnsignedOffset(),
                        bbBlock.getMaxAddress().getUnsignedOffset(),
                        src.getUnsignedOffset(),
                        dst.getUnsignedOffset(),
                        bbRef.getFlowType()));
            }
        }

        final Map<Address, Integer> writtenBeforeReads = new HashMap<>();
        final Map<Address, Integer> readBeforeWrites = new HashMap<>();
        final Map<Address, Map<Address, Integer>> nextDstToWrittenRegs = new HashMap<>();
        final ContextEvaluator eval = new ContextEvaluatorAdapter() {
            @Override
            public boolean evaluateContextBefore(VarnodeContext context, Instruction instr) {
                if (instr.getFlowType().isCall()) {
                    // SymbolicPropagator only follows call flow for inline functions.
                    final Function callee = Arrays.stream(instr.getReferencesFrom())
                            .filter(ref -> ref.getReferenceType().isCall())
                            .map(ref -> lst.getFunctionAt(ref.getToAddress()))
                            .findFirst()
                            .orElseThrow();
                    if (!callee.isInline()) {
                        originalFuncDataTypes.put(callee.getBody().getMinAddress(), callee.getReturnType());
                        try {
                            callee.setInline(true);
                            callee.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
                        } catch (final InvalidInputException ex) {
                            printerr(ex.getMessage());
                        }
                    }
                }

                nextDstToWrittenRegs.computeIfPresent(instr.getAddress(), (k, v) -> {
                    writtenBeforeReads.clear();
                    writtenBeforeReads.putAll(v);
                    var regNames = writtenBeforeReads.keySet().stream()
                            .map(addr -> context
                                    .getRegister(new Varnode(addr, writtenBeforeReads.get(addr)))
                                    .getName())
                            .collect(Collectors.joining(","));
                    println(String.format(
                            "@ %06x <= [%s]",
                            instr.getAddress().getUnsignedOffset(),
                            regNames));
                    return v;
                });

                final boolean isStackPush = isStackPush(instr);
                final boolean isReadCleared = isReadCleared(instr);
                for (PcodeOp op : instr.getPcode()) {
                    for (Varnode in : op.getInputs()) {
                        if (in.isRegister()) {
                            if (isReadCleared) {
                                writtenBeforeReads.compute(in.getAddress(), (ignoredAddr, storedSize) -> {
                                    return storedSize == null
                                            ? in.getSize()
                                            : Math.max(storedSize, in.getSize());
                                });
                                continue;
                            }

                            final var inReg = context.getRegister(in);
                            if (isStackPush || isIgnored(inReg)) {
                                continue;
                            }

                            checkReadBeforeWrite(writtenBeforeReads, readBeforeWrites, context, instr, in, inReg);
                        }
                    }

                    final var out = op.getOutput();
                    if (out != null && out.isRegister()) {
                        writtenBeforeReads.compute(out.getAddress(), (ignoredAddr, storedSize) -> {
                            return storedSize == null
                                    ? out.getSize()
                                    : Math.max(storedSize, out.getSize());
                        });
                    }
                }

                srcToDstAddrs.computeIfPresent(instr.getAddress(), (k, v) -> {
                    v.forEach(dst -> nextDstToWrittenRegs.put(dst, new HashMap<>(writtenBeforeReads)));
                    return v;
                });

                return super.evaluateContextBefore(context, instr);
            }

            @Override
            public boolean evaluateContext(VarnodeContext context, Instruction instr) {
                if (isStackPop(instr)) {
                    var outs = Arrays.stream(instr.getResultObjects())
                            .filter(out -> out instanceof Register)
                            .map(Register.class::cast)
                            .collect(Collectors.toList());
                    if (!outs.isEmpty()) {
                        println(String.format(
                                "@ %06x outs = [%s]",
                                instr.getAddress().getUnsignedOffset(),
                                outs.stream()
                                        .map(Register::getName)
                                        .collect(Collectors.joining(","))));
                        outs.stream()
                                .map(Register::getName)
                                .forEach(outName -> {
                                    var vOut = context.getValue(
                                            context.getRegisterVarnode(context.getRegister(outName)),
                                            null);
                                    if (!vOut.isRegister()) {
                                        return;
                                    }
                                    var regOut = context.getRegister(vOut);
                                    if (isIgnored(regOut)) {
                                        return;
                                    }
                                    checkReadBeforeWrite(
                                            writtenBeforeReads,
                                            readBeforeWrites,
                                            context,
                                            instr,
                                            vOut,
                                            regOut);
                                });
                    }
                }

                return super.evaluateContext(context, instr);
            }
        };
        SymbolicPropogator symEval = new SymbolicPropogator(prg, true);
        symEval.flowConstants(
                func.getEntryPoint(),
                funcAddrSet,
                eval,
                true,
                getMonitor());

        originalFuncDataTypes.forEach((addr, dataType) -> {
            final Function callee = lst.getFunctionAt(addr);
            try {
                callee.setInline(false);
                callee.setReturnType(dataType, SourceType.USER_DEFINED);
            } catch (final InvalidInputException ex) {
                printerr(ex.getMessage());
            }
        });

        println(String.format(
                "R-b4-W: [%s]",
                readBeforeWrites.keySet().stream()
                        .map(addr -> lang.getRegister(addr, readBeforeWrites.get(addr)).getName())
                        .collect(Collectors.joining(", "))));

        // TODO:
        // ~/opt/ghidra.git/Ghidra/Features/Base/src/main/java/ghidra/app/cmd/function/NewFunctionStackAnalysisCmd.java
        // ~/opt/ghidra.git/Ghidra/Features/Base/ghidra_scripts/MakeStackRefs.java

        final var mergedReadBeforeWrites = mergeRegs(readBeforeWrites);
        println(String.format("Merged: %s", mergedReadBeforeWrites));

        if (mergedReadBeforeWrites.isEmpty()) {
            return;
        }

        final List<Parameter> params = new ArrayList<>();
        for (Register reg : mergedReadBeforeWrites) {
            params.add(toParam(reg));
        }

        for (final var param : func.getParameters()) {
            if (param.isValid() && param.isStackVariable()) {
                params.add(param);
            }
        }

        final var cmd = new UpdateFunctionCommand(
                func,
                FunctionUpdateType.CUSTOM_STORAGE,
                null,
                null,
                params,
                SourceType.USER_DEFINED,
                true);
        cmd.applyTo(prg);
    }

    public ParameterImpl toParam(final Register reg) {
        final var name = String.format("p_%s", reg.getName().toUpperCase());
        try {
            return new ParameterImpl(name, toDataRef(reg.getNumBytes()), reg, prg);
        } catch (final InvalidInputException ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    protected String decorate(final String message) {
        return message;
    }

    private Set<Register> mergeRegs(Map<Address, Integer> readBeforeWrites) {
        final var sorted = new TreeMap<>(new Comparator<Address>() {
            @Override
            public int compare(Address a1, Address a2) {
                return (int) (a1.getUnsignedOffset() - a2.getUnsignedOffset());
            }
        });
        sorted.putAll(readBeforeWrites);

        final var merged = new TreeSet<>(new Comparator<Register>() {
            @Override
            public int compare(Register r1, Register r2) {
                final var addrDiff = (int) (r1.getAddress().getUnsignedOffset()
                        - r2.getAddress().getUnsignedOffset());
                if (addrDiff == 0) {
                    return r1.getNumBytes() - r2.getNumBytes();
                }
                return addrDiff;
            }
        });
        Register r1 = null;
        for (final var entry : sorted.entrySet()) {
            final var addr = entry.getKey();
            final var size = (int) entry.getValue();
            final var r2 = lang.getRegister(addr, size);
            if (r1 == null) {
                r1 = r2;
                continue;
            } else if (r1.getAddress().add(r1.getNumBytes()).equals(r2.getAddress())) {
                final var r12 = lang.getRegister(r1.getAddress(), r1.getNumBytes() + size);
                if (r12 != null) {
                    r1 = r12;
                } else {
                    merged.add(r1);
                    r1 = r2;
                }
            } else {
                merged.add(r1);
                r1 = r2;
            }
            if (r1 != null) {
                merged.add(r1);
                r1 = null;
            }
        }
        if (r1 != null) {
            merged.add(r1);
        }

        return merged;
    }

    private static DataType toDataRef(Integer value) {
        return switch (value) {
            case 1 -> ByteDataType.dataType;
            case 2 -> WordDataType.dataType;
            case 3 -> UnsignedInteger3DataType.dataType;
            case 4 -> DWordDataType.dataType;
            case 5 -> UnsignedInteger5DataType.dataType;
            case 6 -> UnsignedInteger6DataType.dataType;
            case 7 -> UnsignedInteger7DataType.dataType;
            case 8 -> QWordDataType.dataType;
            default -> PointerDataType.dataType;
        };
    }

    /**
     * @return {@code true} if the read operand is stored in the stack.
     */
    private boolean isStackPush(final Instruction instr) {
        return isPattern(instr, PATTERNS.get("push"));
    }

    /**
     * @return {@code true} if the output operand is written by a stack value.
     */
    private boolean isStackPop(final Instruction instr) {
        return isPattern(instr, PATTERNS.get("pop"));
    }

    /**
     * @return {@code true} if the read value is cleared by the operation (e.g.
     *         {@code xor ax,ax}).
     * @implNote TODO: Propagation over sequence of instructions (e.g.
     *           {@code mov bx,ax; xor ax,bx;}).
     */
    private boolean isReadCleared(final Instruction instr) {
        return isPattern(instr, PATTERNS.get("clear"));
    }

    private boolean isPattern(final Instruction instr, final List<PatternElement> pattern) {
        final var pcode = instr.getPcode();
        final var pcodeLen = pcode.length;
        if (pcodeLen < pattern.size()) {
            return false;
        }

        var pattern_i = 0;
        for (int i = 0; i < pcode.length; i++) {
            if (pcode[i].getOpcode() != pattern.get(pattern_i).opcode()) {
                continue;
            }

            if (pcode[i].getNumInputs() < pattern.get(pattern_i).in().size()) {
                return false;
            }

            Varnode var01 = null;
            for (int j = 0; j < pattern.get(pattern_i).in().size(); j++) {
                final var inPattern = pattern.get(pattern_i).in().get(j);
                final var in = pcode[i].getInput(j);
                if ((inPattern & PATTERN_REG) != 0) {
                    if (!in.isRegister()) {
                        return false;
                    }
                    if ((inPattern & PATTERN_SYM_SP) != 0) {
                        final var sp = prg.getCompilerSpec().getStackPointer();
                        if (!in.isRegister() || !in.getAddress().equals(sp.getAddress())) {
                            return false;
                        }
                    }
                }
                if ((inPattern & PATTERN_VAR_01) != 0) {
                    if (var01 == null) {
                        var01 = in;
                    } else if (!(var01.getAddress().getAddressSpace().getName()
                            .equals(in.getAddress().getAddressSpace().getName()))
                            || (var01.getAddress().getUnsignedOffset() != in.getAddress().getUnsignedOffset())) {
                        return false;
                    }
                }
            }

            for (int j = 0; j < pattern.get(pattern_i).out().size(); j++) {
                final var outPattern = pattern.get(pattern_i).out().get(j);
                final var out = pcode[i].getOutput();
                if ((outPattern & PATTERN_REG) != 0) {
                    continue;
                }
                if (!out.isRegister()) {
                    return false;
                }
            }

            pattern_i++;

            if (pattern_i == pattern.size()) {
                return true;
            }
        }

        return pattern_i == pattern.size();
    }

    private void checkReadBeforeWrite(final Map<Address, Integer> writtenBeforeReads,
                                      final Map<Address, Integer> readBeforeWrites,
                                      final VarnodeContext context,
                                      final Instruction instr,
                                      final Varnode vnode,
                                      final Register reg) {
        if (isReadBeforeWrites(writtenBeforeReads, reg, vnode.getSize())) {
            println(String.format(
                    "@ %06x [%s] => %s [%s]",
                    instr.getAddress().getUnsignedOffset(),
                    instr.toString(),
                    reg.getName(),
                    writtenBeforeReads.keySet().stream()
                            .map(addr -> context
                                    .getRegister(new Varnode(addr, writtenBeforeReads.get(addr)))
                                    .getName())
                            .collect(Collectors.joining(","))));
            readBeforeWrites.compute(reg.getAddress(), (k, v) -> {
                final var newSize = vnode.getSize();
                return (v == null || v < newSize)
                        ? newSize
                        : v;
            });
        }
    }

    private boolean isReadBeforeWrites(final Map<Address, Integer> writtenBeforeReads,
                                       final Register inReg,
                                       final int inSize) {
        final boolean isContained = writtenBeforeReads.entrySet().stream()
                .filter(entry -> entry.getKey().getUnsignedOffset() <= inReg.getAddress().getUnsignedOffset())
                .anyMatch(entry -> entry.getKey().getUnsignedOffset()
                        + entry.getValue() >= inReg.getAddress().getUnsignedOffset() + inReg.getNumBytes());
        if (isContained) {
            return false;
        }

        // Find contiguous smaller sized registers that cover input register size.
        final Address inAddr = inReg.getAddress();
        if (writtenBeforeReads.containsKey(inAddr)) {
            final int storedSize = writtenBeforeReads.get(inAddr);
            int targetSize = storedSize - inSize;
            while (targetSize > 0) {
                final Address targetAddr = inReg.getAddress().add(inSize);
                if (writtenBeforeReads.containsKey(targetAddr)) {
                    targetSize -= writtenBeforeReads.get(targetAddr);
                } else {
                    return true;
                }
            }
            return false;
        }
        return true;
    }

    private boolean isIgnored(final Register reg) {
        final String proc = lang.getLanguageDescription().getProcessor().toString().toLowerCase();
        if (ISA_REGS_BLACKLIST.getOrDefault(proc, Collections.emptySet()).contains(reg.getName())) {
            return true;
        }
        return reg == prg.getCompilerSpec().getStackPointer()
                || reg == lang.getProgramCounter()
                || reg.isDefaultFramePointer()
                || reg.isHidden()
                || reg.isProcessorContext()
                || reg.isZero();
    }

    private AddressSet addressSetWithCallees(final Function func,
                                             final Address startAddr,
                                             final Address endAddr) {
        final AddressSet addrSet = new AddressSet(startAddr, endAddr);

        final Set<Address> seenAddrs = new HashSet<>();
        final Deque<Function> q = new ArrayDeque<>();
        func.getCalledFunctions(getMonitor()).forEach(q::push);
        while (!q.isEmpty()) {
            final Function callee = q.pop();
            if (seenAddrs.contains(callee.getBody().getMinAddress())) {
                continue;
            }
            seenAddrs.add(callee.getBody().getMinAddress());

            addrSet.addRange(callee.getBody().getMinAddress(), callee.getBody().getMaxAddress());
            callee.getCalledFunctions(getMonitor()).forEach(q::push);
        }

        return addrSet;
    }

    private record PatternElement(int opcode, List<Integer> in, List<Integer> out) {
        public static Builder builder() {
            return new Builder();
        }

        public static class Builder {
            private int opcode = -1;
            private List<Integer> in = new ArrayList<>();
            private List<Integer> out = new ArrayList<>();

            public Builder opcode(int opcode) {
                this.opcode = opcode;
                return this;
            }

            public Builder in(int in) {
                this.in.add(in);
                return this;
            }

            public Builder out(int out) {
                this.out.add(out);
                return this;
            }

            public PatternElement build() {
                return new PatternElement(opcode, in, out);
            }
        }
    }
}
