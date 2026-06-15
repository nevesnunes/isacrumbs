//Backwards taint tracking for selected instruction
//@author flib
//@category
//@keybinding
//@menupath
//@toolbar

import static ghidra.program.model.pcode.PcodeOp.BOOL_AND;
import static ghidra.program.model.pcode.PcodeOp.BOOL_NEGATE;
import static ghidra.program.model.pcode.PcodeOp.BOOL_OR;
import static ghidra.program.model.pcode.PcodeOp.BOOL_XOR;
import static ghidra.program.model.pcode.PcodeOp.CALLOTHER;
import static ghidra.program.model.pcode.PcodeOp.CAST;
import static ghidra.program.model.pcode.PcodeOp.COPY;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_ABS;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_ADD;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_CEIL;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_DIV;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_FLOOR;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_MULT;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_NAN;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_NEG;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_ROUND;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_SQRT;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_SUB;
import static ghidra.program.model.pcode.PcodeOp.INDIRECT;
import static ghidra.program.model.pcode.PcodeOp.INT_ADD;
import static ghidra.program.model.pcode.PcodeOp.INT_AND;
import static ghidra.program.model.pcode.PcodeOp.INT_CARRY;
import static ghidra.program.model.pcode.PcodeOp.INT_DIV;
import static ghidra.program.model.pcode.PcodeOp.INT_LEFT;
import static ghidra.program.model.pcode.PcodeOp.INT_MULT;
import static ghidra.program.model.pcode.PcodeOp.INT_NEGATE;
import static ghidra.program.model.pcode.PcodeOp.INT_OR;
import static ghidra.program.model.pcode.PcodeOp.INT_REM;
import static ghidra.program.model.pcode.PcodeOp.INT_RIGHT;
import static ghidra.program.model.pcode.PcodeOp.INT_SBORROW;
import static ghidra.program.model.pcode.PcodeOp.INT_SCARRY;
import static ghidra.program.model.pcode.PcodeOp.INT_SDIV;
import static ghidra.program.model.pcode.PcodeOp.INT_SEXT;
import static ghidra.program.model.pcode.PcodeOp.INT_SREM;
import static ghidra.program.model.pcode.PcodeOp.INT_SRIGHT;
import static ghidra.program.model.pcode.PcodeOp.INT_SUB;
import static ghidra.program.model.pcode.PcodeOp.INT_XOR;
import static ghidra.program.model.pcode.PcodeOp.INT_ZEXT;
import static ghidra.program.model.pcode.PcodeOp.LOAD;
import static ghidra.program.model.pcode.PcodeOp.MULTIEQUAL;
import static ghidra.program.model.pcode.PcodeOp.STORE;
import static ghidra.program.model.pcode.PcodeOp.UNIMPLEMENTED;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Stack;
import java.util.TreeMap;
import java.util.stream.Collectors;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.TaskMonitorAdapter;

public class BackTaint extends GhidraScript {

    private static final Map<String, Set<String>> ISA_REGS_BLACKLIST = Map.of(
            "x86",
            Set.of("CS", "DS", "ES", "FS", "GS", "SS"));

    public Program prg;
    public Address sink;

    public Language lang;
    public Listing lst;
    public ReferenceManager refMgr;

    private final Map<Address, TrackedFunction> trackedFuncCache = new HashMap<>();

    @Override
    protected void run() throws Exception {
        init(currentProgram, currentAddress);
        flow();
    }

    @Override
    protected String decorate(final String message) {
        return message;
    }

    public void init(final Program prg, final Address sink) {
        if (prg == null) {
            throw new RuntimeException("No program loaded.");
        }
        this.prg = prg;
        if (sink == null) {
            throw new RuntimeException("No address selected.");
        }
        this.sink = sink;

        this.lang = this.prg.getLanguage();
        this.lst = this.prg.getListing();
        this.refMgr = this.prg.getReferenceManager();

        if (this.monitor == null) {
            set(this.prg, new TaskMonitorAdapter());
        }
    }

    public TaintContext flow() throws Exception {
        var ctx = newCtx();
        while (!monitor.isCancelled()) {
            if (!ctx.nextSeqNums.isEmpty()) {
                flow(ctx.nextSeqNums.pop(), ctx);
                continue;
            }

            if (!ctx.nextInstrs.isEmpty()) {
                flow(ctx.nextInstrs.pop(), ctx);
                continue;
            }

            break;
        }
        log(ctx);

        return ctx;
    }

    private TaintContext newCtx() throws Exception {
        var sinkFunc = lst.getFunctionContaining(sink);
        if (sinkFunc == null) {
            throw new RuntimeException("No function defined for selected address.");
        }

        var trackedFunc = decompile(sinkFunc);
        var pcodeBB = trackedFunc.highFunc.getBasicBlocks().stream()
                .filter(bb -> bb.contains(sink))
                .findFirst()
                .orElseThrow();

        // Sanity check: A sink must be present in a single bb.
        var bbs = new SimpleBlockModel(currentProgram).getCodeBlocksContaining(sink, monitor);
        if (bbs.length != 1) {
            throw new RuntimeException(String.format("Expected 1 bb, got %d.", bbs.length));
        }

        // Dependencies for this sink may be found in this bb, at or before the selected address.
        var ctx = new TaintContext();
        var it = lst.getInstructions(bbs[0], true);
        while (it.hasNext()) {
            monitor.checkCancelled();

            var instr = it.next();
            if (instr.getAddress().getUnsignedOffset() == sink.getUnsignedOffset()) {
                ctx.nextInstrs.push(instr);
            }
        }
        if (ctx.nextInstrs.isEmpty()) {
            throw new RuntimeException(String.format(
                    "Empty code block @ %08x.",
                    sink.getUnsignedOffset()));
        }

        return ctx;
    }

    private TrackedFunction decompile(final Function currentFunc) {
        if (trackedFuncCache.containsKey(currentFunc.getEntryPoint())) {
            return trackedFuncCache.get(currentFunc.getEntryPoint());
        }

        var dec = new DecompInterface();
        dec.setOptions(new DecompileOptions());
        dec.setSimplificationStyle("firstpass");
        dec.openProgram(prg);

        var decFuncRes = dec.decompileFunction(currentFunc, 10, monitor);
        var highFunc = decFuncRes.getHighFunction();
        if (highFunc == null) {
            throw new RuntimeException("Null high function.");
        }

        List<PcodeOp> pcodeOps = new ArrayList<>();
        var pcodeIt = highFunc.getPcodeOps();
        while (pcodeIt.hasNext()) {
            pcodeOps.add(pcodeIt.next());
        }
        Collections.sort(pcodeOps, new Comparator<PcodeOp>() {
            @Override
            public int compare(PcodeOp o1, PcodeOp o2) {
                int addrDiff = (int) (o1.getSeqnum().getTarget().getUnsignedOffset()
                        - o2.getSeqnum().getTarget().getUnsignedOffset());
                return addrDiff == 0
                        ? o1.getSeqnum().getOrder() - o2.getSeqnum().getOrder()
                        : addrDiff;
            }
        });
        Map<Address, TreeMap<Integer, PcodeOp>> numberedOps = new HashMap<>();
        for (var op : pcodeOps) {
            numberedOps
                    .computeIfAbsent(op.getSeqnum().getTarget(), ignoredKey -> new TreeMap<>())
                    .put(op.getSeqnum().getOrder(), op);
            println(fmt(highFunc, op));
        }

        var trackedFunc = new TrackedFunction(highFunc, numberedOps);
        trackedFuncCache.put(currentFunc.getEntryPoint(), trackedFunc);

        return trackedFunc;
    }

    private void flow(final Address bbAddr, final TaintContext ctx) {
        if (ctx.nextInstrs.isEmpty() && ctx.nextBBs.isEmpty()) {
            // TODO: prev instr is CALL?
        }
    }

    private void flow(final Instruction instr, final TaintContext ctx) {
        println(String.format(
                "%08x: %s",
                instr.getAddress().getUnsignedOffset(),
                instr));

        var refIt = instr.getReferenceIteratorTo();
        while (refIt.hasNext()) {
            final Reference ref = refIt.next();
            if (ref.isMemoryReference()) {
                ctx.nextBBs.add(ref.getFromAddress());
            }
        }

        // Clear temporary variables from previous pcodeOps.
        ctx.deps.keySet().stream()
                .filter(vnode -> vnode.isUnique())
                .forEach(ctx.deps::remove);

        var pcodeOps = trackedFuncCache.get(lst.getFunctionContaining(instr.getAddress()).getEntryPoint()).numberedOps
                .get(instr.getAddress())
                .reversed();
        for (final PcodeOp pcodeOp : pcodeOps.values()) {
            flow(pcodeOp, instr, ctx);
        }
    }

    private void flow(final PcodeOp pcodeOp, final Instruction instr, final TaintContext ctx) {
        log(pcodeOp);

        final Address instrAddr = instr.getAddress();
        final Varnode out = out(pcodeOp);

        // Find the initial dependencies for this sink.
        // TODO: Support memory addresses.
        if (ctx.sinks.isEmpty()) {
            if (out == null || !out.isRegister()) {
                return;
            }

            var regOut = lang.getRegister(out.getAddress(), out.getSize());
            if (regOut == null) {
                throw new RuntimeException(String.format("Null reg '%s'", out));
            }

            var instrRegOuts = Arrays.stream(instr.getResultObjects())
                    .filter(o -> o instanceof Register)
                    .map(Register.class::cast)
                    .filter(reg -> !isIgnored(reg))
                    .collect(Collectors.toList());
            if (instrRegOuts.size() > 1) {
                throw new RuntimeException(String.format("Multiple outs: '%s'", instrRegOuts));
            }

            if (!instrRegOuts.isEmpty()) {
                var instrRegOut = instrRegOuts.getFirst();
                if (regOut.equals(instrRegOut)) {
                    for (final Varnode vnode : pcodeOp.getInputs()) {
                        println(String.format("......... + %s", fmt(vnode)));
                        ctx.deps.put(vnode, instrAddr);
                        if (vnode.getDef() != null) {
                            ctx.nextSeqNums.push(vnode.getDef().getSeqnum());
                        }
                    }
                    ctx.sinks.put(out, instrAddr);
                }
            }

            return;
        }

        if (ctx.deps.isEmpty()) {
            printerr("No dependencies to flow into.");
            return;
        }

        // TODO: Model stack for push/pop macros used as function prologue/epilogue.
        // ghidra.program.util.SymbolicPropogator.applyPcode()
        switch (pcodeOp.getOpcode()) {
            case LOAD:
                // TODO: Resolve segmented reg/mem values from ctx?
                if (pcodeOp.getNumInputs() == 2 && pcodeOp.getInput(1).isAddress()) {
                    ctx.memReads.computeIfAbsent(
                            out.getAddress(),
                            k -> new HashSet<>());
                    ctx.memReads.get(pcodeOp.getInput(1).getAddress())
                            .add(instrAddr);
                }
                taint(ctx, instrAddr, pcodeOp, out);
                break;
            case STORE:
                if (ctx.deps.containsKey(out) && out.isAddress()) {
                    ctx.memWrites.computeIfAbsent(
                            out.getAddress(),
                            k -> new HashSet<>());
                    ctx.memWrites.get(out.getAddress()).add(instrAddr);
                }
                taint(ctx, instrAddr, pcodeOp, out);
                break;
            case CALLOTHER:
                // Assume userops unconditionally read all inputs.
                // TODO: Process hooks from .pspec files, keyed by language id.
                taint(ctx, instrAddr, pcodeOp, out);
                break;
            case CAST, COPY, INDIRECT, MULTIEQUAL,
                    BOOL_AND, BOOL_NEGATE, BOOL_OR, BOOL_XOR,
                    FLOAT_ABS, FLOAT_ADD, FLOAT_CEIL, FLOAT_DIV,
                    FLOAT_FLOOR, FLOAT_MULT, FLOAT_NAN, FLOAT_NEG,
                    FLOAT_ROUND, FLOAT_SQRT, FLOAT_SUB,
                    INT_ADD, INT_AND, INT_CARRY, INT_DIV,
                    INT_LEFT, INT_MULT, INT_NEGATE, INT_OR,
                    INT_REM, INT_RIGHT, INT_SBORROW, INT_SCARRY,
                    INT_SDIV, INT_SEXT, INT_SREM, INT_SRIGHT,
                    INT_SUB, INT_XOR, INT_ZEXT:
                taint(ctx, instrAddr, pcodeOp, out);
                break;
            case UNIMPLEMENTED:
                printerr(String.format(
                        "Unimplemented opcode: %s.",
                        PcodeOp.getMnemonic(pcodeOp.getOpcode())));
                break;
            default:
                printerr(String.format(
                        "Unhandled opcode: %s.",
                        PcodeOp.getMnemonic(pcodeOp.getOpcode())));
                return;
        }
    }

    private void flow(final SequenceNumber seqnum, final TaintContext ctx) {
        ctx.nextInstrs.push(lst.getInstructionAt(seqnum.getTarget()));
    }

    private void taint(final TaintContext ctx,
                       final Address instrAddr,
                       final PcodeOp pcodeOp,
                       final Varnode dst) {
        if (ctx.deps.containsKey(dst)) {
            ctx.deps.remove(dst);
            println(String.format("......... - %s", fmt(dst)));

            for (final Varnode in : pcodeOp.getInputs()) {
                if (in.isRegister() && isIgnored(lang.getRegister(in.getAddress(), in.getSize()))) {
                    continue;
                }

                ctx.deps.put(in, instrAddr);
                println(String.format("......... + %s", fmt(in)));
            }
        }
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

    private Varnode out(final PcodeOp pcodeOp) {
        if (pcodeOp.getOpcode() == STORE) {
            return pcodeOp.getInput(1);
        }
        return pcodeOp.getOutput();
    }

    private void log(final TaintContext ctx) {
        if (!ctx.sinks().isEmpty()) {
            var sinkVnode = List.copyOf(ctx.sinks().entrySet()).get(0).getKey();
            var sinkAddr = ctx.sinks().get(sinkVnode);
            println(String.format("Dependencies for sink %s:", fmt(sinkVnode)));
            ctx.deps.forEach((vnode, addr) -> {
                println(String.format(
                        "......... < %s @ %08x",
                        fmt(vnode),
                        addr.getUnsignedOffset()));
            });
        }

        println(String.format(
                "Mem R:[%s] W:[%s]",
                ctx.memReads.entrySet().stream()
                        .map(entry -> String.format("%08x @ %s",
                                entry.getKey().getUnsignedOffset(),
                                entry.getValue().stream()
                                        .map(addr -> String.format("%08x",
                                                addr.getUnsignedOffset()))
                                        .collect(Collectors.joining(","))))
                        .collect(Collectors.joining(",")),
                ctx.memWrites.entrySet().stream()
                        .map(entry -> String.format("%08x @ %s",
                                entry.getKey().getUnsignedOffset(),
                                entry.getValue().stream()
                                        .map(addr -> String.format("%08x",
                                                addr.getUnsignedOffset()))
                                        .collect(Collectors.joining(","))))
                        .collect(Collectors.joining(","))));
        println(String.format(
                "Next BBs:[%s]",
                ctx.nextBBs.stream()
                        .map(addr -> String.format("%08x", addr.getUnsignedOffset()))
                        .collect(Collectors.joining(","))));
    }

    private void log(final PcodeOp pcodeOp) {
        println(String.format("......... pcode: %s", pcodeOp));
        for (final Varnode vnode : pcodeOp.getInputs()) {
            println(String.format("......... < %s", fmt(vnode)));
        }
        println(String.format("......... > %s", fmt(out(pcodeOp))));
    }

    private String fmt(final HighFunction highFunc, final PcodeOp op) {
        final StringBuilder sb = new StringBuilder();
        sb.append(String.format("%08x:%02d: ",
                op.getSeqnum().getTarget().getUnsignedOffset(),
                op.getSeqnum().getOrder()));
        var out = op.getOutput();
        if (out != null) {
            sb.append(String.format("%s = ", fmt(out)));
        }
        sb.append(String.format("%s(", op.getMnemonic()));
        if (op.getNumInputs() > 0) {
            sb.append(Arrays.stream(op.getInputs())
                    .map(in -> fmt(in)).collect(Collectors.joining(", ")));
        }
        sb.append(")");
        if (op.getOpcode() == PcodeOp.INDIRECT) {
            var sq = new SequenceNumber(op.getSeqnum().getTarget(),
                    (int) op.getInput(op.getNumInputs() == 1
                            ? 0
                            : 1)
                            .getOffset());
            var iop = highFunc.getPcodeOp(sq);
            if (iop != null) {
                sb.append(String.format(" -> %s", fmt(highFunc, iop)));
            }
        }
        return sb.toString();
    }

    private String fmt(final Varnode vnode) {
        if (vnode == null) {
            return "(null)";
        } else if (vnode.isRegister()) {
            final Register reg = prg.getLanguage().getRegister(vnode.getAddress(), vnode.getSize());
            final String name = (reg == null)
                    ? String.format("r0x%x:%d",
                            vnode.getAddress().getUnsignedOffset(),
                            vnode.getSize())
                    : reg.getName();
            final StringBuilder sb = new StringBuilder();
            sb.append(name);
            if (vnode.getDef() != null) {
                sb.append(String.format("(%08x:%02d)",
                        vnode.getDef().getSeqnum().getTarget().getUnsignedOffset(),
                        vnode.getDef().getSeqnum().getOrder()));
            }
            return sb.toString();
        } else if (vnode.isAddress()) {
            return String.format("0x%08x", vnode.getAddress().getUnsignedOffset());
        } else if (vnode.isUnique()) {
            if (vnode.getDef() != null) {
                return String.format("u0x%08x(%08x:%02d)",
                        vnode.getOffset(),
                        vnode.getDef().getSeqnum().getTarget().getUnsignedOffset(),
                        vnode.getDef().getSeqnum().getOrder());
            }
            return String.format("u0x%08x", vnode.getOffset());
        }
        return String.format("0x%x", vnode.getOffset());
    }

    private record TrackedFunction(HighFunction highFunc, Map<Address, TreeMap<Integer, PcodeOp>> numberedOps) {
    }

    public record TaintContext(
            Map<Varnode, Address> sinks,
            Map<Varnode, Address> deps,
            Map<Address, Set<Address>> memReads,
            Map<Address, Set<Address>> memWrites,
            Stack<Address> nextBBs,
            Stack<Instruction> nextInstrs,
            Stack<SequenceNumber> nextSeqNums) {
        public TaintContext() {
            this(
                    new HashMap<>(),
                    new HashMap<>(),
                    new HashMap<>(),
                    new HashMap<>(),
                    new Stack<>(),
                    new Stack<>(),
                    new Stack<>());
        }
    }
}
