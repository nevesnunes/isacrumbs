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
import static ghidra.program.model.pcode.PcodeOp.CALL;
import static ghidra.program.model.pcode.PcodeOp.CALLOTHER;
import static ghidra.program.model.pcode.PcodeOp.CAST;
import static ghidra.program.model.pcode.PcodeOp.COPY;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_ABS;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_ADD;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_CEIL;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_DIV;
import static ghidra.program.model.pcode.PcodeOp.FLOAT_EQUAL;
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
import static ghidra.program.model.pcode.PcodeOp.INT_EQUAL;
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
import static ghidra.program.model.pcode.PcodeOp.INT_SLESS;
import static ghidra.program.model.pcode.PcodeOp.INT_SREM;
import static ghidra.program.model.pcode.PcodeOp.INT_SRIGHT;
import static ghidra.program.model.pcode.PcodeOp.INT_SUB;
import static ghidra.program.model.pcode.PcodeOp.INT_XOR;
import static ghidra.program.model.pcode.PcodeOp.INT_ZEXT;
import static ghidra.program.model.pcode.PcodeOp.LOAD;
import static ghidra.program.model.pcode.PcodeOp.MULTIEQUAL;
import static ghidra.program.model.pcode.PcodeOp.SEGMENTOP;
import static ghidra.program.model.pcode.PcodeOp.STORE;
import static ghidra.program.model.pcode.PcodeOp.UNIMPLEMENTED;

import java.io.PrintWriter;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
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
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitorAdapter;

public class BackTaint extends GhidraScript {

    private static final Map<String, Set<String>> ISA_REGS_BLACKLIST = Map.of(
            "x86",
            Set.of("CS", "DS", "ES", "FS", "GS", "SS"));
    private static final Map<String, Set<String>> ISA_FLAGS = Map.of(
            "x86",
            Set.of("AF", "CF", "OF", "PF", "SF", "ZF"));

    static Program prg;
    static PrintWriter scriptWriter;

    private Address sink;
    private final Map<Address, TrackedFunction> trackedFuncCache = new HashMap<>();
    private final Patterns patternMatcher = new Patterns();

    @Override
    protected void run() throws Exception {
        init(currentProgram, currentAddress, Collections.emptySet());
        flow();
    }

    @Override
    protected String decorate(final String message) {
        return message;
    }

    public static void log(final String message) {
        scriptWriter.println(message);
    }

    public void init(final Program program, final Address sink, final Set<String> funcAddrs) {
        if (program == null) {
            throw new RuntimeException("No program loaded.");
        }
        prg = program;

        if (sink == null) {
            throw new RuntimeException("No address selected.");
        }
        this.sink = sink;

        scriptWriter = this.writer == null
                ? new PrintWriter(System.out, true)
                : this.writer;
        if (this.monitor == null) {
            set(prg, new TaskMonitorAdapter());
        }

        funcAddrs.forEach(funcAddr -> decompile(
                prg.getFunctionManager().getFunctionContaining(prg.getAddressFactory().getAddress(funcAddr))));
    }

    record BBContext(Address addr, Set<Address> seenBBAddrs, TaintContext tctx) {
    }

    public TaintContext flow() throws Exception {
        final List<TaintContext> endCtxs = new ArrayList<>();

        final Deque<BBContext> nextBBCtxs = new ArrayDeque<>();
        nextBBCtxs.push(new BBContext(sink, Collections.emptySet(), new TaintContext()));
        while (!monitor.isCancelled() && !nextBBCtxs.isEmpty()) {
            var bbctx = nextBBCtxs.pop();
            var visitor = new BackTaintVisitor(bbctx.tctx);
            var propagator = new BackPropagator(bbctx.addr, bbctx.seenBBAddrs, visitor);
            while (!monitor.isCancelled() && propagator.flow()) {
            }

            log(propagator);
            propagator.pctx.nextBBs.removeAll(bbctx.seenBBAddrs);
            if (propagator.pctx.nextBBs.isEmpty()) {
                endCtxs.add(visitor.tctx.clone());
            }

            final Set<Address> nextSeenBBAddrs = new HashSet<>();
            nextSeenBBAddrs.add(bbctx.addr);
            nextSeenBBAddrs.addAll(bbctx.seenBBAddrs);
            nextSeenBBAddrs.addAll(propagator.pctx.nextBBs.ignored());
            propagator.pctx.nextBBs
                    .forEach(nextBB -> nextBBCtxs.add(new BBContext(nextBB, nextSeenBBAddrs, visitor.tctx.clone())));
        }

        var mergedTaintContext = merge(endCtxs);
        log("Merged =>");
        log(mergedTaintContext);

        return mergedTaintContext;
    }

    private TaintContext merge(final Collection<TaintContext> ctxs) {
        return new TaintContext(
                new HashMap<Varnode, Address>(ctxs.stream().map(TaintContext::sinks)
                        .flatMap(map -> map.entrySet().stream())
                        .collect(Collectors.toMap(
                                Map.Entry::getKey,
                                Map.Entry::getValue,
                                (oldValue, newValue) -> newValue))),
                new HashMap<Varnode, Address>(ctxs.stream().map(TaintContext::deps)
                        .flatMap(map -> map.entrySet().stream())
                        .collect(Collectors.toMap(
                                Map.Entry::getKey,
                                Map.Entry::getValue,
                                (oldValue, newValue) -> newValue))),
                new HashMap<Varnode, Address>(ctxs.stream().map(TaintContext::memReadsUnresolved)
                        .flatMap(map -> map.entrySet().stream())
                        .collect(Collectors.toMap(
                                Map.Entry::getKey,
                                Map.Entry::getValue,
                                (oldValue, newValue) -> newValue))),
                new HashMap<Address, Set<Address>>(ctxs.stream().map(TaintContext::memReads)
                        .flatMap(map -> map.entrySet().stream())
                        .collect(Collectors.toMap(
                                Map.Entry::getKey,
                                Map.Entry::getValue,
                                (oldValue, newValue) -> {
                                    var set = new HashSet<Address>();
                                    set.addAll(oldValue);
                                    set.addAll(newValue);
                                    return set;
                                }))),
                new HashMap<Address, Set<Address>>(ctxs.stream().map(TaintContext::memWrites)
                        .flatMap(map -> map.entrySet().stream())
                        .collect(Collectors.toMap(
                                Map.Entry::getKey,
                                Map.Entry::getValue,
                                (oldValue, newValue) -> {
                                    var set = new HashSet<Address>();
                                    set.addAll(oldValue);
                                    set.addAll(newValue);
                                    return set;
                                }))));
    }

    public TrackedFunction decompile(final Function func) {
        if (func == null) {
            return null;
        }

        if (trackedFuncCache.containsKey(func.getEntryPoint())) {
            return trackedFuncCache.get(func.getEntryPoint());
        }
        log(String.format("Decompiling '%s' @ %08x.", func.getName(), func.getEntryPoint().getUnsignedOffset()));

        var dec = new DecompInterface();
        dec.setOptions(new DecompileOptions());
        dec.setSimplificationStyle("firstpass");
        dec.openProgram(prg);

        var decFuncRes = dec.decompileFunction(func, 10, monitor);
        var highFunc = decFuncRes.getHighFunction();
        if (highFunc == null) {
            throw new RuntimeException("Null high function.");
        }

        var numberedOps = expandOps(highFunc);
        var trackedFunc = new TrackedFunction(highFunc, numberedOps);
        trackedFuncCache.put(func.getEntryPoint(), trackedFunc);

        // Segmented memory address references are not identified on the first pass,
        // so they are found and created explicitly here, before dependency tracking starts.
        createMemXRefs(trackedFunc);

        return trackedFunc;
    }

    private record TrackedReference(Address from, Address to, RefType type) {
    }

    private void createMemXRefs(final TrackedFunction func) {
        // TODO: Pass map of assumed register values (e.g. captured via dynamic instruction trace).
        final var memPatterns = Map.of("memread", RefType.READ, "memwrite", RefType.WRITE);
        for (var entry : func.numberedOps.entrySet()) {
            var addr = entry.getKey();
            var ops = entry.getValue().values().stream().collect(Collectors.toList());
            memPatterns.forEach((k, refType) -> {
                if (!patternMatcher.match(ops, Patterns.PATTERNS.get(k))) {
                    return;
                }

                log(String.format("MEM %s @ %08x", refType.getName(), addr.getUnsignedOffset()));
                var memAddrOp = prg.getListing().getInstructionAt(addr).getInputObjects()[1];
                if (!(memAddrOp instanceof Scalar)) {
                    return;
                }

                var memAddrVal = ((Scalar) memAddrOp).getUnsignedValue();
                var memAddr = prg.getAddressFactory().getAddress(String.format("0x%08x", memAddrVal));
                var instrRefs = Arrays.asList(prg.getListing().getInstructionAt(addr).getReferencesFrom()).stream()
                        .map(ref -> new TrackedReference(
                                ref.getFromAddress(),
                                ref.getToAddress(),
                                ref.getReferenceType()))
                        .collect(Collectors.toSet());
                if (instrRefs.contains(new TrackedReference(addr, memAddr, refType))) {
                    return;
                }

                prg.getReferenceManager().addMemoryReference(addr, memAddr, refType, SourceType.USER_DEFINED, 1);
            });
        }
    }

    private Map<Address, TreeMap<Integer, PcodeOp>> expandOps(final HighFunction highFunc) {
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
            log(fmt(highFunc, op));
        }
        return numberedOps;
    }

    private void taint(final TaintContext ctx,
                       final Address instrAddr,
                       final PcodeOp pcodeOp,
                       final Varnode dst) {
        final var dep = ctx.asDep(dst);
        if (dep != null) {
            ctx.rmDep(dst);

            for (final Varnode in : pcodeOp.getInputs()) {
                if (in.isRegister() && isIgnored(prg.getRegister(in.getAddress(), in.getSize()))) {
                    continue;
                }

                ctx.deps.put(in, instrAddr);
                log(String.format("......... + (taint) %s", fmt(in)));
            }
        }
    }

    private boolean isIgnored(final Register reg) {
        final String proc = prg.getLanguage().getLanguageDescription().getProcessor().toString().toLowerCase();
        if (ISA_REGS_BLACKLIST.getOrDefault(proc, Collections.emptySet()).contains(reg.getName())) {
            return true;
        }
        if (ISA_FLAGS.getOrDefault(proc, Collections.emptySet()).contains(reg.getName())) {
            return true;
        }
        return reg == prg.getCompilerSpec().getStackPointer()
                || reg == prg.getLanguage().getProgramCounter()
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

    private void log(final BackPropagator propagator) {
        log(((BackTaintVisitor) propagator.visitor).tctx);
        log(String.format(
                "Next BBs:[%s]",
                propagator.pctx.nextBBs.stream()
                        .map(addr -> String.format("%08x", addr.getUnsignedOffset()))
                        .collect(Collectors.joining(", "))));
    }

    private void log(final TaintContext tctx) {
        log(String.format(
                "Sinks:[%s] Deps:[%s]",
                tctx.sinks.entrySet().stream()
                        .map(entry -> String.format("%s @ %08x",
                                fmt(entry.getKey()),
                                entry.getValue().getUnsignedOffset()))
                        .collect(Collectors.joining(", ")),
                tctx.deps.entrySet().stream()
                        .map(entry -> String.format("%s @ %08x",
                                fmt(entry.getKey()),
                                entry.getValue().getUnsignedOffset()))
                        .collect(Collectors.joining(", "))));
        log(String.format(
                "Mem R:[%s] (Unrsv:[%s]) W:[%s]",
                tctx.memReads.entrySet().stream()
                        .map(entry -> String.format("%08x @ %s",
                                entry.getKey().getUnsignedOffset(),
                                entry.getValue().stream()
                                        .map(addr -> String.format("%08x",
                                                addr.getUnsignedOffset()))
                                        .collect(Collectors.joining(","))))
                        .collect(Collectors.joining(", ")),
                tctx.memReadsUnresolved.entrySet().stream()
                        .map(entry -> String.format("%s @ %08x",
                                fmt(entry.getKey()),
                                entry.getValue().getUnsignedOffset()))
                        .collect(Collectors.joining(", ")),
                tctx.memWrites.entrySet().stream()
                        .map(entry -> String.format("%08x @ %s",
                                entry.getKey().getUnsignedOffset(),
                                entry.getValue().stream()
                                        .map(addr -> String.format("%08x",
                                                addr.getUnsignedOffset()))
                                        .collect(Collectors.joining(","))))
                        .collect(Collectors.joining(", "))));
    }

    private void log(Reference ref) {
        log(String.format(
                "ref[%02x](%s): %08x->%08x",
                ref.getOperandIndex(),
                ref.getReferenceType().getName(),
                ref.getFromAddress().getUnsignedOffset(),
                ref.getToAddress().getUnsignedOffset()));
    }

    private void log(final PcodeOp pcodeOp) {
        log(String.format("......... pcode: %s", pcodeOp));
        for (final Varnode vnode : pcodeOp.getInputs()) {
            log(String.format("......... < %s", fmt(vnode)));
        }
        log(String.format("......... > %s", fmt(out(pcodeOp))));
    }

    private String fmt(final HighFunction highFunc, final PcodeOp op) {
        final StringBuilder sb = new StringBuilder();
        sb.append(String.format("%08x:%02x: ",
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

    private static String fmt(final Varnode vnode) {
        if (vnode == null) {
            return "(null)";
        } else if (vnode.isRegister()) {
            final Register reg = prg.getRegister(vnode.getAddress(), vnode.getSize());
            final String name = (reg == null)
                    ? String.format("r0x%08x:%04x",
                            vnode.getAddress().getUnsignedOffset(),
                            vnode.getSize())
                    : reg.getName();
            final StringBuilder sb = new StringBuilder();
            sb.append(name);
            if (vnode.getDef() != null) {
                sb.append(String.format("(%08x:%02x)",
                        vnode.getDef().getSeqnum().getTarget().getUnsignedOffset(),
                        vnode.getDef().getSeqnum().getOrder()));
            }
            return sb.toString();
        } else if (vnode.isAddress()) {
            return String.format("0x%08x", vnode.getAddress().getUnsignedOffset());
        } else if (vnode.isUnique()) {
            if (vnode.getDef() != null) {
                return String.format("u0x%08x(%08x:%02x)",
                        vnode.getOffset(),
                        vnode.getDef().getSeqnum().getTarget().getUnsignedOffset(),
                        vnode.getDef().getSeqnum().getOrder());
            }
            return String.format("u0x%08x", vnode.getOffset());
        }
        return String.format("0x%08x", vnode.getOffset());
    }

    static class DistinctStack<E> extends Stack<E> {
        private Set<E> set = new HashSet<>();

        public void ignoreAll(Set<E> items) {
            this.set.addAll(items);
        }

        public Set<E> ignored() {
            return this.set;
        }

        @Override
        public E push(E item) {
            if (!this.set.contains(item)) {
                this.set.add(item);
                super.push(item);
            }

            return item;
        }
    }

    class BackPropagator {
        public PropagatorContext pctx;
        public Visitor visitor;

        public BackPropagator(Address addr, Set<Address> seenBBAddrs, Visitor visitor) throws Exception {
            this.pctx = newCtx(addr, seenBBAddrs);
            this.visitor = visitor;
        }

        private PropagatorContext newCtx(Address addr, Set<Address> seenBBAddrs) throws Exception {
            var sinkFunc = prg.getListing().getFunctionContaining(addr);
            if (sinkFunc == null) {
                throw new RuntimeException(
                        String.format("No function defined for selected address 0x%08x.", addr.getUnsignedOffset()));
            }

            var trackedFunc = decompile(sinkFunc);
            trackedFunc.highFunc.getBasicBlocks().stream()
                    .filter(bb -> {
                        log(String.format("Sink %08x in HighFunc BB %08x..%08x?",
                                addr.getUnsignedOffset(),
                                bb.getStart().getUnsignedOffset(),
                                bb.getStop().getUnsignedOffset()));
                        return bb.contains(addr);
                    })
                    .findFirst()
                    .orElseThrow();

            // Dependencies for this sink may be found in this bb, at or before the selected address.
            var ctx = new BackPropagator.PropagatorContext(trackedFunc);
            ctx.nextBBs.ignoreAll(seenBBAddrs);
            expandBB(addr, ctx);

            return ctx;
        }

        private CodeBlock bb(final Address addr) {
            // Sanity check: Address must be present in a single Basic Block (BB).
            try {
                var bbs = new BasicBlockModel(prg).getCodeBlocksContaining(addr, monitor);
                if (bbs.length != 1) {
                    throw new RuntimeException(String.format("Expected 1 bb, got %d.", bbs.length));
                }
                return bbs[0];
            } catch (final Exception ex) {
                throw new RuntimeException(ex);
            }
        }

        private void expandBB(final Address addr,
                              final BackTaint.BackPropagator.PropagatorContext ctx) {
            try {
                var bb = bb(addr);
                log(String.format("Expand BB @ %08x..%08x.",
                        bb.getFirstStartAddress().getUnsignedOffset(),
                        bb.getLastRange().getMaxAddress().getUnsignedOffset()));
                var bbIt = bb.getSources(monitor);
                while (bbIt.hasNext()) {
                    var srcBB = bb(bbIt.next().getSourceAddress());
                    Instruction lastInstr = prg.getListing().getInstructionContaining(srcBB.getMaxAddress());
                    log(String.format("  Next BB @ %08x..%08x(instr @ %08x).",
                            srcBB.getFirstStartAddress().getUnsignedOffset(),
                            srcBB.getLastRange().getMaxAddress().getUnsignedOffset(),
                            lastInstr.getAddress().getUnsignedOffset()));
                    if (bb.contains(lastInstr.getAddress())) {
                        log(String.format("  Skip BB (loop?)."));
                        continue;
                    }
                    ctx.nextBBs.push(lastInstr.getAddress());
                }

                var it = prg.getListing().getInstructions(bb, true);
                while (it.hasNext()) {
                    monitor.checkCancelled();

                    // FIXME: Filter by deps.
                    var instr = it.next();
                    if (instr.getAddress().getUnsignedOffset() <= addr.getUnsignedOffset()) {
                        ctx.nextInstrs.push(instr);
                    }
                }
            } catch (final Exception ex) {
                throw new RuntimeException(ex);
            }
            if (ctx.nextInstrs.isEmpty()) {
                throw new RuntimeException(String.format(
                        "Empty code block @ %08x.",
                        addr.getUnsignedOffset()));
            }
        }

        public boolean flow() {
            if (!pctx.nextSeqNums.isEmpty()) {
                visitor.visitSeqNum(pctx.nextSeqNums.pop(), pctx);
                return true;
            }

            if (!pctx.nextInstrs.isEmpty()) {
                visitor.visitInstr(pctx.nextInstrs.pop(), pctx);
                return true;
            }

            return false;
        }

        public interface Visitor {
            void visitInstr(Instruction instr, PropagatorContext ctx);

            void visitSeqNum(SequenceNumber seqNum, PropagatorContext ctx);
        }

        public interface VisitorContext {
        }

        public record PropagatorContext(
                TrackedFunction trackedFunc,
                DistinctStack<Address> nextBBs,
                DistinctStack<Instruction> nextInstrs,
                DistinctStack<SequenceNumber> nextSeqNums) {
            public PropagatorContext(TrackedFunction trackedFunc) {
                this(
                        trackedFunc,
                        new DistinctStack<>(),
                        new DistinctStack<>(),
                        new DistinctStack<>());
            }
        }
    }

    record TaintContext(
            Map<Varnode, Address> sinks,
            Map<Varnode, Address> deps,
            Map<Varnode, Address> memReadsUnresolved,
            Map<Address, Set<Address>> memReads,
            Map<Address, Set<Address>> memWrites) implements BackPropagator.VisitorContext {

        private static Comparator<Varnode> cmp = new Comparator<>() {
            @Override
            public int compare(Varnode v1, Varnode v2) {
                final var addrDiff = (int) (v1.getAddress().getUnsignedOffset()
                        - v2.getAddress().getUnsignedOffset());
                if (addrDiff == 0) {
                    return v1.getSize() - v2.getSize();
                }
                return addrDiff;
            }
        };

        public TaintContext() {
            this(
                    new TreeMap<>(cmp),
                    new TreeMap<>(cmp),
                    new HashMap<>(),
                    new HashMap<>(),
                    new HashMap<>());
        }

        public TaintContext clone() {
            final var tctx = new TaintContext(
                    new HashMap<Varnode, Address>(this.sinks),
                    new HashMap<Varnode, Address>(this.deps),
                    new HashMap<Varnode, Address>(this.memReadsUnresolved),
                    new HashMap<Address, Set<Address>>(this.memReads.entrySet().stream()
                            .collect(Collectors.toMap(Map.Entry::getKey, e -> new HashSet<>(e.getValue())))),
                    new HashMap<Address, Set<Address>>(this.memWrites.entrySet().stream()
                            .collect(Collectors.toMap(Map.Entry::getKey, e -> new HashSet<>(e.getValue())))));
            tctx.rmUniqDeps();

            return tctx;
        }

        private Varnode asDep(final Varnode v1) {
            if (this.deps.containsKey(v1)) {
                return v1;
            }

            Varnode dep = null;
            for (final var entry : this.deps.entrySet()) {
                final var v2 = entry.getKey();
                if (v1.getAddress().equals(v2.getAddress())) {
                    dep = v2;
                    if (v1.getSize() == v2.getSize()) {
                        return v2;
                    }
                }
                if (v1.isRegister() && v2.isRegister()) {
                    var a1 = v1.getAddress().getUnsignedOffset();
                    var a2 = v2.getAddress().getUnsignedOffset();
                    var s1 = v1.getSize();
                    var s2 = v2.getSize();
                    if ((a1 <= a2 && (a1 + s1) >= (a2 + s2)) || (a1 >= a2 && (a1 + s1) <= (a2 + s2))) {
                        return v2;
                    }
                }
            }

            return dep;
        }

        public void rmDep(final Varnode v1) {
            if (this.deps.containsKey(v1)) {
                this.deps.remove(v1);
                log(String.format("......... - (rmDep(v1)) %s", fmt(v1)));
                return;
            }

            Varnode dep = null;
            Varnode depRest = null;
            for (final var entry : this.deps.entrySet()) {
                final var v2 = entry.getKey();
                if (v1.getAddress().equals(v2.getAddress())) {
                    if (v1.getSize() == v2.getSize()) {
                        this.deps.remove(v2);
                        log(String.format("......... - (rmDep(v2)) %s", fmt(v2)));
                        return;
                    }
                }
                if (v1.isRegister() && v2.isRegister()) {
                    final var a1 = v1.getAddress().getUnsignedOffset();
                    final var a2 = v2.getAddress().getUnsignedOffset();
                    final var s1 = v1.getSize();
                    final var s2 = v2.getSize();

                    if (a1 > a2 && s1 < s2) {
                        // v1=3:1 v2=0:4 => 0:3
                        final var r12 = prg.getRegister(v2.getAddress(), s2 - s1);
                        if (r12 != null) {
                            dep = v2;
                            depRest = new Varnode(r12.getAddress(), s2 - s1);
                        }
                    } else if (a1 == a2 && s1 < s2) {
                        // v1=0:1 v2=0:4 => 1:3
                        final var a12 = prg.getAddressFactory().getAddress(String.format("register:0x%08x", a1 + s1));
                        final var r21 = prg.getRegister(a12, s2 - s1);
                        if (r21 != null) {
                            dep = v2;
                            depRest = new Varnode(a12, s2 - s1);
                        }
                    }
                }
            }

            if (dep != null && depRest != null) {
                final var a = this.deps.get(dep);
                this.deps.remove(dep);
                this.deps.put(depRest, a);
                log(String.format("......... - (rmDep) %s", fmt(dep)));
                log(String.format("......... + (rmDep) %s", fmt(depRest)));
            }
        }

        public void rmUniqDeps() {
            // Clear temporary variables from previous pcodeOps.
            this.deps.keySet().stream()
                    .filter(vnode -> vnode.isUnique())
                    .collect(Collectors.toList())
                    .forEach(this.deps::remove);
        }
    }

    private record TrackedFunction(HighFunction highFunc, Map<Address, TreeMap<Integer, PcodeOp>> numberedOps) {
    }

    class BackTaintVisitor implements BackPropagator.Visitor {
        public TaintContext tctx;

        public BackTaintVisitor(TaintContext tctx) {
            this.tctx = tctx;
        }

        @Override
        public void visitInstr(Instruction instr, BackPropagator.PropagatorContext pctx) {
            log(String.format(
                    "%08x: %s",
                    instr.getAddress().getUnsignedOffset(),
                    instr));

            var refIt = instr.getReferenceIteratorTo();
            while (refIt.hasNext()) {
                final Reference ref = refIt.next();
                log(ref);
                if (ref.isMemoryReference()) {
                    pctx.nextBBs.add(ref.getFromAddress());
                }
            }

            for (var ref : instr.getReferencesFrom()) {
                if (ref.isMemoryReference() && ref.getReferenceType().isData()) {
                    var memAddr = ref.getToAddress();
                    var refToIt = prg.getReferenceManager().getReferencesTo(memAddr);
                    while (refToIt.hasNext()) {
                        final Reference refTo = refToIt.next();
                        if (refTo.getReferenceType().isWrite()) {
                            var writeInstr = prg.getListing().getInstructionContaining(refTo.getFromAddress());
                            if (writeInstr != null) {
                                log(String.format(
                                        "Next MEM WRITE BB @ %08x [%08x]",
                                        writeInstr.getAddress().getUnsignedOffset(),
                                        memAddr.getUnsignedOffset()));
                                pctx.nextBBs.add(writeInstr.getAddress());
                            }
                        }
                    }
                }
            }

            tctx.rmUniqDeps();

            var pcodeOps = trackedFuncCache
                    .get(prg.getListing().getFunctionContaining(instr.getAddress()).getEntryPoint()).numberedOps
                            .get(instr.getAddress())
                            .reversed();
            for (final PcodeOp pcodeOp : pcodeOps.values()) {
                try {
                    visitOp(pcodeOp, instr, pctx);
                } catch (final Exception ex) {
                    throw new RuntimeException(ex);
                }
            }
        }

        @Override
        public void visitSeqNum(SequenceNumber seqNum, BackPropagator.PropagatorContext pctx) {
            pctx.nextInstrs.push(prg.getListing().getInstructionAt(seqNum.getTarget()));
        }

        private void visitOp(final PcodeOp pcodeOp,
                             final Instruction instr,
                             BackPropagator.PropagatorContext pctx) throws Exception {
            log(pcodeOp);

            final Address instrAddr = instr.getAddress();
            final Varnode out = out(pcodeOp);

            // Find the initial dependencies for this sink.
            if (tctx.sinks.isEmpty()) {
                if (out == null || !out.isRegister()) {
                    return;
                }

                var regOut = prg.getRegister(out.getAddress(), out.getSize());
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
                            log(String.format("......... + (visitOp) %s", fmt(vnode)));
                            tctx.deps.put(vnode, instrAddr);
                            if (vnode.getDef() != null) {
                                pctx.nextSeqNums.push(vnode.getDef().getSeqnum());
                            }
                        }
                        tctx.sinks.put(out, instrAddr);
                    }
                }

                return;
            }

            if (tctx.deps.isEmpty()) {
                printerr("No dependencies to flow into.");
                return;
            }

            // TODO: PIECE + SUBPIECE (split and invalidate deps, e.g. BH=PIECE(BX); BX=SUBPIECE(BH,BL);).
            // TODO: Model stack for push/pop macros used as function prologue/epilogue.
            // ghidra.program.util.SymbolicPropogator.applyPcode()
            switch (pcodeOp.getOpcode()) {
                case SEGMENTOP:
                    if (pcodeOp.getNumInputs() == 3 && pcodeOp.getInput(1).isRegister()) {
                        var v2 = pcodeOp.getInput(2);
                        if (tctx.memReadsUnresolved.containsKey(out)) {
                            var loadAddr = tctx.memReadsUnresolved.get(out);
                            tctx.memReadsUnresolved.remove(out);
                            var instrAddrs = tctx.memReads.get(loadAddr);
                            if (v2.isRegister()) {
                                tctx.deps.put(v2, loadAddr);
                                tctx.memReadsUnresolved.put(v2, loadAddr);
                            } else if (v2.isConstant()) {
                                tctx.memReads.remove(loadAddr);
                                tctx.memReads.put(v2.getAddress(), instrAddrs);
                                log(String.format(
                                        "Need MEM WRITE BB for %08x [%08x]",
                                        v2.getAddress().getUnsignedOffset(),
                                        loadAddr.getUnsignedOffset()));
                                var refToIt = prg.getReferenceManager().getReferencesTo(v2.getAddress());
                                while (refToIt.hasNext()) {
                                    final Reference refTo = refToIt.next();
                                    if (refTo.getReferenceType().isWrite()) {
                                        var writeInstr = prg.getListing()
                                                .getInstructionContaining(refTo.getFromAddress());
                                        if (writeInstr != null) {
                                            log(String.format(
                                                    "Next MEM WRITE BB @ %08x [%08x]",
                                                    writeInstr.getAddress().getUnsignedOffset(),
                                                    v2.getAddress().getUnsignedOffset()));
                                            pctx.nextBBs.add(writeInstr.getAddress());
                                        }
                                    }
                                }
                            } else {
                                printerr("Unhandled SEGMENTOP inputs.");
                            }
                        }
                    } else {
                        printerr("Unhandled SEGMENTOP inputs.");
                    }
                    break;
                case LOAD:
                    if (pcodeOp.getNumInputs() == 2) {
                        tctx.memReads.computeIfAbsent(
                                out.getAddress(),
                                k -> new HashSet<>());
                        tctx.memReads.get(out.getAddress()).add(instrAddr);
                        if (pcodeOp.getInput(1).isRegister() || pcodeOp.getInput(1).isUnique()) {
                            tctx.memReadsUnresolved.put(pcodeOp.getInput(1), out.getAddress());
                        }
                    } else {
                        printerr("Unhandled LOAD inputs.");
                    }
                    taint(tctx, instrAddr, pcodeOp, out);
                    break;
                case STORE:
                    if (tctx.asDep(out) == null && out.isUnique()) {
                        // First time we see this output, computed via segment:
                        // u0x00010e00(00000022:02) = SEGMENTOP(0x1b374820, DS, 0x00000010)
                        // u0x00010f00(00000022:03) = COPY(AL(00000020:01))
                        // STORE(0x000001a1, u0x00010e00(00000022:02), u0x00010f00(00000022:03))
                        tctx.deps.put(out, instrAddr);
                        log(String.format("......... + (store unique) %s", fmt(out)));
                    }
                    if (tctx.asDep(out) != null && out.isAddress()) {
                        tctx.memWrites.computeIfAbsent(
                                out.getAddress(),
                                k -> new HashSet<>());
                        tctx.memWrites.get(out.getAddress()).add(instrAddr);
                    }
                    taint(tctx, instrAddr, pcodeOp, out);
                    break;
                case CALL:
                    expandCall(instr, pctx);
                    break;
                case CALLOTHER:
                    // Assume userops unconditionally read all inputs.
                    // TODO: Process hooks from .pspec files, keyed by language id.
                    taint(tctx, instrAddr, pcodeOp, out);
                    break;
                case CAST, COPY, INDIRECT, MULTIEQUAL,
                        BOOL_AND, BOOL_NEGATE, BOOL_OR, BOOL_XOR,
                        FLOAT_ABS, FLOAT_ADD, FLOAT_CEIL, FLOAT_DIV, FLOAT_EQUAL,
                        FLOAT_FLOOR, FLOAT_MULT, FLOAT_NAN, FLOAT_NEG,
                        FLOAT_ROUND, FLOAT_SQRT, FLOAT_SUB,
                        INT_ADD, INT_AND, INT_CARRY, INT_DIV, INT_EQUAL,
                        INT_LEFT, INT_MULT, INT_NEGATE, INT_OR,
                        INT_REM, INT_RIGHT, INT_SBORROW, INT_SCARRY,
                        INT_SDIV, INT_SEXT, INT_SLESS, INT_SREM,
                        INT_SRIGHT, INT_SUB, INT_XOR, INT_ZEXT:
                    taint(tctx, instrAddr, pcodeOp, out);
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

        private void expandCall(final Instruction instr,
                                final BackPropagator.PropagatorContext pctx) throws Exception {
            for (var ref : instr.getReferencesFrom()) {
                if (!ref.isMemoryReference()) {
                    continue;
                }

                var calleeAddr = ref.getToAddress();
                var callee = prg.getListing().getFunctionContaining(calleeAddr);
                decompile(callee);

                var bbIt = new BasicBlockModel(prg).getCodeBlocksContaining(callee.getBody(), monitor);
                while (bbIt.hasNext()) {
                    var bb = bbIt.next();
                    if (bb.getNumDestinations(monitor) > 0) {
                        continue;
                    }

                    var lastAddr = bb.getMaxAddress();
                    if (pctx.trackedFunc.highFunc.getFunction().getBody().contains(lastAddr)) {
                        log(String.format("  Skip CALL BB (loop?)."));
                        continue;
                    }

                    log(String.format("  Next CALL BB @ %08x..%08x(instr @ %08x).",
                            bb.getFirstStartAddress().getUnsignedOffset(),
                            bb.getLastRange().getMaxAddress().getUnsignedOffset(),
                            lastAddr.getUnsignedOffset()));
                    pctx.nextBBs.push(lastAddr);
                }
            }
        }
    }

    class Patterns {
        private static final int ANY = 0;
        private static final int REG = 0b0000_0001_0000_0000;
        private static final int SYM_DS = 0b0000_0000_0001_0000;
        private static final int VAR_01 = 0b0000_0000_0000_0001;

        // Assume opcodes given by "firstpass" decompilation.
        public static final Map<String, List<PatternElement>> PATTERNS = Map.of(
                "memread",
                List.of(
                        PatternElement.builder().opcode(PcodeOp.SEGMENTOP).in(ANY).in(REG | SYM_DS).in(ANY).out(VAR_01)
                                .build(),
                        PatternElement.builder().opcode(PcodeOp.LOAD).in(ANY).in(VAR_01).build()),
                "memwrite",
                List.of(
                        PatternElement.builder().opcode(PcodeOp.SEGMENTOP).in(ANY).in(REG | SYM_DS).in(ANY).out(VAR_01)
                                .build(),
                        PatternElement.builder().opcode(PcodeOp.STORE).in(ANY).in(VAR_01).in(ANY).build()));

        private record PatternElement(int opcode, List<Integer> in, List<Integer> out) {
            public static Builder builder() {
                return new Builder();
            }

            static class Builder {
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

        private boolean match(final List<PcodeOp> pcode, final List<PatternElement> pattern) {
            final var pcodeLen = pcode.size();
            if (pcodeLen < pattern.size()) {
                return false;
            }

            var pattern_i = 0;
            for (int i = 0; i < pcodeLen; i++) {
                if (pcode.get(i).getOpcode() != pattern.get(pattern_i).opcode()) {
                    continue;
                }

                if (pcode.get(i).getNumInputs() < pattern.get(pattern_i).in().size()) {
                    return false;
                }

                Varnode var01 = null;
                for (int j = 0; j < pattern.get(pattern_i).in().size(); j++) {
                    final var inPattern = pattern.get(pattern_i).in().get(j);
                    final var in = pcode.get(i).getInput(j);
                    if ((inPattern & REG) != 0) {
                        if (!in.isRegister()) {
                            return false;
                        }
                        if ((inPattern & SYM_DS) != 0) {
                            final var reg = prg.getRegister("DS");
                            if (!in.isRegister() || !in.getAddress().equals(reg.getAddress())) {
                                return false;
                            }
                        }
                    }
                    if ((inPattern & VAR_01) != 0) {
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
                    final var out = pcode.get(i).getOutput();
                    if ((outPattern & VAR_01) != 0) {
                        if (var01 == null) {
                            var01 = out;
                        } else if (!(var01.getAddress().getAddressSpace().getName()
                                .equals(out.getAddress().getAddressSpace().getName()))
                                || (var01.getAddress().getUnsignedOffset() != out.getAddress().getUnsignedOffset())) {
                            return false;
                        }
                        continue;
                    }
                    if ((outPattern & REG) != 0) {
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
    }
}
