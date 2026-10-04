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
import static ghidra.program.model.pcode.PcodeOp.STORE;
import static ghidra.program.model.pcode.PcodeOp.UNIMPLEMENTED;

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
    private static final Map<String, Set<String>> ISA_FLAGS = Map.of(
            "x86",
            Set.of("AF", "CF", "OF", "PF", "SF", "ZF"));

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
                endCtxs.add(clone(visitor.tctx));
            }

            final Set<Address> nextSeenBBAddrs = new HashSet<>();
            nextSeenBBAddrs.add(bbctx.addr);
            nextSeenBBAddrs.addAll(bbctx.seenBBAddrs);
            nextSeenBBAddrs.addAll(propagator.pctx.nextBBs.ignored());
            propagator.pctx.nextBBs
                    .forEach(nextBB -> nextBBCtxs.add(new BBContext(nextBB, nextSeenBBAddrs, clone(visitor.tctx))));
        }

        var mergedTaintContext = merge(endCtxs);
        println("Merged taint ctx:");
        log(mergedTaintContext);

        return mergedTaintContext;
    }

    private TaintContext merge(final Collection<TaintContext> ctxs) {
        return new TaintContext(
                new HashMap<Varnode, Address>(ctxs.stream().map(ctx -> ctx.sinks)
                        .flatMap(map -> map.entrySet().stream())
                        .collect(Collectors.toMap(
                                Map.Entry::getKey,
                                Map.Entry::getValue,
                                (oldValue, newValue) -> newValue))),
                new HashMap<Varnode, Address>(ctxs.stream().map(ctx -> ctx.deps)
                        .flatMap(map -> map.entrySet().stream())
                        .collect(Collectors.toMap(
                                Map.Entry::getKey,
                                Map.Entry::getValue,
                                (oldValue, newValue) -> newValue))),
                new HashMap<Address, Set<Address>>(ctxs.stream().map(ctx -> ctx.memReads)
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
                new HashMap<Address, Set<Address>>(ctxs.stream().map(ctx -> ctx.memWrites)
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

    private TaintContext clone(TaintContext tctx) {
        return new TaintContext(
                new HashMap<Varnode, Address>(tctx.sinks),
                new HashMap<Varnode, Address>(tctx.deps),
                new HashMap<Address, Set<Address>>(tctx.memReads.entrySet().stream()
                        .collect(Collectors.toMap(Map.Entry::getKey, e -> new HashSet<>(e.getValue())))),
                new HashMap<Address, Set<Address>>(tctx.memWrites.entrySet().stream()
                        .collect(Collectors.toMap(Map.Entry::getKey, e -> new HashSet<>(e.getValue())))));
    }

    private TrackedFunction decompile(final Function currentFunc) {
        if (trackedFuncCache.containsKey(currentFunc.getEntryPoint())) {
            return trackedFuncCache.get(currentFunc.getEntryPoint());
        }
        printf("Decompiling '%s' @ %08x.%n", currentFunc.getName(), currentFunc.getEntryPoint().getUnsignedOffset());

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

    private void taint(final TaintContext ctx,
                       final Address instrAddr,
                       final PcodeOp pcodeOp,
                       final Varnode dst) {
        // FIXME: AX vs. AH+AL
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
        if (ISA_FLAGS.getOrDefault(proc, Collections.emptySet()).contains(reg.getName())) {
            return true;
        }
        return reg == prg.getCompilerSpec().getStackPointer()
                || reg == lang.getProgramCounter()
                || reg.isDefaultFramePointer()
                || reg.isHidden()
                || reg.isProcessorContext()
                || reg.isZero();
    }

    private CodeBlock bb(final Address addr) {
        // Sanity check: Address must be present in a single bb.
        try {
            var bbs = new SimpleBlockModel(currentProgram).getCodeBlocksContaining(addr, monitor);
            if (bbs.length != 1) {
                throw new RuntimeException(String.format("Expected 1 bb, got %d.", bbs.length));
            }
            return bbs[0];
        } catch (final Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    private Varnode out(final PcodeOp pcodeOp) {
        if (pcodeOp.getOpcode() == STORE) {
            return pcodeOp.getInput(1);
        }
        return pcodeOp.getOutput();
    }

    private void log(final BackPropagator propagator) {
        log(((BackTaintVisitor) propagator.visitor).tctx);
        println(String.format(
                "Next BBs:[%s]",
                propagator.pctx.nextBBs.stream()
                        .map(addr -> String.format("%08x", addr.getUnsignedOffset()))
                        .collect(Collectors.joining(","))));
    }

    private void log(final TaintContext tctx) {
        if (!tctx.sinks().isEmpty()) {
            var sinkVnode = List.copyOf(tctx.sinks().entrySet()).get(0).getKey();
            var sinkAddr = tctx.sinks().get(sinkVnode);
            println(String.format("Dependencies for sink %s:", fmt(sinkVnode)));
            tctx.deps.forEach((vnode, addr) -> {
                println(String.format(
                        "......... < %s @ %08x",
                        fmt(vnode),
                        addr.getUnsignedOffset()));
            });
        }

        println(String.format(
                "Sinks:[%s] Deps:[%s]",
                tctx.sinks.entrySet().stream()
                        .map(entry -> String.format("> %s @ %08x",
                                fmt(entry.getKey()),
                                entry.getValue().getUnsignedOffset()))
                        .collect(Collectors.joining(",")),
                tctx.deps.entrySet().stream()
                        .map(entry -> String.format("< %s @ %08x",
                                fmt(entry.getKey()),
                                entry.getValue().getUnsignedOffset()))
                        .collect(Collectors.joining(","))));
        println(String.format(
                "Mem R:[%s] W:[%s]",
                tctx.memReads.entrySet().stream()
                        .map(entry -> String.format("%08x @ %s",
                                entry.getKey().getUnsignedOffset(),
                                entry.getValue().stream()
                                        .map(addr -> String.format("%08x",
                                                addr.getUnsignedOffset()))
                                        .collect(Collectors.joining(","))))
                        .collect(Collectors.joining(",")),
                tctx.memWrites.entrySet().stream()
                        .map(entry -> String.format("%08x @ %s",
                                entry.getKey().getUnsignedOffset(),
                                entry.getValue().stream()
                                        .map(addr -> String.format("%08x",
                                                addr.getUnsignedOffset()))
                                        .collect(Collectors.joining(","))))
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

    private String fmt(final Varnode vnode) {
        if (vnode == null) {
            return "(null)";
        } else if (vnode.isRegister()) {
            final Register reg = prg.getLanguage().getRegister(vnode.getAddress(), vnode.getSize());
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
            var sinkFunc = lst.getFunctionContaining(addr);
            if (sinkFunc == null) {
                throw new RuntimeException("No function defined for selected address.");
            }

            var trackedFunc = decompile(sinkFunc);
            trackedFunc.highFunc.getBasicBlocks().stream()
                    .filter(bb -> {
                        printf("Sink %08x in HighFunc BB %08x..%08x?%n",
                                addr.getUnsignedOffset(),
                                bb.getStart().getUnsignedOffset(),
                                bb.getStop().getUnsignedOffset());
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

        private void expandBB(final Address addr,
                              final BackTaint.BackPropagator.PropagatorContext ctx) {
            try {
                var bb = bb(addr);
                printf("Expand BB @ %08x..%08x.%n",
                        bb.getFirstStartAddress().getUnsignedOffset(),
                        bb.getLastRange().getMaxAddress().getUnsignedOffset());
                var bbIt = bb.getSources(monitor);
                while (bbIt.hasNext()) {
                    var srcBB = bb(bbIt.next().getSourceAddress());
                    Instruction lastInstr = lst.getInstructionContaining(srcBB.getMaxAddress());
                    printf("  Next BB @ %08x..%08x(instr @ %08x).%n",
                            srcBB.getFirstStartAddress().getUnsignedOffset(),
                            srcBB.getLastRange().getMaxAddress().getUnsignedOffset(),
                            lastInstr.getAddress().getUnsignedOffset());
                    if (bb.contains(lastInstr.getAddress())) {
                        printf("  Skip BB (loop?).%n");
                        continue;
                    }
                    ctx.nextBBs.push(lastInstr.getAddress());
                }

                var it = lst.getInstructions(bb, true);
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
            Map<Address, Set<Address>> memReads,
            Map<Address, Set<Address>> memWrites) implements BackPropagator.VisitorContext {
        public TaintContext() {
            this(
                    new HashMap<>(),
                    new HashMap<>(),
                    new HashMap<>(),
                    new HashMap<>());
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
            println(String.format(
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

            // FIXME: Try parsing SEGMENTOP + LOAD
            for (var ref : instr.getReferencesFrom()) {
                if (ref.isMemoryReference() && ref.getReferenceType().isData()) {
                    var memAddr = ref.getToAddress();
                    var refToIt = refMgr.getReferencesTo(memAddr);
                    while (refToIt.hasNext()) {
                        final Reference refTo = refToIt.next();
                        if (refTo.getReferenceType().isWrite()) {
                            var writeInstr = lst.getInstructionContaining(refTo.getFromAddress());
                            if (writeInstr != null) {
                                println(String.format(
                                        "Next MEM WRITE BB @ %08x [%08x]",
                                        writeInstr.getAddress().getUnsignedOffset(),
                                        memAddr.getUnsignedOffset()));
                                pctx.nextBBs.add(writeInstr.getAddress());
                            }
                        }
                    }
                }
            }

            // Clear temporary variables from previous pcodeOps.
            tctx.deps.keySet().stream()
                    .filter(vnode -> vnode.isUnique())
                    .forEach(tctx.deps::remove);

            var pcodeOps = trackedFuncCache
                    .get(lst.getFunctionContaining(instr.getAddress()).getEntryPoint()).numberedOps
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
            pctx.nextInstrs.push(lst.getInstructionAt(seqNum.getTarget()));
        }

        private void visitOp(final PcodeOp pcodeOp,
                             final Instruction instr,
                             BackPropagator.PropagatorContext pctx) throws Exception {
            log(pcodeOp);

            final Address instrAddr = instr.getAddress();
            final Varnode out = out(pcodeOp);

            // Find the initial dependencies for this sink.
            // TODO: Support memory addresses.
            if (tctx.sinks.isEmpty()) {
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

            // TODO: Model stack for push/pop macros used as function prologue/epilogue.
            // ghidra.program.util.SymbolicPropogator.applyPcode()
            switch (pcodeOp.getOpcode()) {
                case LOAD:
                    // TODO: Resolve segmented reg/mem values from ctx?
                    if (pcodeOp.getNumInputs() == 2 && pcodeOp.getInput(1).isAddress()) {
                        tctx.memReads.computeIfAbsent(
                                out.getAddress(),
                                k -> new HashSet<>());
                        tctx.memReads.get(pcodeOp.getInput(1).getAddress())
                                .add(instrAddr);
                    }
                    taint(tctx, instrAddr, pcodeOp, out);
                    break;
                case STORE:
                    if (tctx.deps.containsKey(out) && out.isAddress()) {
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
                case INDIRECT:
                    var sq = new SequenceNumber(pcodeOp.getSeqnum().getTarget(),
                            (int) pcodeOp.getInput(pcodeOp.getNumInputs() == 1
                                    ? 0
                                    : 1)
                                    .getOffset());
                    var iop = pctx.trackedFunc.highFunc.getPcodeOp(sq);
                    if (iop == null) {
                        throw new RuntimeException(String.format("INDIRECT op not found in func? %08x -> %08x",
                                instr.getAddress().getUnsignedOffset(),
                                fmt(pctx.trackedFunc.highFunc, iop)));
                    }
                    taint(tctx, instrAddr, pcodeOp, out);
                    taint(tctx, instrAddr, iop, out);
                    break;
                case CAST, COPY, MULTIEQUAL,
                        BOOL_AND, BOOL_NEGATE, BOOL_OR, BOOL_XOR,
                        FLOAT_ABS, FLOAT_ADD, FLOAT_CEIL, FLOAT_DIV,
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
                var callee = lst.getFunctionContaining(calleeAddr);
                decompile(callee);

                var model = new BasicBlockModel(prg);
                var bbIt = model.getCodeBlocksContaining(callee.getBody(), monitor);
                while (bbIt.hasNext()) {
                    var bb = bbIt.next();
                    if (bb.getNumDestinations(monitor) > 0) {
                        continue;
                    }

                    var lastAddr = bb.getMaxAddress();
                    if (pctx.trackedFunc.highFunc.getFunction().getBody().contains(lastAddr)) {
                        printf("  Skip CALL BB (loop?).%n");
                        continue;
                    }

                    printf("  Next CALL BB @ %08x..%08x(instr @ %08x).%n",
                            bb.getFirstStartAddress().getUnsignedOffset(),
                            bb.getLastRange().getMaxAddress().getUnsignedOffset(),
                            lastAddr.getUnsignedOffset());
                    pctx.nextBBs.push(lastAddr);
                }
            }
        }
    }

    public void log(Reference ref) {
        println(String.format(
                "ref[%02x](%s): %08x->%08x",
                ref.getOperandIndex(),
                ref.getReferenceType().getName(),
                ref.getFromAddress().getUnsignedOffset(),
                ref.getToAddress().getUnsignedOffset()));
    }
}
