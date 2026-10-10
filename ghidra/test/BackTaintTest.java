import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ghidra.GhidraTestApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;

public class BackTaintTest {

    @TempDir
    private static File userSettingsDir;

    private static Stream<Arguments> x86Args() {
        var argsBBs = Arrays.asList(
                Arguments.of(
                        "bb1",
                        Map.of(
                                "0x0",
                                """
                                        b8 01 00  # MOV AX,0x1
                                        09 c0     # OR AX,AX
                                        74 09     # JZ 0x10 ----.
                                        c3        # RET         |
                                        """,
                                "0x10",
                                """
                                        89 c3     # MOV BX,AX <-'
                                        c3        # RET
                                        """),
                        Set.of("0x0"),
                        Map.of("0x0", new Match(AddressSpace.TYPE_CONSTANT, 0x1L)),
                        "0x10"),
                Arguments.of(
                        "bb2",
                        Map.of(
                                "0x0",
                                """
                                        b8 01 00  # MOV AX,0x1
                                        09 c0     # OR AX,AX
                                        74 09     # JZ 0x10 ----.
                                        c3        # RET         |
                                        """,
                                "0x10",
                                """
                                        88 c7     # MOV BH,AL <-'
                                        b3 02     # MOV BL,0x02
                                        89 d8     # MOV AX,BX
                                        c3        # RET
                                        """),
                        Set.of("0x0"),
                        Map.of("0x0", new Match(AddressSpace.TYPE_CONSTANT, 0x1L)),
                        "0x14"),
                Arguments.of(
                        "bb3",
                        Map.of(
                                "0x0",
                                """
                                        b8 01 00  # MOV AX,0x1
                                        09 c0     # OR AX,AX
                                        74 09     # JZ 0x10 ---------.
                                        eb 17     # JMP 0x20 ------. |
                                        """,
                                "0x10",
                                """
                                        89 d8     # MOV AX,BX <----|-'
                                        eb 1c     # JMP 0x30 ----. |
                                        """,
                                "0x20",
                                """
                                        88 c7     # MOV BH,AL <--|-'
                                        b3 02     # MOV BL,0x02  |
                                        eb 0a     # JMP 0x30 ----+
                                        """,
                                "0x30",
                                """
                                        89 d8     # MOV AX,BX <--'
                                        c3        # RET
                                        """),
                        Set.of("0x0"),
                        Map.of("0x0", new Match(AddressSpace.TYPE_CONSTANT, 0x1L)),
                        "0x30"));

        var argsGenAfterKill = Arrays.asList(
                Arguments.of(
                        "gen_after_kill_in_reg",
                        Map.of(
                                "0x0",
                                """
                                        bb 01 00    # MOV BX,0x1
                                        89 c3       # MOV BX,AX
                                        c3          # RET
                                        """),
                        Set.of("0x0"),
                        Map.of("0x3", new Match(AddressSpace.TYPE_REGISTER, "AX")),
                        "0x3"),
                Arguments.of(
                        "gen_after_kill_reg_val_0x2",
                        Map.of(
                                "0x0",
                                """
                                        b8 01 00    # MOV AX,0x1
                                        b8 02 00    # MOV AX,0x2
                                        bb 03 00    # MOV BX,0x3
                                        89 c3       # MOV BX,AX
                                        c3          # RET
                                        """),
                        Set.of("0x0"),
                        Map.of("0x3", new Match(AddressSpace.TYPE_CONSTANT, 0x2L)),
                        "0x9"));

        var argsGenCallee = Arrays.asList(
                Arguments.of(
                        "gen_callee",
                        Map.of(
                                "0x0",
                                """
                                        e8 0d 00  # CALL 0x10 ---.
                                        89 c3     # MOV BX,AX    |
                                        c3        # RET          |
                                        """,
                                "0x10",
                                """
                                        b0 01     # MOV AL,0x1 <-'
                                        c3        # RET
                                        """),
                        Set.of("0x0", "0x10"),
                        Map.of("0x10", new Match(AddressSpace.TYPE_CONSTANT, 0x1L)),
                        "0x03"));

        var argsGenCaller = Arrays.asList(
                Arguments.of(
                        "gen_caller",
                        Map.of(
                                "0x0",
                                """
                                        bb 02 00    # MOV BX,0x2
                                        b8 01 00    # MOV AX,0x1
                                        e8 07 00    # CALL 0x10 --.
                                        c3          # RET         |
                                        """,
                                "0x10",
                                """
                                        89 c3       # MOV BX,AX <-'
                                        c3          # RET
                                        """),
                        Set.of("0x0", "0x10"),
                        Map.of("0x3", new Match(AddressSpace.TYPE_CONSTANT, 0x1L)),
                        "0x10"));

        var argsGenSibling = Arrays.asList(
                Arguments.of(
                        "gen_sibling",
                        Map.of(
                                "0x0",
                                """
                                        bb 02 00    # MOV BX,0x2
                                        e8 1a 00    # CALL 0x20 ---.
                                        bb 03 00    # MOV BX,0x3   |
                                        e8 24 00    # CALL 0x30 --.|
                                        e8 21 00    # CALL 0x30 --+|
                                        e8 1e 00    # CALL 0x30 --+|
                                        c3          # RET         ||
                                        """,
                                "0x20",
                                """
                                        b8 01 00    # MOV AX,0x1 <-'
                                        c3          # RET         |
                                        """,
                                "0x30",
                                """
                                        89 c3       # MOV BX,AX <-'
                                        c3          # RET
                                        """),
                        Set.of("0x0", "0x20", "0x30"),
                        Map.of("0x20", new Match(AddressSpace.TYPE_CONSTANT, 0x1L)),
                        "0x30"));

        var argsIndirectCall = Arrays.asList(
                Arguments.of(
                        "indirect_call",
                        Map.of(
                                "0x0",
                                """
                                        a1 10 00  # MOV AX,[0x10]
                                        0d 20 00  # OR AX,0x20
                                        ff d0     # CALL AX
                                        89 c3     # MOV BX,AX
                                        c3        # RET
                                        """,
                                "0x30",
                                """
                                        b8 55 00  # MOV AX, 0x55
                                        c3        # RET
                                        """),
                        Set.of("0x0", "0x30"),
                        Map.of("0x30", new Match(AddressSpace.TYPE_CONSTANT, 0x55L)),
                        "0x08"));

        var argsIndirectMerge = Arrays.asList(
                Arguments.of(
                        "indirect_merge",
                        Map.of(
                                "0x0",
                                """
                                        b8 01 00    # MOV AX,0x1
                                        09 c0       # OR AX,AX
                                        74 09       # JZ 0x10
                                        e8 26 00    # CALL 0x30 ------.
                                        eb 14       # JMP 0x20 ---.   |
                                        """,
                                "0x10",
                                """
                                        e8 2d 00    # CALL 0x40 --)-. |
                                        eb 0b       # JMP 0x20  --| | |
                                        """,
                                "0x20",
                                """
                                        89 d8       # MOV AX,BX <-' | |
                                        c3          # RET           | |
                                        """,
                                "0x30",
                                """
                                        88 c7       # MOV BH,AL <---)-'
                                        b3 02       # MOV BL,0x02   |
                                        c3          # RET           |
                                        """,
                                "0x40",
                                """
                                        88 c7       # MOV BH,AL <---'
                                        b3 22       # MOV BL,0x22
                                        bb ff 00    # MOV BX,0xff
                                        c3          # RET
                                        """),
                        Set.of("0x0", "0x30", "0x40"),
                        Map.of("0x30",
                                new Match(AddressSpace.TYPE_REGISTER, "AL"),
                                "0x32",
                                new Match(AddressSpace.TYPE_CONSTANT, 0x02L),
                                "0x44",
                                new Match(AddressSpace.TYPE_CONSTANT, 0xffL)),
                        "0x20"));

        var argsMems = Arrays.asList(
                Arguments.of(
                        "mem1",
                        Map.of(
                                "0x0",
                                """
                                        a0 10 00     # MOV AL,[0x10]
                                        88 c3        # MOV BL,AL
                                        c3           # RET
                                        """,
                                "0x10",
                                """
                                        aa aa aa aa
                                        """,
                                "0x20",
                                """
                                        b0 55        # MOV AL, 0x55
                                        a2 10 00     # MOV [0x10],AL
                                        c3           # RET
                                        """),
                        Set.of("0x0", "0x20"),
                        Map.of("0x20", new Match(AddressSpace.TYPE_CONSTANT, 0x55L)),
                        "0x03"),
                Arguments.of(
                        "mem2",
                        Map.of(
                                "0x0",
                                """
                                        b2 5a        # MOV DL, 0x5a
                                        b3 10        # MOV BL, 0x10
                                        89 17        # MOV word ptr [BX],DX
                                        8d 07        # LEA AX,[BX]
                                        88 c3        # MOV BL,AL
                                        c3           # RET
                                        """,
                                "0x10",
                                """
                                        aa aa aa aa
                                        """,
                                "0x20",
                                """
                                        b0 55        # MOV AL, 0x55
                                        a2 10 00     # MOV [0x10],AL
                                        c3           # RET
                                        """),
                        Set.of("0x0", "0x20"),
                        Map.of("0x20", new Match(AddressSpace.TYPE_CONSTANT, 0x55L)),
                        "0x08"),
                Arguments.of(
                        "mem3",
                        Map.of(
                                "0x0",
                                """
                                        a1 10 00     # MOV AX,[0x10]
                                        09 c0        # OR AX,AX
                                        75 19        # JNZ 0x20
                                        c3           # RET
                                        """,
                                "0x10",
                                """
                                        aa aa aa aa
                                        """,
                                "0x20",
                                """
                                        89 c3        # MOV BX,AX
                                        c3           # RET
                                        """,
                                "0x30",
                                """
                                        b8 55 00     # MOV AX, 0x55
                                        a3 10 00     # MOV [0x10],AX
                                        c3           # RET
                                        """,
                                "0x40",
                                """
                                        b8 5a 00     # MOV AX, 0x5a
                                        a3 20 00     # MOV [0x20],AX
                                        c3           # RET
                                        """,
                                "0x50",
                                """
                                        a1 20 00     # MOV AX, [0x20]
                                        a3 10 00     # MOV [0x10],AX
                                        c3           # RET
                                        """),
                        Set.of("0x0", "0x30", "0x40", "0x50"),
                        Map.of("0x30",
                                new Match(AddressSpace.TYPE_CONSTANT, 0x55L),
                                "0x40",
                                new Match(AddressSpace.TYPE_CONSTANT, 0x5aL)),
                        "0x20"));

        var argsNone = Arrays.asList(
                Arguments.of(
                        "none_ret",
                        Map.of(
                                "0x0",
                                "       c3          # RET"),
                        Set.of("0x0"),
                        Collections.EMPTY_MAP,
                        "0x0"),
                Arguments.of(
                        "none_retf",
                        Map.of(
                                "0x0",
                                "       cb          # RETF"),
                        Set.of("0x0", "0x10"),
                        Collections.EMPTY_MAP,
                        "0x0"),
                Arguments.of(
                        "none_loop",
                        Map.of(
                                "0x0",
                                "       eb fe       # JMP 0x0"),
                        Set.of("0x0"),
                        Collections.EMPTY_MAP,
                        "0x0"),
                Arguments.of(
                        "none_loop_bbs",
                        Map.of(
                                "0x0",
                                """
                                        74 0e       # JZ 0x10"
                                        75 0e       # JNZ 0x10"
                                        eb 0e       # JMP 0x10"
                                        """,
                                "0x10",
                                "       eb ee       # JMP 0x0"),
                        Set.of("0x0"),
                        Collections.EMPTY_MAP,
                        "0x0"));

        return Stream.of(
                argsBBs,
                argsGenAfterKill,
                argsGenCallee,
                argsGenCaller,
                argsGenSibling,
                argsIndirectCall,
                argsIndirectMerge,
                argsMems,
                argsNone)
                .flatMap(Collection::stream);
    }

    private TestInfo testInfo;

    @BeforeAll
    public static void beforeAll() {
        try {
            Application.initializeApplication(
                    new GhidraTestApplicationLayout(userSettingsDir),
                    new ApplicationConfiguration());
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    @BeforeEach
    void beforeEach(final TestInfo testInfo) {
        this.testInfo = testInfo;
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("x86Args")
    public void x86(final String testName,
                    final Map<String, String> prgBytes,
                    final Set<String> funcAddrs,
                    final Map<String, Match> expectedSrcs,
                    final String sinkAddr) throws Exception {
        of(prgBytes, funcAddrs, expectedSrcs, sinkAddr, "x86:LE:16:Protected Mode");
    }

    /**
     * @param prgBytes     Program bytes keyed-by address on which they are inserted.
     * @param funcAddrs    Addresses on which functions are defined.
     * @param expectedSrcs Expected sources keyed-by address to be found by script.
     * @param sinkAddr     Address selected as sink.
     * @param langName     Program language.
     */
    public void of(final Map<String, String> prgBytes,
                   final Set<String> funcAddrs,
                   final Map<String, Match> expectedSrcs,
                   final String sinkAddr,
                   final String langName) throws Exception {
        System.out.printf("\n==== %s ====\n", testInfo.getDisplayName().replaceAll("\s\s*", " "));

        var script = newScript(prgBytes, funcAddrs, sinkAddr, langName);
        var tctx = script.flow();
        var ctxAddrs = Set.copyOf(tctx.deps().values());
        expectedSrcs.forEach((addrStr, match) -> {
            var addr = script.prg.getAddressFactory().getAddress(addrStr);
            assertTrue(
                    ctxAddrs.contains(addr),
                    String.format(
                            "ctx '%s' contains addr '0x%08x'",
                            ctxAddrs,
                            addr.getUnsignedOffset()));

            var ctxVar = tctx.deps().entrySet().stream()
                    .filter(entry -> entry.getValue().equals(addr))
                    .map(Map.Entry::getKey)
                    .findFirst()
                    .orElseThrow();
            assertEquals(
                    match.spaceType,
                    ctxVar.getAddress().getAddressSpace().getType(),
                    String.format(
                            "space type '%d' matches ctx '%d'",
                            match.spaceType,
                            ctxVar.getAddress().getAddressSpace().getType()));

            if (match.spaceType == AddressSpace.TYPE_CONSTANT) {
                assertEquals(
                        match.val,
                        ctxVar.getOffset(),
                        String.format(
                                "val '%s' matches ctx '0x%08x'",
                                match.val,
                                ctxVar.getOffset()));
            } else if (match.spaceType == AddressSpace.TYPE_REGISTER) {
                var matchReg = script.prg.getRegister(match.val.toString());
                var ctxReg = script.prg.getRegister(ctxVar.getAddress(), ctxVar.getSize());
                assertEquals(
                        matchReg,
                        ctxReg,
                        String.format(
                                "reg '%s' matches ctx '%s'",
                                matchReg,
                                ctxReg));
            }
        });
    }

    private BackTaint newScript(final Map<String, String> prgBytes,
                                final Set<String> funcAddrs,
                                final String sinkAddr,
                                final String langName) throws Exception {
        var prg = newProgram(prgBytes, funcAddrs, langName);
        var script = new BackTaint();
        script.init(prg, prg.getAddressFactory().getAddress(sinkAddr), funcAddrs);

        return script;
    }

    private Program newProgram(final Map<String, String> prgBytes,
                               final Set<String> funcAddrs,
                               final String langName) throws Exception {
        var builder = new ProgramBuilder("test", langName);
        prgBytes.forEach((addr, lstBytes) -> {
            var bytes = HexFormat.of().parseHex(
                    lstBytes.lines()
                            .map(line -> line.replaceAll("#.*$", "").replaceAll("\s", ""))
                            .collect(Collectors.joining()));
            try {
                builder.setBytes(addr, bytes, true);
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        });
        funcAddrs.forEach(builder::createFunction);

        var prg = builder.getProgram();
        prg.startTransaction(this.getClass().getSimpleName());

        return prg;
    }

    private record Match(Integer spaceType, Object val) {
    }
}
