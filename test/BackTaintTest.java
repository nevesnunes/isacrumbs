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
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;

public class BackTaintTest {

    @TempDir
    private static File userSettingsDir;

    private static Stream<Arguments> x86Args() {
        var argsNone = Arrays.asList(
                Arguments.of(
                        Map.of(
                                "0x0",
                                "       c3          # RET"),
                        Set.of("0x0"),
                        Collections.EMPTY_MAP,
                        "0x0"),
                Arguments.of(
                        Map.of(
                                "0x0",
                                "       cb          # RETF"),
                        Set.of("0x0", "0x10"),
                        Collections.EMPTY_MAP,
                        "0x0"),
                Arguments.of(
                        Map.of(
                                "0x0",
                                "       eb fe       # JMP 0x0"),
                        Set.of("0x0"),
                        Collections.EMPTY_MAP,
                        "0x0"));

        var argsInReg = Arrays.asList(
                Arguments.of(
                        Map.of(
                                "0x0",
                                """
                                        bb 01 00    # MOV BX,0x1
                                        89 c3       # MOV BX,AX
                                        c3          # RET
                                        """),
                        Set.of("0x0"),
                        Map.of("0x3", new Match(AddressSpace.TYPE_REGISTER, "AX")),
                        "0x3"));

        var argsGenAfterKill = Arrays.asList(
                Arguments.of(
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

        var argsGenCaller = Arrays.asList(
                Arguments.of(
                        Map.of(
                                "0x0",
                                """
                                        bb 02 00    # MOV BX,0x2
                                        b8 01 00    # MOV AX,0x1
                                        e8 07 00    # CALL 0x10
                                        c3          # RET
                                        """,
                                "0x10",
                                """
                                        89 c3       # MOV BX,AX
                                        c3          # RET
                                        """),
                        Set.of("0x0", "0x10"),
                        Map.of("0x3", new Match(AddressSpace.TYPE_CONSTANT, 0x1L)),
                        "0x10"));

        var argsGenSibling = Arrays.asList(
                Arguments.of(
                        Map.of(
                                "0x0",
                                """
                                        bb 02 00    # MOV BX,0x2
                                        e8 1a 00    # CALL 0x20
                                        bb 03 00    # MOV BX,0x3
                                        e8 24 00    # CALL 0x30
                                        e8 21 00    # CALL 0x30
                                        e8 1e 00    # CALL 0x30
                                        c3          # RET
                                        """,
                                "0x20",
                                """
                                        b8 01 00    # MOV AX,0x1
                                        c3          # RET
                                        """,
                                "0x30",
                                """
                                        89 c3       # MOV BX,AX
                                        c3          # RET
                                        """),
                        Set.of("0x0", "0x20", "0x30"),
                        Map.of("0x20", new Match(AddressSpace.TYPE_CONSTANT, 0x1L)),
                        "0x30"));

        var argsIndirectMerge = Arrays.asList(
                Arguments.of(
                        Map.of(
                                "0x0",
                                """
                                        b8 01 00    # MOV AX,0x1
                                        09 c0       # OR AX,AX
                                        74 09       # JZ 0x10
                                        e8 26 00    # CALL 0x30
                                        e9 13 00    # JMP 0x20
                                        """,
                                "0x10",
                                """
                                        e8 2d 00    # CALL 0x40
                                        eb 0b       # JMP 0x20
                                        """,
                                "0x20",
                                """
                                        89 d8       # MOV AX,BX
                                        c3          # RET
                                        """,
                                "0x30",
                                """
                                        88 c7       # MOV BH,AL
                                        b3 02       # MOV BL,0x02
                                        c3          # RET
                                        """,
                                "0x40",
                                """
                                        88 c7       # MOV BH,AL
                                        b3 22       # MOV BL,0x22
                                        bb ff 00    # MOV BX,0xff
                                        c3          # RET
                                        """),
                        Set.of("0x0", "0x30", "0x40"),
                        Map.of("0x30",
                                new Match(AddressSpace.TYPE_REGISTER, "AL"),
                                "0x32",
                                new Match(AddressSpace.TYPE_CONSTANT, 0x02L),
                                "0x40",
                                new Match(AddressSpace.TYPE_REGISTER, "AL"),
                                "0x42",
                                new Match(AddressSpace.TYPE_CONSTANT, 0x22L)),
                        "0x20"));

        return Stream.of(
                argsInReg,
                argsGenAfterKill,
                // argsGenCaller,
                // argsGenSibling,
                // argsIndirectMerge,
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

    @ParameterizedTest(name = "x86Test{0}")
    @MethodSource("x86Args")
    public void x86(final Map<String, String> prgBytes,
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
        System.out.printf("\n====\n%s\n====\n", testInfo.getDisplayName().replaceAll("\s\s*", " "));

        var script = newScript(prgBytes, funcAddrs, sinkAddr, langName);
        var ctx = script.flow();
        var ctxAddrs = Set.copyOf(ctx.deps().values());
        expectedSrcs.forEach((addrStr, match) -> {
            var addr = script.lang.getAddressFactory().getAddress(addrStr);
            assertTrue(ctxAddrs.contains(addr));

            var ctxVar = ctx.deps().entrySet().stream()
                    .filter(entry -> entry.getValue().equals(addr))
                    .map(Map.Entry::getKey)
                    .findFirst()
                    .orElseThrow();
            assertEquals(match.spaceType, ctxVar.getAddress().getAddressSpace().getType());
            if (match.spaceType == AddressSpace.TYPE_CONSTANT) {
                assertEquals(match.val, ctxVar.getOffset());
            } else if (match.spaceType == AddressSpace.TYPE_REGISTER) {
                assertEquals(
                        script.lang.getRegister(match.val.toString()),
                        script.lang.getRegister(ctxVar.getAddress(), ctxVar.getSize()));
            }
        });
    }

    private BackTaint newScript(final Map<String, String> prgBytes,
                                final Set<String> funcAddrs,
                                final String sinkAddr,
                                final String langName) throws Exception {
        var prg = newProgram(prgBytes, funcAddrs, langName);
        var script = new BackTaint();
        script.init(prg, prg.getAddressFactory().getAddress(sinkAddr));

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
                if (funcAddrs.contains(addr)) {
                    builder.createEmptyFunction(String.format("FUN_%s", addr), addr, bytes.length, DataType.DEFAULT);
                }
            } catch (final Exception e) {
                throw new RuntimeException(e);
            }
        });
        var prg = builder.getProgram();
        prg.startTransaction(this.getClass().getSimpleName());

        return prg;
    }

    private record Match(Integer spaceType, Object val) {
    }
}
