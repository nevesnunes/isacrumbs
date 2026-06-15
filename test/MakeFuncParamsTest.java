import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ghidra.GhidraTestApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;

public class MakeFuncParamsTest {

    @TempDir
    private static File userSettingsDir;

    private static final ParameterImpl[] EMPTY_PARAMS = new ParameterImpl[] {};
    private static final List<String> LIST_AX = List.of("AX");
    private static final List<String> LIST_AX_BX = List.of("AX", "BX");

    private static Stream<Arguments> x86Args() {
        var argsNone = Arrays.asList(
                Arguments.of(
                        Map.of(
                                "0x0",
                                "       c3          # RET",
                                "0x10",
                                "       cb          # RETF"),
                        Map.of(
                                "0x0",
                                Collections.EMPTY_LIST,
                                "0x10",
                                Collections.EMPTY_LIST)));

        var argsPushNone = Arrays.asList(
                Arguments.of(
                        Map.of(
                                "0x0",
                                """
                                        67 50       # PUSH AX
                                        c3          # RET
                                        """),
                        Map.of("0x0", Collections.EMPTY_LIST)));

        var argsClearedNone = Arrays.asList(
                Arguments.of(
                        Map.of(
                                "0x0",
                                """
                                        33 c0       # XOR AX,AX
                                        c3          # RET
                                        """),
                        Map.of("0x0", Collections.EMPTY_LIST)),
                Arguments.of(
                        Map.of(
                                "0x0",
                                """
                                        67 50       # POP AX
                                        c3          # RET
                                        """),
                        Map.of("0x0", Collections.EMPTY_LIST)),
                Arguments.of(
                        Map.of(
                                "0x0",
                                """
                                        bb 02 00    # MOV BX,0x2
                                        89 d8       # MOV AX,BX
                                        c3          # RET
                                        """),
                        Map.of("0x0", Collections.EMPTY_LIST)));

        var argsAX = Arrays.asList(
                Arguments.of(
                        Map.of(
                                "0x0",
                                """
                                        09 c0       # OR AX,AX
                                        c3          # RET
                                        """),
                        Map.of("0x0", LIST_AX)),
                Arguments.of(
                        Map.of(
                                "0x0",
                                """
                                        67 50       # PUSH AX
                                        09 c0       # OR AX,AX
                                        67 58       # POP AX
                                        c3          # RET
                                        """),
                        Map.of("0x0", LIST_AX)));

        var argsAXBX = Arrays.asList(
                Arguments.of(
                        Map.of(
                                "0x0",
                                """
                                        0b c3       # OR AX,BX
                                        c3          # RET
                                        """),
                        Map.of("0x0", LIST_AX_BX)),
                Arguments.of(
                        Map.of(
                                "0x0",
                                """
                                        89 c1       # MOV CX,AX
                                        89 d8       # MOV AX,BX
                                        89 c1       # MOV CX,AX
                                        c3          # RET
                                        """),
                        Map.of("0x0", LIST_AX_BX)));

        var argsMergedAX = Arrays.asList(
                Arguments.of(
                        Map.of(
                                "0x0",
                                """
                                        88 c3       # MOV BL,AL
                                        88 e3       # MOV BL,AH
                                        c3          # RET
                                        """),
                        Map.of("0x0", LIST_AX)));

        var argsIndirectAX = Arrays.asList(
                Arguments.of(
                        Map.of(
                                "0x0",
                                """
                                        50          # PUSH AX
                                        51          # PUSH CX
                                        59          # POP CX
                                        5b          # POP BX
                                        c3          # RET
                                        """),
                        Map.of("0x0", LIST_AX)));

        var argsIndirectCallAX = Arrays.asList(
                Arguments.of(
                        Map.of(
                                "0x0",
                                """
                                        53          # PUSH BX
                                        e8 0c 00    # CALL 0x10
                                        5b          # POP BX
                                        c3          # RET
                                        """,
                                "0x10",
                                """
                                        50          # PUSH AX
                                        c3          # RET
                                        """),
                        Map.of(
                                "0x0",
                                LIST_AX,
                                "0x10",
                                LIST_AX)));

        var argsNestedAX = Arrays.asList(
                // Callees are recursively analyzed by our script (including those in unreachable basic blocks).
                // This case ensures that writes done under callees are found, and their respective
                // reads on callers are not identified as false positive read-before-write.
                Arguments.of(
                        Map.of(
                                "0x0",
                                """
                                        b8 01 00    # MOV AX,0x1
                                        09 c0       # OR AX,AX
                                        74 09       # JZ 0x10
                                        e8 26 00    # CALL 0x30
                                        eb 14       # JMP 0x20
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
                                        e8 0d 00    # CALL 0x40
                                        e8 0a 00    # CALL 0x40
                                        e8 07 00    # CALL 0x40
                                        c3          # RET
                                        """,
                                "0x40",
                                """
                                        89 c3       # MOV BX,AX
                                        c3          # RET
                                        """),
                        Map.of(
                                "0x0",
                                Collections.EMPTY_LIST,
                                "0x30",
                                LIST_AX,
                                "0x40",
                                LIST_AX)));

        return Stream.of(
                argsNone,
                argsPushNone,
                argsClearedNone,
                argsAX,
                argsAXBX,
                argsMergedAX,
                argsIndirectAX,
                // FIXME: argsIndirectCallAX,
                argsNestedAX)
                .flatMap(Collection::stream);
    }

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

    @ParameterizedTest
    @MethodSource("x86Args")
    public void x86(final Map<String, String> prgBytes,
                    final Map<String, List<String>> expectedParams) throws Exception {
        of(prgBytes, expectedParams, "x86:LE:16:Protected Mode");
    }

    /**
     * @param prgBytes       Program bytes keyed-by address on which they are inserted.
     * @param expectedParams Parameters keyed-by function address.
     * @param langName       Program language.
     */
    public void of(final Map<String, String> prgBytes,
                   final Map<String, List<String>> expectedParams,
                   final String langName) throws Exception {
        var script = newScript(prgBytes, expectedParams.keySet(), langName);

        // First pass: script hasn't updated any parameters yet.
        for (var entry : expectedParams.entrySet()) {
            var func = func(script, entry.getKey());
            assertParameters(entry.getKey(), EMPTY_PARAMS, func.getParameters());
        }

        // Second pass: script might have already updated the current iterated function, since it might be
        // a callee of a previously iterated function. However, updates are expected to be idempotent.
        for (var entry : expectedParams.entrySet()) {
            var func = func(script, entry.getKey());
            script.resolveParams(func);
            var expectedParamsArray = new ParameterImpl[entry.getValue().size()];
            for (int i = 0; i < expectedParamsArray.length; i++) {
                expectedParamsArray[i] = script.toParam(script.prg.getRegister(entry.getValue().get(i)));
            }
            assertParameters(entry.getKey(), expectedParamsArray, func.getParameters());
        }
    }

    private void assertParameters(final String addr,
                                  final ParameterImpl[] expectedParams,
                                  final Parameter[] actualParams) throws Exception {
        assertNotNull(expectedParams);
        assertNotNull(actualParams);

        // FIXME: What if the function already had other parameters derived by auto-analysis?
        assertEquals(
                expectedParams.length,
                actualParams.length,
                String.format(
                        "Comparing @ '%s' params len '%s' vs. '%s'",
                        addr,
                        Arrays.toString(expectedParams),
                        Arrays.toString(actualParams)));

        for (int i = 0; i < expectedParams.length; i++) {
            // ParameterImpl has an unassigned ordinal, but iteration implicitly ensures ordering.
            // To ensure equivalence, we override unassigned value with actual value.
            var ordinalField = expectedParams[i].getClass().getDeclaredField("ordinal");
            ordinalField.setAccessible(true);
            ordinalField.setInt(expectedParams[i], actualParams[i].getOrdinal());

            assertTrue(
                    expectedParams[i].isEquivalent(actualParams[i]),
                    String.format(
                            "Comparing param '%s' vs. '%s'",
                            expectedParams[i],
                            actualParams[i]));
        }
    }

    private Function func(final MakeFuncParams script, final String lstAddr) {
        var addr = script.prg.getAddressFactory().getAddress(lstAddr);
        var func = script.lst.getFunctionContaining(addr);
        if (func == null) {
            throw new RuntimeException("No function defined for selected address.");
        }

        return func;
    }

    private MakeFuncParams newScript(final Map<String, String> prgBytes,
                                     final Set<String> funcAddrs,
                                     final String langName) throws Exception {
        var prg = newProgram(prgBytes, funcAddrs, langName);
        var script = new MakeFuncParams();
        script.init(prg);

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
}
