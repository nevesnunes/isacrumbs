import static org.junit.Assert.assertNotNull;

import java.io.File;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ghidra.GhidraTestApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;

public class DumpFunctionTest {

    @TempDir
    private static File userSettingsDir;

    private static Logger logger = LoggerFactory.getLogger(DumpFunctionTest.class);

    static {
        try {
            Application.initializeApplication(
                    new GhidraTestApplicationLayout(userSettingsDir),
                    new ApplicationConfiguration());
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void dumpsNameAndBody() {
        var prg = newProgram();
        var script = new DumpFunction();
        script.init(prg, prg.getAddressFactory().getAddress("0x0"));

        var name = script.name();
        assertNotNull(name);
        logger.info(name);

        var body = script.body();
        assertNotNull(body);
        logger.info(body);
    }

    private Program newProgram() {
        final ProgramBuilder builder;
        try {
            var addr = "0x0";
            var bytes = new byte[] { (byte) 0xC3 };
            builder = new ProgramBuilder("test", ProgramBuilder._X86_16_REAL_MODE);
            builder.setBytes(addr, bytes, true);
            builder.createEmptyFunction("FUN1", addr, bytes.length, DataType.DEFAULT);
        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
        var prg = builder.getProgram();

        return prg;
    }
}
