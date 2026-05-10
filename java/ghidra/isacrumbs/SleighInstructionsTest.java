package ghidra.isacrumbs;

import com.google.common.io.Files;
import ghidra.pcodeCPort.slgh_compile.SleighCompile;
import ghidra.pcodeCPort.slgh_compile.SleighCompilePreprocessorDefinitionsAdapater;
import ghidra.sleigh.grammar.*;
import org.antlr.runtime.ANTLRStringStream;
import org.antlr.runtime.CharStream;
import org.antlr.runtime.UnbufferedTokenStream;
import org.antlr.runtime.tree.CommonTreeNodeStream;
import org.junit.Test;

import java.io.File;
import java.util.List;

public class SleighInstructionsTest {
    @Test
    public void test() throws Exception {
        // From "$GHIDRA_INSTALL_DIR/Ghidra/Processors/6502/data/languages/6502.slaspec"
        final String inputPath = "/tmp/6502.slaspec";
        final File inputFile = new File(inputPath);
        if (!inputFile.exists()) {
            throw new RuntimeException(String.format("File '%s' not found.", inputFile.getAbsolutePath()));
        }

        final SleighCompile sc = new SleighCompile();
        final LineArrayListWriter writer = new LineArrayListWriter();
        final ParsingEnvironment env = new ParsingEnvironment(writer);
        final SleighCompilePreprocessorDefinitionsAdapater definitionsAdapter = new SleighCompilePreprocessorDefinitionsAdapater(sc);
        final SleighPreprocessor sp = new SleighPreprocessor(definitionsAdapter, inputFile);
        sp.process(writer);

        final CharStream input = new ANTLRStringStream(writer.toString());
        final SleighLexer lex = new SleighLexer(input);
        lex.setEnv(env);

        final UnbufferedTokenStream tokens = new UnbufferedTokenStream(lex);
        final SleighParser parser = new SleighParser(tokens);
        parser.setEnv(env);
        parser.setLexer(lex);
        final SleighParser.spec_return parserRoot = parser.spec();

        final CommonTreeNodeStream nodes = new CommonTreeNodeStream(parserRoot.getTree());
        nodes.setTokenStream(tokens);

        // Populate symtab.
        final SleighCompiler walker = new SleighCompiler(nodes);
        int result = walker.root(env, sc);
        if (result != 0) {
            throw new RuntimeException(String.format("Compiler error '%d'.", result));
        }

        final SleighInstructionsVisitor visitor = new SleighInstructionsVisitor(sc);
        final List<SleighInstructionsVisitor.SubTableBitPatterns> patterns = visitor.visitRoot();
        SleighInstructionsEmitter.toJson(patterns, "/tmp/out.json");

        System.out.println("DONE");
    }
}
