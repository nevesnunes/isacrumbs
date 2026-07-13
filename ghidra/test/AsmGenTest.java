import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;

import org.antlr.runtime.ANTLRStringStream;
import org.antlr.runtime.CharStream;
import org.antlr.runtime.UnbufferedTokenStream;
import org.antlr.runtime.tree.CommonTreeNodeStream;
import org.junit.jupiter.api.Test;

import ghidra.pcodeCPort.slgh_compile.SleighCompile;
import ghidra.pcodeCPort.slgh_compile.SleighCompilePreprocessorDefinitionsAdapater;
import ghidra.sleigh.grammar.LineArrayListWriter;
import ghidra.sleigh.grammar.ParsingEnvironment;
import ghidra.sleigh.grammar.SleighCompiler;
import ghidra.sleigh.grammar.SleighLexer;
import ghidra.sleigh.grammar.SleighParser;
import ghidra.sleigh.grammar.SleighPreprocessor;

public class AsmGenTest {
    @Test
    public void test() throws Exception {
        final String inputPath = System.getProperty("slaspec.path");
        final File inputFile = new File(inputPath);
        if (!inputFile.exists()) {
            throw new RuntimeException(String.format("File '%s' not found.", inputFile.getAbsolutePath()));
        }

        final SleighCompile sc = new SleighCompile();
        final LineArrayListWriter writer = new LineArrayListWriter();
        final ParsingEnvironment env = new ParsingEnvironment(writer);
        final SleighCompilePreprocessorDefinitionsAdapater definitionsAdapter = new SleighCompilePreprocessorDefinitionsAdapater(
                sc);
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

        final AsmGenVisitor visitor = new AsmGenVisitor(sc);
        final List<AsmGenVisitor.SubTableBitPatterns> patterns = visitor.visitRoot();
        assertTrue(!patterns.isEmpty());

        final String outputPath = System.getProperty("bitpatterns.path", "/tmp/out.json");
        AsmGenEmitter.toJson(patterns, outputPath);
    }
}
