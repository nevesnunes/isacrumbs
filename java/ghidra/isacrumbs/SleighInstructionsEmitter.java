package ghidra.isacrumbs;

import com.google.gson.stream.JsonWriter;
import ghidra.pcodeCPort.slghpattern.InstructionPattern;
import ghidra.pcodeCPort.slghpattern.Pattern;

import java.io.*;
import java.util.List;

public class SleighInstructionsEmitter {
    public static void toJson(final List<SleighInstructionsVisitor.SubTableBitPatterns> instructions,
                              final String outFilename) {
        final OutputStream os;
        try {
            os = new FileOutputStream(outFilename);
        } catch (final FileNotFoundException e) {
            throw new RuntimeException(e);
        }

        try {
            final JsonWriter jsonWriter = new JsonWriter(new OutputStreamWriter(os));
            jsonWriter.beginArray();

            for (final SleighInstructionsVisitor.SubTableBitPatterns instruction : instructions) {
                jsonWriter.beginArray();

                jsonWriter.value(instruction.name());

                jsonWriter.beginArray();
                for (final List<SleighInstructionsVisitor.BitPattern> bitPatterns : instruction.patterns()) {
                    jsonWriter.beginArray();

                    for (final SleighInstructionsVisitor.BitPattern bitPattern : bitPatterns) {
                        jsonWriter.beginObject();

                        jsonWriter.name("len").value(bitPattern.length());
                        jsonWriter.name("kind").value(bitPattern.kind());
                        jsonWriter.name("le").value(bitPattern.le());
                        jsonWriter.name("re").value(bitPattern.re());
                        jsonWriter.name("mask").value(switch (bitPattern.values().getFirst()) {
                            case InstructionPattern instrPattern ->
                                    instrPattern.getBlock().getMask(0, bitPattern.length());
                            case Pattern ignoredPattern ->
                                    throw new IllegalStateException(String.format(
                                            "Unexpected pattern '%s'.",
                                            bitPattern.values().getFirst().getClass().getSimpleName()
                                    ));
                        });
                        jsonWriter.name("vals");
                        jsonWriter.beginArray();
                        for (final Pattern pattern : bitPattern.values()) {
                            jsonWriter.value(switch (pattern) {
                                case InstructionPattern instrPattern ->
                                        instrPattern.getBlock().getValue(0, bitPattern.length());
                                case Pattern ignoredPattern ->
                                        throw new IllegalStateException(String.format(
                                                "Unexpected pattern '%s'.",
                                                pattern.getClass().getSimpleName()
                                        ));
                            });
                        }
                        jsonWriter.endArray();

                        jsonWriter.endObject();
                    }

                    jsonWriter.endArray();
                }
                jsonWriter.endArray();

                jsonWriter.endArray();
            }

            jsonWriter.endArray();
            jsonWriter.close();
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }
}
