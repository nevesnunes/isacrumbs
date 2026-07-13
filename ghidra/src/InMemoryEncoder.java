import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import ghidra.pcodeCPort.opcodes.OpCode;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.AttributeId;
import ghidra.program.model.pcode.ElementId;
import ghidra.program.model.pcode.Encoder;

public class InMemoryEncoder implements Encoder {

    private final Map<String, List<Object>> cache = new HashMap<>();
    private final Deque<String> keyPrefix = new ArrayDeque<>();

    public String get(String key) {
        return this.cache.get(key).stream()
                .map(value -> value.toString().strip())
                .filter(value -> !value.isBlank())
                .collect(Collectors.joining());
    }

    private void put(AttributeId attribId, Object val) {
        final String key = Stream
                .concat(this.keyPrefix.stream(), Stream.of(attribId.name()))
                .collect(Collectors.joining("."));
        this.cache.computeIfAbsent(key, ignoredKey -> new ArrayList<>()).add(val);
    }

    @Override
    public void openElement(ElementId elemId) {
        this.keyPrefix.push(elemId.name());
    }

    @Override
    public void closeElement(ElementId elemId) {
        this.keyPrefix.pop();
    }

    @Override
    public void writeBool(AttributeId attribId, boolean val) {
        put(attribId, val);
    }

    @Override
    public void writeSignedInteger(AttributeId attribId, long val) {
        put(attribId, val);
    }

    @Override
    public void writeUnsignedInteger(AttributeId attribId, long val) {
        put(attribId, val);
    }

    @Override
    public void writeString(AttributeId attribId, String val) {
        put(attribId, val);
    }

    @Override
    public void writeStringIndexed(AttributeId attribId, int index, String val) {
        put(attribId, val);
    }

    @Override
    public void writeSpace(AttributeId attribId, AddressSpace spc) {
        put(attribId, spc.getName());
    }

    @Override
    public void writeSpace(AttributeId attribId, int index, String name) {
        put(attribId, name);
    }

    @Override
    public void writeOpcode(AttributeId attribId, OpCode opcode) {
        put(attribId, opcode.getName());
    }
}
