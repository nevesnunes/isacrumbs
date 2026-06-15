//Dump function body
//@author flib
//@category
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

public class DumpFunction extends GhidraScript {

    Program scriptProgram;
    Address scriptAddress;
    Listing lst;

    public void init(final Program prg, final Address addr) {
        if (prg == null) {
            throw new RuntimeException("No program loaded.");
        }
        if (addr == null) {
            throw new RuntimeException("No address selected.");
        }
        scriptProgram = prg;
        scriptAddress = addr;
        lst = scriptProgram.getListing();
    }

    public String body() {
        var func = lst.getFunctionContaining(scriptAddress);
        var it = lst.getInstructions(func.getBody(), true);
        var out = new StringBuilder();
        while (it.hasNext()) {
            var instr = it.next();
            out.append(String.format("%08x: %s %s\n",
                    instr.getAddress().getUnsignedOffset(),
                    instr.getMnemonicString()));
        }
        return out.toString();
    }

    public String name() {
        return lst.getFunctionContaining(scriptAddress).getName();
    }

    @Override
    public void run() throws Exception {
        init(currentProgram, currentAddress);
        println(name());
        println(body());
    }
}
