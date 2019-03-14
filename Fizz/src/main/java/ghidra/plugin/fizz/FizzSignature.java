package ghidra.plugin.fizz;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.InstructionBlock;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramSelection;
import ghidra.utilities.memory.MemorySignature;

/**
 * @author quosego <https://github.com/quosego>
 * @version Mar 14, 2019
 */
class FizzSignature {
    private MemorySignature signature;

    FizzSignature(Program program, ProgramSelection selection, String delimiter) {
        this.signature = new MemorySignature(program, selection.getFirstRange(), delimiter);
    }

    public String getSelectedSignature() {
        return signature.getSignature();
    }


    public String getSelectedBlockSignature() {
        InstructionBlock block = new InstructionBlock(signature.getMinAddress());
        // MemoryBlock != InstructionBlock
        //MemoryBlock block = signature.getMemory().getBlock(signature.getMinAddress());
        MemorySignature sig = new MemorySignature(signature.getProgram(), block.getStart(), block.getEnd(), signature.getDelimiter());
        return sig.getSignature();
    }

    public String getSelectedFunctionSignature() {
        Function function = signature.getProgram().getFunctionManager().getFunctionContaining(signature.getMinAddress());
        // function function.getBody().getMaxAddress() != EndPoint
        MemorySignature sig = new MemorySignature(signature.getProgram(), function.getEntryPoint(), function.getBody().getMaxAddress(), signature.getDelimiter());
        return sig.getSignature();
    }
}
